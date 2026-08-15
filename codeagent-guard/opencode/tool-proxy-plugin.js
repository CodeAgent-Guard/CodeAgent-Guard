import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

const DEFAULT_GUARD_URL = "http://127.0.0.1:8000";

const DEFAULT_ALLOWED_TOOLS = [
  "read_file",
  "write_file",
  "run_command",
  "http_request",
  "list_directory",
  "search_files",
  "make_directory",
  "delete_path",
  "move_path",
];

const sessionPrompts = new Map();
const sessionTraceIds = new Map();
const sessionMessageIds = new Map();
const toolCallArgs = new Map();

function cleanId(value, fallback) {
  return String(value || fallback)
    .replace(/[^A-Za-z0-9_.:-]+/g, "-")
    .slice(0, 120);
}

function compactText(value, limit = 2000) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

function stablePromptId(value) {
  let hash = 2166136261;
  for (const character of String(value || "")) {
    hash ^= character.codePointAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `prompt-${(hash >>> 0).toString(36)}`;
}

function textFromParts(parts) {
  return (Array.isArray(parts) ? parts : [])
    .filter((part) => part && part.type === "text" && part.text)
    .map((part) => part.text)
    .join("\n")
    .trim();
}

function promptTextFromValue(value) {
  if (!value) return "";
  if (typeof value === "string") return compactText(value);
  const direct = [
    value.text,
    value.content,
    value.prompt,
    value.input,
    value.message?.text,
    value.message?.content,
    value.message?.prompt,
  ].find((item) => typeof item === "string" && item.trim());
  if (direct) return compactText(direct);

  const parts = Array.isArray(value.parts)
    ? value.parts
    : Array.isArray(value.message?.parts)
      ? value.message.parts
      : [];
  const partText = textFromParts(parts);
  if (partText) return compactText(partText);

  const summary = value.message?.summary || value.summary || {};
  return compactText([summary.title, summary.body].filter(Boolean).join(" "));
}

function promptTextFromMessage(...values) {
  for (const value of values) {
    const prompt = promptTextFromValue(value);
    if (prompt) return prompt;
  }
  return "";
}

function taskForSession(options, sessionID) {
  return (
    options.task ||
    process.env.OPENCODE_GUARD_TASK ||
    sessionPrompts.get(sessionID) ||
    `OpenCode session ${sessionID}`
  );
}

function traceIdForSession(sessionID) {
  return `opencode-${sessionTraceIds.get(sessionID) || sessionID}`;
}

function compactResult(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return compactText(value, 12000);
  if (typeof value !== "object") return value;
  if (depth >= 4) {
    try {
      return compactText(JSON.stringify(value), 4000);
    } catch {
      return compactText(String(value), 4000);
    }
  }
  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => compactResult(item, depth + 1));
  }
  const result = {};
  for (const [key, item] of Object.entries(value).slice(0, 60)) {
    if (["blob", "buffer", "bytes", "raw"].includes(String(key).toLowerCase())) {
      continue;
    }
    result[key] = compactResult(item, depth + 1);
  }
  return result;
}

function canonicalResult(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(canonicalResult);
  if (typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalResult(value[key])]),
  );
}

function fullResultFingerprint(value) {
  try {
    return createHash("sha256")
      .update(JSON.stringify(canonicalResult(value)))
      .digest("hex");
  } catch {
    return createHash("sha256").update(String(value)).digest("hex");
  }
}

function resultPayload(output) {
  const full = !output || typeof output !== "object" ? output : {
    title: output.title,
    output: output.output,
    metadata: output.metadata,
    result: output.result,
    content: output.content,
    text: output.text,
  };
  const compact = compactResult(full);
  return {
    ...(compact && typeof compact === "object" ? compact : {output: compact}),
    _guard_result_fingerprint: fullResultFingerprint(full),
  };
}

function promptTextFromMessageLegacy(output) {
  const parts = Array.isArray(output?.parts) ? output.parts : [];
  const partText = parts
    .filter((part) => part && part.type === "text" && part.text)
    .map((part) => part.text)
    .join("\n")
    .trim();
  if (partText) return compactText(partText);
  const summary = output?.message?.summary || {};
  return compactText([summary.title, summary.body].filter(Boolean).join(" "));
}

function normalizeUrl(value) {
  return String(value || "").replace(/\/+$/, "");
}

function routeGatewayAddress(hex) {
  const clean = String(hex || "").trim();
  if (!/^[0-9A-Fa-f]{8}$/.test(clean)) return "";
  const parts = clean.match(/../g).map((part) => parseInt(part, 16));
  return parts.reverse().join(".");
}

function wslHostGuardUrl() {
  try {
    const route = readFileSync("/proc/net/route", "utf-8");
    for (const line of route.split(/\r?\n/).slice(1)) {
      const columns = line.trim().split(/\s+/);
      if (columns[1] === "00000000" && columns[2]) {
        const gateway = routeGatewayAddress(columns[2]);
        if (gateway && gateway !== "0.0.0.0") {
          return `http://${gateway}:8000`;
        }
      }
    }
  } catch {
    // Non-WSL hosts do not expose /proc/net/route.
  }
  try {
    const resolv = readFileSync("/etc/resolv.conf", "utf-8");
    const match = resolv.match(/^nameserver\s+([0-9.]+)/m);
    return match ? `http://${match[1]}:8000` : "";
  } catch {
    return "";
  }
}

function guardUrls(options) {
  const configured =
    options.guardUrl ||
    process.env.OPENCODE_TOOL_PROXY_URL ||
    process.env.GUARD_TOOL_PROXY_URL;
  if (configured) return [normalizeUrl(configured)];
  return [...new Set([
    DEFAULT_GUARD_URL,
    "http://localhost:8000",
    wslHostGuardUrl(),
  ].filter(Boolean).map(normalizeUrl))];
}

async function postJson(url, body) {
  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    const requestError = new Error(
      `CodeAgent Guard is unreachable at ${url}: ${error.message}`,
    );
    requestError.retryable = true;
    throw requestError;
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const requestError = new Error(
      payload.error || `Guard tool proxy rejected HTTP ${response.status}`,
    );
    requestError.retryable = false;
    requestError.status = response.status;
    throw requestError;
  }
  return payload;
}

async function postJsonAny(baseUrls, path, body) {
  let lastError;
  for (const baseUrl of baseUrls) {
    try {
      return {
        baseUrl,
        payload: await postJson(`${baseUrl}${path}`, body),
      };
    } catch (error) {
      if (error.retryable === false) throw error;
      lastError = error;
    }
  }
  throw lastError || new Error("CodeAgent Guard is unreachable");
}

async function getJson(url) {
  let response;
  try {
    response = await fetch(url, {
      headers: { Accept: "application/json" },
    });
  } catch (error) {
    throw new Error(
      `CodeAgent Guard approval endpoint is unreachable at ${url}: ${error.message}`,
    );
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Guard approval lookup failed HTTP ${response.status}`);
  }
  return payload;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function postToolResultWithRetry(baseUrls, body, attempts = 4) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await postJsonAny(baseUrls, "/api/opencode/tool-result", body);
    } catch (error) {
      lastError = error;
      if (error.retryable === false || attempt === attempts) throw error;
      await sleep(250 * (2 ** (attempt - 1)));
    }
  }
  throw lastError;
}

async function waitForApproval(baseUrl, approvalId, options) {
  const pollMs = Math.max(250, Number(options.approvalPollMs || 1000));
  const timeoutMs = Math.max(1000, Number(options.approvalTimeoutMs || 600000));
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const approval = await getJson(
      `${baseUrl}/api/approvals/${encodeURIComponent(approvalId)}`,
    );
    if (approval.status === "approved") {
      const resolution = approval.resolution || {};
      const approvalStatus = resolution.approval_status || approval.status;
      if (approvalStatus !== "approved" || resolution.execution_authorized !== true) {
        const reasons = (resolution.reasons || []).join(", ") || "policy_rejected";
        throw new Error(
          `CodeAgent Guard did not authorize the resumed call: ` +
            `approval_status=${approvalStatus || "unknown"}, ` +
            `execution_authorized=${String(resolution.execution_authorized)} ` +
            `(${reasons})`,
        );
      }
      return resolution;
    }
    if (approval.status === "rejected" || approval.status === "expired") {
      throw new Error(
        `CodeAgent Guard approval ${approval.status}: approval_id=${approvalId}`,
      );
    }
    await sleep(pollMs);
  }
  throw new Error(
    `CodeAgent Guard approval timed out: approval_id=${approvalId}`,
  );
}

export const CodeAgentGuardToolProxy = async (ctx, options = {}) => {
  const baseUrls = guardUrls(options);
  const allowedTools = Array.isArray(options.allowedTools)
    ? options.allowedTools
    : DEFAULT_ALLOWED_TOOLS;

  return {
    async "chat.message"(input, output) {
      const prompt = promptTextFromMessage(input, output) || promptTextFromMessageLegacy(output);
      const sessionID = cleanId(input?.sessionID || output?.sessionID, "session");
      if (prompt) {
        const messageID = cleanId(
          input?.messageID || output?.message?.id || stablePromptId(prompt),
          "message",
        );
        if (sessionMessageIds.get(sessionID) === messageID) return;
        sessionMessageIds.set(sessionID, messageID);
        sessionPrompts.set(sessionID, prompt);
        const suffix = `${sessionID}-task-${messageID}`;
        sessionTraceIds.set(sessionID, cleanId(suffix, sessionID));
      }
    },

    async "tool.execute.before"(input, output) {
      const sessionID = cleanId(input.sessionID, "session");
      const callID = cleanId(input.callID, "call");
      const toolArgs = output.args || input?.args || {};
      const task = taskForSession(options, sessionID);
      toolCallArgs.set(`${sessionID}:${callID}`, toolArgs);
      const { baseUrl, payload: result } = await postJsonAny(
        baseUrls,
        "/api/opencode/authorize-tool",
        {
          tool: input.tool,
          args: toolArgs,
          trace_id: traceIdForSession(sessionID),
          session_id: sessionID,
          call_id: callID,
          task,
          source: "agent",
          agent_id: "opencode",
          allowed_tools: allowedTools,
          metadata: {
            project: ctx.project,
            directory: ctx.directory,
            worktree: ctx.worktree,
            home: homedir(),
            server_url: String(ctx.serverUrl),
          },
        },
      );

      const fusionAction = result.fusion_action || result.action;
      if (fusionAction === "ask" && result.approval_id) {
        await waitForApproval(baseUrl, result.approval_id, options);
        return;
      }

      if (fusionAction !== "allow" || result.execution_authorized !== true) {
        const approval = result.approval_id
          ? ` approval_id=${result.approval_id}`
          : "";
        const reasons = (result.reasons || []).join(", ") || "policy_rejected";
        throw new Error(
          `CodeAgent Guard blocked ${input.tool}: ${fusionAction || "unknown"} ` +
          `(${reasons}).${approval}`,
        );
      }
    },

    async "tool.execute.after"(input, output) {
      const sessionID = cleanId(input?.sessionID || output?.sessionID, "session");
      const callID = cleanId(input?.callID || output?.callID, "call");
      const callKey = `${sessionID}:${callID}`;
      const toolArgs = output?.args || input?.args || toolCallArgs.get(callKey) || {};
      const task = taskForSession(options, sessionID);
      try {
        await postToolResultWithRetry(
          baseUrls,
          {
            tool: input.tool,
            args: toolArgs,
            result: resultPayload(output),
            trace_id: traceIdForSession(sessionID),
            session_id: sessionID,
            call_id: callID,
          task,
          source: "agent",
          agent_id: "opencode",
            metadata: {
              project: ctx.project,
              directory: ctx.directory,
              worktree: ctx.worktree,
              home: homedir(),
              server_url: String(ctx.serverUrl),
            },
          },
        );
      } catch (error) {
        console.warn(`[CodeAgent Guard] failed to record tool result: ${error.message}`);
      } finally {
        toolCallArgs.delete(callKey);
      }
    },
  };
};

export default CodeAgentGuardToolProxy;
