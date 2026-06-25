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

function cleanId(value, fallback) {
  return String(value || fallback)
    .replace(/[^A-Za-z0-9_.:-]+/g, "-")
    .slice(0, 120);
}

function guardUrl(options) {
  return String(
    options.guardUrl ||
      process.env.OPENCODE_TOOL_PROXY_URL ||
      process.env.GUARD_TOOL_PROXY_URL ||
      DEFAULT_GUARD_URL,
  ).replace(/\/+$/, "");
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Guard tool proxy rejected HTTP ${response.status}`);
  }
  return payload;
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Guard approval lookup failed HTTP ${response.status}`);
  }
  return payload;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
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
      if (resolution.action !== "allow") {
        const reasons = (resolution.reasons || []).join(", ") || "policy_rejected";
        throw new Error(
          `CodeAgent Guard did not authorize the resumed call: ` +
            `${resolution.action || "deny"} (${reasons})`,
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
  const baseUrl = guardUrl(options);
  const allowedTools = Array.isArray(options.allowedTools)
    ? options.allowedTools
    : DEFAULT_ALLOWED_TOOLS;

  return {
    async "tool.execute.before"(input, output) {
      const sessionID = cleanId(input.sessionID, "session");
      const callID = cleanId(input.callID, "call");
      const result = await postJson(`${baseUrl}/api/opencode/authorize-tool`, {
        tool: input.tool,
        args: output.args || {},
        trace_id: `opencode-${sessionID}`,
        session_id: sessionID,
        call_id: callID,
        task:
          options.task ||
          process.env.OPENCODE_GUARD_TASK ||
          `OpenCode session ${sessionID}`,
        source: "agent",
        agent_id: "opencode",
        allowed_tools: allowedTools,
        metadata: {
          project: ctx.project,
          directory: ctx.directory,
          worktree: ctx.worktree,
          server_url: String(ctx.serverUrl),
        },
      });

      if (result.action === "ask" && result.approval_id) {
        await waitForApproval(baseUrl, result.approval_id, options);
        return;
      }

      if (result.action !== "allow") {
        const approval = result.approval_id
          ? ` approval_id=${result.approval_id}`
          : "";
        const reasons = (result.reasons || []).join(", ") || "policy_rejected";
        throw new Error(
          `CodeAgent Guard blocked ${input.tool}: ${result.action} ` +
            `(${reasons}).${approval}`,
        );
      }
    },
  };
};

export default CodeAgentGuardToolProxy;
