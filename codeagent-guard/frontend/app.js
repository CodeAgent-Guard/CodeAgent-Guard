const state = {
  health: null,
  overview: null,
  policies: [],
  tools: [],
  providers: [],
  traces: [],
  auditEvents: [],
  approvals: [],
  trustedWorkspaces: [],
  chainVerification: null,
  primaryTraceId: null,
  traceSelectionLocked: false,
  selectedTrace: null,
  latestTrace: null,
  selectedCallId: null,
  selectedAuditSeq: null,
  resourceErrors: {},
  loading: false,
  settingsInitialized: false,
  contextId: localStorage.getItem("agentContextId") || null,
};

const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[char]));
const first = (...values) => values.find(value => value !== undefined && value !== null && value !== "");
const truncate = (value, length = 72) => {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
};
const formatDate = iso => {
  if (!iso) return "—";
  const value = new Date(iso);
  if (Number.isNaN(value.getTime())) return String(iso);
  const pad = number => String(number).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`;
};
const shortIdentifier = (value, head = 4, tail = 4) => {
  const text = String(value || "");
  if (!text) return "—";
  if (text === "GENESIS") return text;
  return text.length > head + tail + 1 ? `${text.slice(0, head)}…${text.slice(-tail)}` : text;
};
const shortHash = value => shortIdentifier(value, 8, 6);
const shortTrace = value => shortIdentifier(value, 4, 4);
const decisionClass = value => ["allow", "ask", "deny"].includes(String(value || "").toLowerCase())
  ? String(value).toLowerCase() : "pending";
const decisionLabel = value => ({allow: "ALLOW", ask: "ASK", deny: "DENY"}[decisionClass(value)] || "待定");
const riskLabel = value => ({low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "HIGH"}[String(value || "").toLowerCase()] || "未知风险");
const auditEventLabel = event => event?.event_type === "external_execution_result"
  ? (event.execution_status === "error" ? "执行失败" : "已执行")
  : decisionLabel(event?.decision);
const maskSensitive = value => String(value ?? "")
  .replace(/sk-[A-Za-z0-9_-]{8,}/g, match => `${match.slice(0, 5)}****${match.slice(-4)}`)
  .replace(/(api[_-]?key|token|password|secret)(\s*[:=]\s*)[^\s,;"']+/gi, "$1$2[REDACTED]")
  .replace(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi, "[PRIVATE KEY REDACTED]");
const safeJson = value => maskSensitive(JSON.stringify(value ?? {}, null, 2));
const setText = (selector, value) => {
  const node = $(selector);
  if (node) node.textContent = value;
};

function canonicalPath(value) {
  let path = String(value || "").trim().replace(/^file:\/\//i, "").replaceAll("\\", "/").replace(/\/{2,}/g, "/");
  const wslDrive = path.match(/^\/mnt\/([a-z])\/(.*)$/i);
  if (wslDrive) path = `${wslDrive[1].toLowerCase()}:/${wslDrive[2]}`;
  if (/^[A-Z]:\//.test(path)) path = `${path[0].toLowerCase()}${path.slice(1)}`;
  return path.length > 1 ? path.replace(/\/$/, "") : path;
}

function pathBaseName(value) {
  const parts = canonicalPath(value).split("/").filter(Boolean);
  return parts.at(-1) || "当前工作区";
}

function workspaceRoots() {
  return [state.health?.workspace, ...state.trustedWorkspaces.map(root => root?.path || root)]
    .map(canonicalPath).filter(Boolean).sort((a, b) => b.length - a.length);
}

function workspaceName() {
  const root = first(state.health?.workspace, state.trustedWorkspaces[0]?.path, state.trustedWorkspaces[0]);
  if (!root) return "当前工作区";
  const canonical = canonicalPath(root);
  const name = pathBaseName(canonical);
  if (name.toLowerCase() !== "workspace") return name;
  const parent = canonical.split("/").filter(Boolean).at(-2);
  return parent ? `${parent} · workspace` : name;
}

function looksLikeFile(path) {
  const name = pathBaseName(path);
  return /^\.[^/]+$/.test(name) || /\.[A-Za-z0-9_-]{1,12}$/.test(name);
}

function resolvePathSegments(value) {
  const path = canonicalPath(value);
  const prefix = path.match(/^[a-z]:\//i)?.[0] || (path.startsWith("/") ? "/" : "");
  const body = prefix ? path.slice(prefix.length) : path;
  const stack = [];
  body.split("/").forEach(segment => {
    if (!segment || segment === ".") return;
    if (segment === "..") {
      if (stack.length && stack.at(-1) !== "..") stack.pop();
      else if (!prefix) stack.push(segment);
      return;
    }
    stack.push(segment);
  });
  return `${prefix}${stack.join("/")}` || (prefix || ".");
}

function relativePathEscapes(value) {
  let depth = 0;
  for (const segment of canonicalPath(value).split("/")) {
    if (!segment || segment === ".") continue;
    if (segment === "..") {
      depth -= 1;
      if (depth < 0) return true;
    } else depth += 1;
  }
  return false;
}

function pathPresentation(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === ".") return {label: "当前工作区", scope: "工作区内", relative: ".", raw};
  const path = canonicalPath(raw.replace(/^['"]|['"]$/g, ""));
  const lower = path.toLowerCase();
  const roots = workspaceRoots();
  const resolvedPath = resolvePathSegments(path);
  const resolvedLower = resolvedPath.toLowerCase();
  const isolatedSensitive = lower.match(/(?:^|\/)(\.demo_fake_home\/\.ssh\/(?:id_rsa|id_ed25519))(?:$|\/)/);
  if (isolatedSensitive) {
    const insideWorkspace = roots.some(item => resolvedLower === resolvePathSegments(item).toLowerCase() || resolvedLower.startsWith(`${resolvePathSegments(item).toLowerCase()}/`));
    const absolute = /^(?:[a-z]:\/|\/)/i.test(path);
    const outsideWorkspace = relativePathEscapes(path) || (absolute && !insideWorkspace);
    const evidencePath = /^\.\.\//.test(path) ? path : isolatedSensitive[1];
    return {
      label: `隔离演示敏感文件｜${evidencePath}${outsideWorkspace ? "（工作区外）" : ""}`,
      scope: outsideWorkspace ? "工作区外 · 隔离测试资源" : "隔离测试资源",
      relative: evidencePath,
      raw,
    };
  }
  const sshMatch = lower.match(/(?:^~|(?:^|\/)(?:(?:users|home)\/[^/]+|root))\/(\.ssh\/(?:id_rsa|id_ed25519))(?:$|\/)/)
    || lower.match(/^(\.ssh\/(?:id_rsa|id_ed25519))(?:$|\/)/);
  if (sshMatch) {
    const suffix = `~/${sshMatch[1]}`;
    return {label: `用户 SSH 私钥｜${suffix}`, scope: "用户敏感目录", relative: suffix, raw};
  }
  const userSensitive = lower.match(/(?:^~|(?:^|\/)(?:(?:users|home)\/[^/]+|root))\/(\.ssh(?:\/.*)?|\.gnupg(?:\/.*)?|\.aws(?:\/.*)?|\.config(?:\/.*)?)/);
  if (userSensitive) {
    const suffix = `~/${userSensitive[1]}`;
    return {label: `用户敏感目录｜${suffix}`, scope: "用户主目录", relative: suffix, raw};
  }
  const desktop = lower.match(/(?:^~\/|(?:^|\/)(?:users|home)\/[^/]+\/)(desktop|desktop\/.*)$/);
  if (desktop) {
    const suffix = desktop[1].replace(/^desktop/i, "~/Desktop");
    return {label: `用户桌面｜${suffix}`, scope: "工作区外", relative: suffix, raw};
  }
  const sensitiveConfig = path.match(/(?:^|\/)(\.env(?:\.[^/]*)?|\.opencode(?:\/.*)?)(?:$|\/)?/i);
  if (sensitiveConfig) {
    const insideWorkspace = roots.some(item => resolvedLower === resolvePathSegments(item).toLowerCase() || resolvedLower.startsWith(`${resolvePathSegments(item).toLowerCase()}/`));
    const outsideWorkspace = relativePathEscapes(path) || (/^(?:[a-z]:\/|\/)/i.test(path) && !insideWorkspace);
    const evidencePath = /(?:^|\/)\.\.(?:\/|$)/.test(path) ? path : sensitiveConfig[1];
    return {label: `敏感配置｜${evidencePath}${outsideWorkspace ? "（工作区外）" : ""}`, scope: outsideWorkspace ? "工作区外 · 敏感配置" : "工作区内 · 敏感配置", relative: evidencePath, raw};
  }
  const root = roots.find(item => resolvedLower === resolvePathSegments(item).toLowerCase() || resolvedLower.startsWith(`${resolvePathSegments(item).toLowerCase()}/`));
  const beganInsideRoot = roots.some(item => lower === item.toLowerCase() || lower.startsWith(`${item.toLowerCase()}/`));
  if (beganInsideRoot && !root && /(?:^|\/)\.\.(?:\/|$)/.test(path)) {
    const suffix = path.slice(roots.find(item => lower.startsWith(item.toLowerCase()))?.length || 0).replace(/^\//, "") || path;
    return {label: `工作区逃逸｜${suffix}`, scope: "边界逃逸", relative: suffix, raw};
  }
  if (root) {
    const relative = resolvedPath.slice(resolvePathSegments(root).length).replace(/^\//, "") || ".";
    if (relative === ".") return {label: "当前工作区", scope: "工作区内", relative, raw};
    const evidenceRelative = /(?:^|\/)\.\.(?:\/|$)/.test(path) ? `${relative} （原参数含 ..）` : relative;
    return {label: `${looksLikeFile(relative) ? "工作区文件" : "工作区目录"}｜${evidenceRelative}`, scope: "工作区内", relative: evidenceRelative, raw};
  }
  const isAbsolute = /^(?:[a-z]:\/|\/)/i.test(path) || path.startsWith("~");
  const relativePath = path.replace(/^\.\//, "");
  if (!isAbsolute && relativePathEscapes(relativePath)) {
    return {label: `工作区逃逸｜${path}`, scope: "边界逃逸", relative: path, raw};
  }
  if (!isAbsolute && !/^\.\.(?:\/|$)/.test(relativePath)) {
    return {label: `${looksLikeFile(relativePath) ? "工作区文件" : "工作区目录"}｜${relativePath}`, scope: "工作区内", relative: relativePath, raw};
  }
  if (/^\.\.(?:\/|$)/.test(path)) {
    return {label: `工作区外｜${path}`, scope: "边界逃逸", relative: path, raw};
  }
  if (/^\/(?:proc|sys)(?:\/|$)/i.test(path)) {
    const parts = path.split("/").filter(Boolean);
    const suffix = `/${parts.slice(0, 4).join("/")}`;
    return {label: `系统运行信息｜${suffix}`, scope: "工作区外 · 系统状态", relative: suffix, raw};
  }
  if (/^(?:\/etc(?:\/|$)|[a-z]:\/windows(?:\/|$))/i.test(path)) {
    return {label: `系统配置目录｜${path.replace(/^[a-z]:/i, "")}`, scope: "工作区外", relative: path, raw};
  }
  return {label: `工作区外｜${pathBaseName(path)}`, scope: "工作区外", relative: pathBaseName(path), raw};
}

function identifierRef(kind, value, {copy = true} = {}) {
  const full = String(value || "");
  const short = kind === "Hash" ? shortHash(full) : shortTrace(full);
  if (!full) return `<span class="technical-ref"><code>${esc(kind)} —</code></span>`;
  return `<span class="technical-ref"><code>${esc(kind)} ${esc(short)}</code>${copy ? `<button class="copy-button" type="button" data-copy-value="${esc(full)}" aria-label="复制完整${esc(kind)}">复制</button>` : ""}</span>`;
}

function rawDetails(label, value, {copyValue = "", className = ""} = {}) {
  return `<details class="raw-details ${esc(className)}"><summary><span>${esc(label)}</span><em>展开</em></summary><div class="raw-details-body">${copyValue ? `<button class="copy-button raw-copy" type="button" data-copy-value="${esc(copyValue)}">复制完整值</button>` : ""}<pre>${esc(safeJson(value))}</pre></div></details>`;
}

function runtimeIdentity(agentId) {
  const value = String(agentId || "").toLowerCase();
  if (value === "builtin-agent" || value.startsWith("builtin-")) return {kind: "builtin", entry: "自研 Agent", adapter: ""};
  if (value.includes("opencode")) return {kind: "opencode", entry: "OpenCode", adapter: "OpenCode Adapter"};
  if (["defense-demo-agent", "demo-agent"].includes(value) || value.includes("demo")) return {kind: "test", entry: "网关测试调用", adapter: ""};
  return {kind: agentId ? "external" : "unknown", entry: agentId ? "外部 Agent" : "未记录", adapter: ""};
}

function runtimeIdentityLabel(agentId, {includeAdapter = true} = {}) {
  const identity = runtimeIdentity(agentId);
  return `运行入口｜${identity.entry}${includeAdapter && identity.adapter ? ` · 适配器｜${identity.adapter}` : ""}`;
}

const REASON_LABELS = {
  policy_passed: "基础策略通过",
  ct_trm_assessment: "已完成 CT-TRM 风险评估",
  command_sensitive_resource_access: "Shell 命令访问敏感资源",
  sensitive_file_access: "访问敏感文件",
  credential_exposure_risk: "存在凭据暴露风险",
  resource_scope_violation: "目标超出工作区边界",
  untrusted_context_requires_confirmation: "不可信上下文需要确认",
  tainted_argument_flow: "低可信内容进入工具参数",
  tainted_instruction: "调用受到不可信指令影响",
  sensitive_file_access_via_shell: "Shell 绕过文件工具读取敏感资产",
  policy_bypass_attempt: "尝试绕过既有安全边界",
  ct_trm_risk_score: "CT-TRM 风险分达到处置阈值",
  user_confirmation_required: "需要用户明确确认",
  user_rejected: "用户拒绝操作",
  tool_execution_failed: "工具执行阶段失败",
  write_operation: "检测到写入副作用",
  configuration_file_write: "检测到配置文件变更",
  file_not_found: "目标在受控工作区内不存在",
  external_command_workdir: "命令将在外部授权目录执行",
  command_workdir_not_found: "命令工作目录不存在",
  external_tool_execution_failed: "OpenCode 外部工具执行失败",
  task_tool_misalignment: "工具动作与任务目标不匹配",
  path_traversal_detected: "检测到路径穿越",
  path_traversal: "原始路径包含工作区逃逸",
  outside_workspace: "访问对象位于工作区外",
  command_from_untrusted_context: "低可信内容触发危险命令",
};
const reasonText = reason => REASON_LABELS[reason] || String(reason || "").replaceAll("_", " ");

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      ...options,
      headers: {"Content-Type": "application/json", ...(options.headers || {})},
    });
  } catch (_error) {
    throw new Error("无法连接本地服务，请确认网关已启动");
  }
  let body = {};
  try {
    body = await response.json();
  } catch (_error) {
    throw new Error(`服务返回了无法解析的响应（HTTP ${response.status}）`);
  }
  if (!response.ok) throw new Error(body.error || `请求失败（HTTP ${response.status}）`);
  return body;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 3200);
}

async function copyText(value) {
  const text = String(value || "");
  if (!text) return;
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
    else {
      const input = document.createElement("textarea");
      input.value = text;
      input.setAttribute("readonly", "");
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }
    toast("完整值已复制");
  } catch (_error) {
    toast("复制失败，请展开原始记录后手动复制");
  }
}

function displayTask(value) {
  const task = String(value || "").trim().replace(/^\d+(?=[\u3400-\u9fff])/, "");
  if (!task) return "未记录任务";
  return /\?{3,}/.test(task) ? "原始任务文本编码不可用（Trace 标识仍可检索）" : humanizeMachineText(task);
}

function displayTaskSummary(value, length = 160) {
  const task = displayTask(value);
  const boundary = task.slice(36).search(/[；。]/);
  const focused = boundary >= 0 ? task.slice(0, boundary + 37) : task;
  return truncate(focused, length);
}

function showDataStatus() {
  const node = $("#data-status");
  const errors = Object.entries(state.resourceErrors);
  if (!errors.length) {
    node.hidden = true;
    node.textContent = "";
    return;
  }
  const names = {
    health: "网关状态", overview: "总览统计", audit: "审计列表", policies: "策略",
    tools: "工具目录", providers: "模型配置", traces: "Trace", approvals: "审批队列", trusted: "可信工作区",
    traceDetail: "最近 Trace 详情", selectedTraceDetail: "当前 Trace 详情",
    chainVerification: "审计链校验", liveSync: "实时同步",
  };
  node.hidden = false;
  node.textContent = `部分数据读取失败：${errors.map(([key]) => names[key] || key).join("、")}。页面不会用 0 或“正常”代替缺失数据，请点击刷新重试。`;
}

function switchView(id) {
  const titles = {
    dashboard: ["系统总览", "工具调用安全网关的实时状态"],
    agent: ["Agent 控制台", "从原始调用到审计写入的完整安全闭环"],
    audit: ["审计日志", "检索并还原每次工具调用的裁决证据"],
    policies: ["生效策略", "当前后端策略描述与受控工具目录"],
  };
  $$(".view").forEach(view => view.classList.toggle("active", view.dataset.viewId === id));
  $$(".nav").forEach(button => {
    const active = button.dataset.view === id;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  setText("#page-title", titles[id]?.[0] || "CodeAgent Guard");
  setText("#page-subtitle", titles[id]?.[1] || "");
  history.replaceState(null, "", `#${id}`);
  window.scrollTo(0, 0);
  if (id === "dashboard") renderOverview();
  if (id === "audit") {
    renderCurrentAuditVerification();
    renderAuditList();
    if (!state.selectedAuditSeq && state.selectedTrace) syncAuditSelectionToCall(state.selectedTrace, state.selectedCallId);
    const auditSeq = state.selectedAuditSeq || state.auditEvents[0]?.seq;
    if (auditSeq) selectAuditEvent(auditSeq, false);
    scheduleLiveSync(0);
  }
}

function phase(trace, name, callId = null, last = false) {
  const values = (trace?.events || []).filter(event => event.phase === name && (!callId || event.details?.call_id === callId));
  return last ? values.at(-1) : values[0];
}

function callGroups(trace) {
  const groups = new Map();
  const events = trace?.events || [];
  const approvalCalls = new Map();
  events.forEach(event => {
    const approvalId = event.details?.approval_id;
    const callId = event.details?.call_id;
    if (approvalId && callId) approvalCalls.set(approvalId, callId);
  });
  events.forEach(event => {
    const callId = event.details?.call_id || approvalCalls.get(event.details?.approval_id);
    if (!callId) return;
    if (!groups.has(callId)) groups.set(callId, []);
    groups.get(callId).push(event);
  });
  return [...groups.entries()].map(([callId, events]) => {
    const event = name => events.find(item => item.phase === name);
    const lastEvent = name => events.filter(item => item.phase === name).at(-1);
    const plan = event("agent_plan");
    const policyEvents = events.filter(item => item.phase === "policy_decision");
    const initialPolicy = policyEvents[0];
    const policy = policyEvents.at(-1);
    const fusionEvents = events.filter(item => item.phase === "decision_fusion");
    const initialFusion = fusionEvents[0];
    const fusion = fusionEvents.at(-1);
    const actionEvents = events.filter(item => item.phase === "tool_action");
    const initialAction = actionEvents[0];
    const action = actionEvents.at(-1);
    const reportedResults = events.filter(item => item.phase === "tool_result" && item.status !== "unavailable");
    const result = reportedResults.at(-1) || lastEvent("tool_result");
    const auditEvents = events.filter(item => item.phase === "audit_record");
    const executionAudits = auditEvents.filter(item => item.details?.audit_type === "external_execution_result");
    const audit = executionAudits.at(-1) || auditEvents.at(-1);
    const approval = lastEvent("approval_decision");
    const initialDecision = first(initialFusion?.details?.decision, initialFusion?.status, initialPolicy?.details?.decision, initialPolicy?.status, initialAction?.status, "pending");
    const fusionDecision = first(fusion?.details?.decision, fusion?.status, initialDecision);
    const displayDecision = decisionClass(initialDecision) === "ask" && approval ? "ask" : fusionDecision;
    const dlpEvents = events.filter(item => item.phase === "dlp_scan");
    const dlpStage = item => String(first(item.details?.scan_stage, item.details?.direction, item.details?.target, "")).toLowerCase();
    const inputDlp = dlpEvents.find(item => /input|argument|request/.test(dlpStage(item))) || dlpEvents[0];
    const outputDlp = [...dlpEvents].reverse().find(item => /output|result|response/.test(dlpStage(item))) || (dlpEvents.length > 1 ? dlpEvents.at(-1) : null);
    return {
      callId,
      events,
      plan,
      initialPolicy,
      policy,
      initialFusion,
      fusion,
      initialAction,
      action,
      result,
      audit,
      approval,
      dlp: inputDlp,
      outputDlp,
      ct: lastEvent("ct_trm_assessment"),
      tool: first(plan?.details?.tool, policy?.details?.tool, action?.details?.tool, result?.details?.tool, "tool"),
      args: first(plan?.details?.arguments, policy?.details?.normalized_arguments, action?.details?.arguments, {}),
      initialDecision,
      fusionDecision,
      decision: displayDecision,
      risk: first(fusion?.details?.risk_level, policy?.details?.risk_level, "low"),
    };
  });
}

function callDecisionPresentation(group) {
  const initial = decisionClass(first(group?.initialDecision, group?.decision));
  const fusion = decisionClass(first(group?.fusionDecision, group?.decision));
  const approved = group?.approval?.details?.approved;
  if (initial === "ask" && approved === false) {
    return {decision: "ask", label: "ASK", status: "ASK → 用户拒绝", source: "Decision Fusion（初始裁决）", approval: "用户拒绝"};
  }
  if (initial === "ask" && approved === true) {
    return {decision: "ask", label: "ASK", status: "ASK → 用户批准", source: "Decision Fusion（初始裁决）", approval: "用户批准"};
  }
  return {decision: fusion, label: decisionLabel(fusion), status: decisionLabel(fusion), source: group?.fusion ? "Decision Fusion" : "历史裁决记录", approval: "无需审批"};
}

function fusionDecisionReason(group) {
  const fusion = group?.initialFusion?.details || group?.fusion?.details || {};
  const decision = decisionClass(first(group?.initialDecision, group?.fusionDecision, group?.decision));
  const reason = first(fusion.reason, fusion.explanation, (fusion.reasons || []).map(reasonText).join("；"));
  if (reason) return humanizeMachineText(reason);
  if (decision === "deny") return "风险证据达到拒绝条件，Decision Fusion 在执行前阻断该调用。";
  if (decision === "ask") return "风险证据要求人工确认，Decision Fusion 冻结参数并暂停执行。";
  if (decision === "allow") return "风险证据未达到阻断条件，Decision Fusion 允许调用进入受控执行阶段。";
  return "尚未生成 Decision Fusion 裁决。";
}

function presentationArgsForGroup(group, fallback = {}) {
  const presented = {...(fallback || {})};
  const plan = group?.plan?.details || {};
  const raw = plan.raw_arguments || plan.arguments || {};
  const rawPath = first(raw.path, raw.filePath, raw.file_path);
  if (rawPath && /(?:^|[\\/])\.\.(?:[\\/]|$)|%2e/i.test(String(rawPath))) {
    presented.path = rawPath;
  }
  const rawCommand = first(raw.cmd, raw.command);
  if (rawCommand) {
    if ("cmd" in presented || !("command" in presented)) presented.cmd = rawCommand;
    else presented.command = rawCommand;
  }
  [
    ["source", ["source", "src", "from"]],
    ["destination", ["destination", "dst", "to"]],
  ].forEach(([canonical, aliases]) => {
    const rawValue = first(...aliases.map(name => raw[name]));
    if (!rawValue || !/(?:^|[\\/])\.\.(?:[\\/]|$)|%2e/i.test(String(rawValue))) return;
    const existingAlias = aliases.find(name => name in presented);
    presented[existingAlias || canonical] = rawValue;
    presented[canonical] = rawValue;
  });
  return presented;
}

function latestCall(trace) {
  const groups = callGroups(trace);
  return groups.at(-1) || null;
}

function preferredCall(trace) {
  const groups = callGroups(trace);
  return groups.find(group => decisionClass(group.fusionDecision) === "deny"
    && !group.approval && group.action?.details?.executed === false && group.fusion && group.audit)
    || groups.at(-1)
    || null;
}

function traceIsComplete(trace) {
  const groups = callGroups(trace);
  return groups.length >= 1 && groups.length <= 3
    && groups.some(group => group.fusion && group.action && group.audit);
}

async function choosePrimaryTrace(summaries = state.traces) {
  const supported = summaries.filter(summary => {
    const count = Number(summary.event_count || 0);
    const kind = runtimeIdentity(summary.agent_id).kind;
    return count > 0 && count <= 80 && ["builtin", "opencode"].includes(kind);
  }).slice(0, 12);
  const candidates = await Promise.all(supported.map(async summary => {
    try {
      const trace = await api(`/api/traces/${encodeURIComponent(summary.trace_id)}`);
      return trace?.events ? trace : null;
    } catch (_error) {
      return null;
    }
  }));
  const complete = candidates.filter(trace => trace && traceIsComplete(trace));
  const directDeny = complete.find(trace => {
    const group = preferredCall(trace);
    return decisionClass(group?.fusionDecision) === "deny" && !group?.approval && group?.action?.details?.executed === false;
  });
  if (directDeny) return directDeny;
  if (complete[0]) return complete[0];
  const fallback = summaries.find(summary => Number(summary.event_count || 0) > 0 && Number(summary.event_count || 0) <= 80) || summaries[0];
  if (!fallback) return null;
  try {
    const trace = await api(`/api/traces/${encodeURIComponent(fallback.trace_id)}`);
    return trace?.events ? trace : null;
  } catch (_error) {
    return null;
  }
}

function syncAuditSelectionToCall(trace, callId) {
  const group = callGroups(trace).find(item => item.callId === callId) || preferredCall(trace);
  const event = auditForGroup(group, trace?.trace_id);
  if (event) state.selectedAuditSeq = Number(event.seq);
}

function auditCallId(event) {
  return first(event?.call_id, event?.tool_call_id, event?.result_evidence?.call_id, event?.args?._opencode?.call_id);
}

function auditLegacySignature(event) {
  return [event?.trace_id || "no-trace", event?.tool || "tool", JSON.stringify(event?.args || {})].join("::");
}

function auditRecordsForGroup(group, traceId = state.selectedTrace?.trace_id) {
  if (!group || !traceId) return [];
  const exact = state.auditEvents.filter(event => event.trace_id === traceId && auditCallId(event) === group.callId);
  if (exact.length) return [...exact].sort((left, right) => Number(left.seq || 0) - Number(right.seq || 0));

  const embeddedSeqs = new Set(group.events
    .filter(event => event.phase === "audit_record")
    .map(event => Number(event.details?.audit_seq || 0))
    .filter(Boolean));
  const embeddedMatches = state.auditEvents.filter(event => embeddedSeqs.has(Number(event.seq || 0)));
  if (embeddedMatches.length) {
    const legacySignatures = new Set(embeddedMatches.filter(event => !auditCallId(event)).map(auditLegacySignature));
    const relatedLegacy = state.auditEvents.filter(event => !auditCallId(event) && legacySignatures.has(auditLegacySignature(event)));
    return [...new Map([...embeddedMatches, ...relatedLegacy].map(event => [Number(event.seq), event])).values()]
      .sort((left, right) => Number(left.seq || 0) - Number(right.seq || 0));
  }

  const legacySignature = auditLegacySignature({trace_id: traceId, tool: group.tool, args: group.policy?.details?.normalized_arguments || group.args || {}});
  return state.auditEvents
    .filter(event => !auditCallId(event) && auditLegacySignature(event) === legacySignature)
    .sort((left, right) => Number(left.seq || 0) - Number(right.seq || 0));
}

function executionState(group, auditEvent = null) {
  if (!group) return {key: "unknown", title: "状态未知", detail: "没有可关联的执行事件。"};
  const action = group.action?.details || {};
  const result = group.result?.details || {};
  const payload = result.result || {};
  if (group.approval?.details?.approved === false) {
    return {key: "rejected", title: "工具未执行 · 用户已拒绝", detail: "审批结论已写入 Trace 与 Audit Hash Chain，没有产生工具副作用。"};
  }
  if (action.execution_delegated) {
    if (!group.result || group.result?.status === "unavailable" || result.result_unavailable) {
      return {key: "delegated", title: "已授权，外部执行结果未回报", detail: "Guard 只完成执行前授权，不能据此声称工具已执行。"};
    }
    if (payload.error || group.result?.status === "error") {
      return {key: "error", title: "OpenCode 已执行 · 执行失败", detail: maskSensitive(payload.error || group.result?.summary || "外部工具返回错误")};
    }
    if (payload.exit_code !== undefined) {
      const exitCode = Number(payload.exit_code);
      return {
        key: exitCode === 0 ? "executed" : "executed_nonzero",
        title: `OpenCode 已执行 · 退出码 ${exitCode}`,
        detail: exitCode === 0 ? "外部工具结果已回报 Guard 并写入审计链。" : "外部工具已运行，但进程以非零状态退出；结果已写入审计链。",
      };
    }
    return {key: "executed", title: "OpenCode 已执行", detail: "外部工具结果已回报 Guard 并写入审计链。"};
  }
  if (action.executed === false) {
    if (decisionClass(group.decision) === "ask") {
      const approvalPending = !state.resourceErrors.approvals && state.approvals.some(item => item.approval_id === action.approval_id);
      if (action.approval_id && !state.resourceErrors.approvals && !approvalPending) {
        return {key: "expired", title: "未执行 · 审批已失效", detail: "该请求已不在待审批队列；如需执行，应从原运行入口重新提交调用。"};
      }
      return {key: "waiting", title: "未执行 · 等待审批", detail: "参数已冻结，只有明确批准后才会进入执行阶段。"};
    }
    return {key: "blocked", title: "工具未执行", detail: "Tool Proxy 在产生副作用前阻断了调用。"};
  }
  if (action.executed === true) {
    if (payload.error || group.result?.status === "error" || (auditEvent?.reasons || []).includes("tool_execution_failed")) {
      return {key: "error", title: "已尝试执行 · 执行失败", detail: maskSensitive(payload.error || group.result?.summary || auditEvent?.result_summary || "执行器返回错误")};
    }
    if (payload.exit_code !== undefined) {
      const exitCode = Number(payload.exit_code);
      return {key: exitCode === 0 ? "executed" : "executed_nonzero", title: `已执行 · 退出码 ${exitCode}`, detail: exitCode === 0 ? "工具完成执行。" : "工具已运行，但进程以非零状态退出。"};
    }
    return {key: "executed", title: "工具已执行", detail: group.result?.summary || auditEvent?.result_summary || "执行器已返回结果。"};
  }
  return {key: "unknown", title: "执行状态未记录", detail: "Trace 中没有可确认的 Tool Proxy 执行动作。"};
}

function sourceFrom(group, trace) {
  const plan = group?.plan?.details || {};
  const matches = group?.ct?.details?.taint_matches || [];
  return first(matches[0]?.source_origin, matches[0]?.origin, plan.raw_arguments?.source_origin, plan.arguments?._opencode?.source_origin, matches[0]?.source, trace?.metadata?.source, plan.source, "未记录来源");
}

function replaceLiteral(text, search, replacement) {
  if (!search) return text;
  return text.split(search).join(replacement).split(search.replaceAll("/", "\\")).join(replacement);
}

function humanizeMachineText(value, traceId = "") {
  let text = maskSensitive(value);
  workspaceRoots().forEach(root => {
    text = replaceLiteral(text, root, "当前工作区");
    const match = root.match(/^([a-z]):\/(.*)$/i);
    if (match) text = replaceLiteral(text, `/mnt/${match[1].toLowerCase()}/${match[2]}`, "当前工作区");
  });
  const pathPattern = /(?:~\/(?:\.ssh|\.gnupg|\.aws|\.config)\/[^\s"'`,;)}\]]+|[A-Za-z]:[\\/][^\s"'`,;)}\]]+|\/mnt\/[A-Za-z]\/[^\s"'`,;)}\]]+|\/(?:home|Users|etc)\/[^\s"'`,;)}\]]+)/g;
  text = text.replace(pathPattern, match => pathPresentation(match).label);
  text = text.replace(/\b[a-f0-9]{40,128}\b/gi, match => shortHash(match));
  if (traceId) text = replaceLiteral(text, traceId, `Trace ${shortTrace(traceId)}`);
  return text;
}

function commandTarget(command) {
  const text = String(command || "").trim();
  const quoted = token => token?.replace(/^['"]|['"]$/g, "") || "";
  let match = text.match(/^\s*(?:cat|head|tail|wc|stat)\s+(?:-[^\s]+\s+)*(['"]?[^\s'"]+['"]?)/i);
  if (match) return quoted(match[1]);
  match = text.match(/^\s*(?:pytest|python\s+-m\s+pytest)\s+(['"]?[^\s'"]+['"]?)/i);
  if (match) return quoted(match[1]);
  match = text.match(/^\s*(?:ls|find)\s+(?:-[^\s]+\s+)*(['"]?[^\s'"]+['"]?)/i);
  return match ? quoted(match[1]) : "";
}

function commandDisplay(command) {
  const text = String(command || "").trim();
  if (!text) return "命令未记录";
  if (/^\s*pwd\s*$/i.test(text)) return "显示当前执行目录";
  if (/^\s*ls\b/i.test(text)) return "列出目标目录内容";
  if (/^\s*find\b/i.test(text)) return "搜索目标目录与文件";
  if (/^\s*(?:cat|head|tail)\b/i.test(text)) return "读取目标文件内容";
  if (/^\s*(?:wc|stat)\b/i.test(text)) return "读取目标文件元数据";
  if (/(?:^|\s)(?:pytest|python\s+-m\s+pytest|npm\s+(?:run\s+)?test)\b/i.test(text)) return "运行项目测试";
  if (/^\s*git\s+status\b/i.test(text)) return "查看版本库状态";
  if (/^\s*git\b/i.test(text)) return "执行版本库操作";
  if (/^\s*(?:curl|wget)\b/i.test(text)) return "发起网络请求";
  return "执行受控 Shell 命令";
}

function argumentSummary(tool, args = {}) {
  const command = String(args.cmd || args.command || "").trim();
  const path = String(args.path || args.filePath || args.file_path || "").trim();
  const cwd = first(args.cwd, args.workdir, args.working_directory, state.health?.workspace, ".");
  const rows = [{label: "工具", value: tool || "未记录"}];
  if (tool === "run_command") {
    const target = commandTarget(command);
    rows.push({label: "命令摘要", value: commandDisplay(command)});
    if (target) rows.push({label: "关键参数", value: pathPresentation(target).label});
    rows.push({label: "执行位置", value: pathPresentation(cwd).label});
    return {rows, oneLine: commandDisplay(command), scope: pathPresentation(cwd).label};
  }
  if (tool === "move_path") {
    const source = first(args.source, args.src, args.from, path);
    const destination = first(args.destination, args.dst, args.to);
    const sourceView = pathPresentation(source);
    const destinationView = pathPresentation(destination);
    const scope = sourceView.scope === "工作区内" && destinationView.scope === "工作区内" ? "工作区内" : "涉及工作区边界";
    const value = `${sourceView.label} → ${destinationView.label}`;
    rows.push({label: "关键参数", value});
    rows.push({label: "执行范围", value: scope});
    return {rows, oneLine: value, scope};
  }
  if (path) {
    const presented = pathPresentation(path);
    rows.push({label: "关键参数", value: presented.label});
    rows.push({label: "执行范围", value: presented.scope});
    return {rows, oneLine: presented.label, scope: presented.scope};
  }
  if (args.url) rows.push({label: "目标", value: truncate(args.url, 80)});
  else if (args.to) rows.push({label: "目标", value: truncate(args.to, 80)});
  else rows.push({label: "关键参数", value: "无需路径参数"});
  rows.push({label: "执行范围", value: "受控工具边界"});
  return {rows, oneLine: first(args.url, args.to, "无路径参数"), scope: "受控工具边界"};
}

function sourcePresentation(value) {
  const source = String(value || "").trim();
  if (!source || source === "user") return "用户直接任务";
  if (/^(?:agent|llm[_ -]?plan)$/i.test(source)) return "Agent 工具规划";
  if (/opencode/i.test(source) && !/[\\/]/.test(source)) return "OpenCode 适配器";
  if (/user[ _-]?task/i.test(source)) return "用户直接任务";
  if (/repository|repo|readme/i.test(source) && !/[\\/]/.test(source)) return "仓库内容";
  if (/[\\/]/.test(source)) return pathPresentation(source).label;
  return humanizeMachineText(source);
}

function semanticFor(tool, args = {}, group = null) {
  const command = String(args.cmd || args.command || "");
  const path = String(args.path || args.filePath || args.file_path || "");
  const url = String(args.url || "");
  const target = path || command || url || String(args.to || "");
  const shellTarget = commandTarget(command);
  if (/cat\s+.*(?:\.ssh[\\/]|id_rsa|id_ed25519)/i.test(command) || /(?:\.ssh[\\/]|id_rsa|id_ed25519)/i.test(path)) {
    return {object: pathPresentation(path || shellTarget).label, action: "读取并输出敏感文件", effect: "敏感凭据可能暴露"};
  }
  if (tool === "run_command" && /^\s*pwd\s*$/i.test(command)) {
    return {object: pathPresentation(first(args.cwd, args.workdir, state.health?.workspace, ".")).label, action: "显示当前执行目录", effect: "仅产生目录路径输出，不修改文件"};
  }
  if (tool === "run_command" && /(?:pytest|npm\s+(?:run\s+)?test|python\s+-m\s+pytest)/i.test(command)) {
    return {object: shellTarget ? pathPresentation(shellTarget).label : "工作区测试目录", action: "运行项目测试", effect: "产生测试输出与短时子进程，不应修改项目文件"};
  }
  if (tool === "read_file") {
    return {object: path ? pathPresentation(path).label : "工作区文件", action: "读取文件内容", effect: "文件内容进入 Agent 上下文，不修改文件"};
  }
  if (tool === "write_file") {
    const config = /\.ya?ml$|\.json$|\.toml$|\.ini$/i.test(path);
    return {object: path ? pathPresentation(path).label : "未指定文件", action: "创建或覆盖文件内容", effect: config ? "改变项目运行配置" : "修改工作区状态"};
  }
  if (tool === "delete_path") return {object: pathPresentation(path || target).label, action: "删除文件或空目录", effect: "目标内容不可继续使用"};
  if (tool === "move_path") return {object: `${pathPresentation(first(path, args.source, args.src, args.from)).label} → ${pathPresentation(first(args.destination, args.dst, args.to)).label}`, action: "移动或重命名", effect: "原路径引用可能失效"};
  if (tool === "http_request") return {object: `网络端点：${url || "未指定"}`, action: "发起受控网络请求", effect: "数据可能离开本机"};
  if (tool === "send_email") return {object: `邮件收件人：${args.to || "未指定"}`, action: "发送或排队邮件", effect: "内容可能对外传输"};
  if (tool === "run_command" && /^\s*(?:ls|find)\b/i.test(command)) return {object: pathPresentation(shellTarget || first(args.cwd, ".")).label, action: /^\s*ls\b/i.test(command) ? "列出目录内容" : "搜索目录与文件", effect: "文件名或匹配结果进入 Agent 上下文，不修改文件"};
  if (tool === "run_command" && /^\s*(?:cat|head|tail|wc|stat)\b/i.test(command)) return {object: pathPresentation(shellTarget).label, action: /^\s*stat\b/i.test(command) ? "读取文件元数据" : "读取并输出文件内容", effect: "读取结果进入 Agent 上下文，不修改文件"};
  if (tool === "run_command") return {object: shellTarget ? pathPresentation(shellTarget).label : pathPresentation(first(args.cwd, ".")).label, action: commandDisplay(command), effect: "启动受控子进程；具体影响由命令和参数决定"};
  if (tool === "list_directory" || tool === "search_files") return {object: pathPresentation(path || ".").label, action: tool === "list_directory" ? "列出目录内容" : "搜索工作区文件", effect: "文件名或匹配内容进入 Agent 上下文，不修改文件"};
  const feature = (group?.ct?.details?.features || []).find(item => item.name === "ActionRisk");
  return {object: target || "工具参数指定的资源", action: `${tool || "工具"} 操作`, effect: feature?.reason || "可能改变受控资源状态"};
}

function reasonCodes(value) {
  const values = Array.isArray(value) ? value : value ? [value] : [];
  return values.flatMap(item => {
    if (typeof item === "string") return [item];
    if (!item || typeof item !== "object") return [];
    return reasonCodes(first(item.reasons, item.reason_codes, item.reason, item.id, item.pattern_id));
  });
}

function policyEvidence(group) {
  const rules = group?.policy?.details?.matched_rules || [];
  const dlpReasons = new Set([
    ...reasonCodes(group?.dlp?.details?.reasons),
    ...reasonCodes(group?.dlp?.details?.findings),
  ]);
  const legacyCtReasons = group?.fusion ? [] : [
    ...reasonCodes(group?.ct?.details?.reasons),
    ...reasonCodes(group?.ct?.details?.risk_patterns),
  ];
  const ctOnlyReasons = new Set([
    "ct_trm_assessment", "ct_trm_risk_score", "tainted_argument_flow",
    "tainted_instruction", "sensitive_file_access_via_shell",
    "policy_bypass_attempt", "task_tool_misalignment",
    "user_confirmation_required", "untrusted_context_requires_confirmation",
    ...legacyCtReasons,
  ]);
  return rules.filter(rule => !ctOnlyReasons.has(rule) && !dlpReasons.has(rule));
}

function decisionReason(group) {
  const decision = decisionClass(group?.decision);
  const rules = policyEvidence(group);
  const patterns = group?.ct?.details?.risk_patterns || [];
  const fusion = group?.fusion?.details || {};
  const fusionReason = first(fusion.reason, fusion.explanation, (fusion.reasons || []).map(reasonText).join("；"));
  if (group?.approval?.details?.approved === false) return "该调用最初需要审批；用户已明确拒绝，系统保持阻断并记录审批结论。";
  if (fusionReason) return humanizeMachineText(fusionReason);
  if (decision === "deny") {
    if (patterns[0]?.name) return `调用命中“${patterns[0].name}”，并触发${reasonText(rules[0] || "ct_trm_risk_score")}，因此在执行前拒绝。`;
    return `调用命中${reasonText(rules[0] || "ct_trm_risk_score")}，风险证据达到拒绝条件。`;
  }
  if (decision === "ask") return `操作具有明确副作用，系统冻结当前参数并等待用户确认后再决定是否执行。`;
  if (decision === "allow") {
    if (group?.policy && group?.ct && group?.dlp) return "当前调用在任务授权和资源边界内，Policy、CT-TRM 与 DLP 未形成阻断证据。";
    return "最终记录为 ALLOW；部分证据事件未记录，不能据此推断对应模块的结论。";
  }
  return "尚未生成最终裁决。";
}

async function loadResource(key, path, apply) {
  try {
    const result = await api(path);
    delete state.resourceErrors[key];
    apply(result);
    return result;
  } catch (error) {
    state.resourceErrors[key] = error.message;
    return null;
  }
}

let liveSyncPromise = null;
let lastHealthSyncAt = 0;

async function refresh({preserveTrace = true, quiet = false} = {}) {
  if (state.loading) return;
  if (liveSyncPromise) await liveSyncPromise;
  if (state.loading) return;
  state.loading = true;
  $("#refresh").disabled = true;
  const selectedTraceId = preserveTrace && state.traceSelectionLocked ? state.selectedTrace?.trace_id : null;
  await Promise.all([
    loadResource("health", "/api/health", result => { state.health = result; }),
    loadResource("overview", "/api/overview", result => { state.overview = result; state.chainVerification = result.chain || null; }),
    loadResource("audit", "/api/audit?limit=100", result => { state.auditEvents = result.events || []; }),
    loadResource("policies", "/api/policies", result => { state.policies = result.policies || []; }),
    loadResource("tools", "/api/tools", result => { state.tools = result.tools || []; }),
    loadResource("providers", "/api/llm/providers", result => { state.providers = result.providers || []; state.providerCurrent = result.current || {}; }),
    loadResource("traces", "/api/traces?limit=60", result => { state.traces = result.traces || []; }),
    loadResource("approvals", "/api/approvals", result => { state.approvals = result.approvals || []; }),
    loadResource("trusted", "/api/trusted-workspaces", result => { state.trustedWorkspaces = result.roots || []; }),
  ]);
  if (!state.resourceErrors.health) lastHealthSyncAt = Date.now();
  const healthAvailable = !state.resourceErrors.health;
  const overviewAvailable = !state.resourceErrors.overview;
  const auditAvailable = !state.resourceErrors.audit;
  const policiesAvailable = !state.resourceErrors.policies;
  const toolsAvailable = !state.resourceErrors.tools;
  if (overviewAvailable) delete state.resourceErrors.chainVerification;
  else state.chainVerification = null;
  let primaryTrace = null;
  if (!state.resourceErrors.traces && state.traces.length) {
    try {
      const primarySummary = state.traceSelectionLocked && state.primaryTraceId
        ? state.traces.find(item => item.trace_id === state.primaryTraceId)
        : null;
      primaryTrace = primarySummary
        ? await api(`/api/traces/${encodeURIComponent(primarySummary.trace_id)}`)
        : await choosePrimaryTrace(state.traces);
      state.latestTrace = primaryTrace;
      state.primaryTraceId = primaryTrace?.trace_id || null;
      delete state.resourceErrors.traceDetail;
    } catch (error) {
      state.latestTrace = null;
      state.primaryTraceId = null;
      state.resourceErrors.traceDetail = error.message;
    }
  } else {
    state.latestTrace = null;
    state.primaryTraceId = null;
    delete state.resourceErrors.traceDetail;
  }

  const desiredTraceId = selectedTraceId || primaryTrace?.trace_id;
  if (desiredTraceId && desiredTraceId === primaryTrace?.trace_id) {
    delete state.resourceErrors.selectedTraceDetail;
    state.selectedTrace = primaryTrace;
    const groups = callGroups(state.selectedTrace);
    if (!groups.some(group => group.callId === state.selectedCallId)) state.selectedCallId = preferredCall(state.selectedTrace)?.callId || null;
  } else if (desiredTraceId && !state.resourceErrors.traces) {
    await loadTrace(desiredTraceId, {quiet: true, render: false, clearFilter: false});
  }
  if (state.selectedTrace) syncAuditSelectionToCall(state.selectedTrace, state.selectedCallId);

  renderShell();
  renderCurrentAuditVerification();
  if (auditAvailable) renderAuditList();
  if (policiesAvailable || toolsAvailable) renderPolicies();
  renderSettings();
  renderHistory();
  renderWorkbench();
  showDataStatus();
  if (healthAvailable || overviewAvailable || auditAvailable) renderOverview();
  if (activeViewId() === "audit" && state.selectedAuditSeq) await selectAuditEvent(state.selectedAuditSeq, false);
  state.loading = false;
  $("#refresh").disabled = false;
  if (!quiet && !Object.keys(state.resourceErrors).length) toast("运行态数据已刷新");
}

function renderShell() {
  const health = state.health;
  const gateway = $("#gateway-state");
  const dot = $("#runtime-dot");
  if (state.resourceErrors.health) {
    gateway.className = "gateway-state error";
    gateway.querySelector("strong").textContent = "网关连接失败";
    dot.className = "status-dot error";
    setText("#runtime-status", "连接失败");
    setText("#workspace-label", "无法读取工作区");
    setText("#runtime-workspace", "不可用");
  } else if (health?.ok) {
    gateway.className = "gateway-state online";
    gateway.querySelector("strong").textContent = "网关运行中";
    dot.className = "status-dot online";
    setText("#runtime-status", "运行中");
    setText("#workspace-label", workspaceName());
    setText("#runtime-workspace", workspaceName());
  }
}

function renderOverview() {
  const overview = state.overview;
  const overviewAvailable = !state.resourceErrors.overview;
  setText("#metric-calls", overviewAvailable && overview ? overview.calls : "—");
  setText("#metric-denied", overviewAvailable && overview ? overview.blocked : "—");
  setText("#metric-latency", overviewAvailable && overview ? Number(overview.avg_latency_ms || 0).toFixed(1) : "—");
  setText("#metric-approvals", state.resourceErrors.approvals ? "—" : state.approvals.length);
  const integrity = $("#overview-integrity");
  if (!overviewAvailable) {
    integrity.className = "integrity-line unknown";
    integrity.innerHTML = `<i>?</i><div><b>审计链状态不可用</b><span>本次读取失败，未沿用旧校验结论</span></div>`;
  } else if (state.chainVerification?.valid === true) {
    integrity.className = "integrity-line valid";
    integrity.innerHTML = `<i>✓</i><div><b>全局审计链校验通过</b><span>${esc(state.chainVerification.events)} 条记录 · Head ${esc(shortHash(state.chainVerification.head))}</span></div>`;
  } else if (state.chainVerification?.valid === false) {
    integrity.className = "integrity-line broken";
    integrity.innerHTML = `<i>!</i><div><b>全局审计链校验失败</b><span>断点位于事件 #${esc(state.chainVerification.broken_at)}</span></div>`;
  } else {
    integrity.className = "integrity-line unknown";
    integrity.innerHTML = `<i>?</i><div><b>审计链状态不可用</b><span>未取得后端校验结论</span></div>`;
  }
  const risks = state.auditEvents.filter(event => {
    const rejected = reasonCodes(event.reasons).includes("user_rejected");
    return !rejected && (event.decision === "deny" || ["high", "critical"].includes(event.risk_level));
  }).slice(0, 4);
  const risksNode = $("#recent-risks");
  if (state.resourceErrors.audit) {
    risksNode.className = "risk-list empty-state";
    risksNode.textContent = "审计数据读取失败";
  } else if (!risks.length) {
    risksNode.className = "risk-list empty-state";
    risksNode.textContent = "最近 100 条审计记录中没有高风险事件";
  } else {
    risksNode.className = "risk-list";
    risksNode.innerHTML = risks.map(event => `<button class="risk-item" type="button" data-audit-seq="${event.seq}"><span>${esc(riskLabel(event.risk_level))}</span><div><b>${esc(event.tool)}</b><small>${esc(displayTaskSummary(event.task, 52))}</small></div><time>${esc(formatDate(event.timestamp).slice(5, 16))}</time></button>`).join("");
  }
  const trace = state.latestTrace || null;
    renderOverviewCurrent(trace);
}

function renderOverviewCurrent(trace) {
  const node = $("#overview-current");
  const badge = $("#overview-decision");
  if (!trace) {
    node.className = "current-call empty-state";
    node.textContent = state.resourceErrors.traces || state.resourceErrors.traceDetail ? "Transparency Trace 读取失败" : "暂无 Trace 记录";
    badge.className = "decision-badge pending";
    badge.textContent = "暂无裁决";
    setText("#runtime-trace", state.resourceErrors.traces || state.resourceErrors.traceDetail ? "不可用" : "暂无记录");
    return;
  }
  const group = latestCall(trace);
  if (!group) {
    node.className = "current-call empty-state";
    node.textContent = "最近 Trace 中没有 ToolCall";
    return;
  }
  const auditEvent = auditForGroup(group, trace.trace_id);
  const execution = executionState(group, auditEvent);
  const decisionView = callDecisionPresentation(group);
  const decision = decisionView.decision;
  badge.className = `decision-badge ${decision}`;
  badge.textContent = decisionView.status;
  setText("#runtime-trace", `${displayTaskSummary(trace.task, 28)} · Trace ${shortTrace(trace.trace_id)}`);
  const summary = argumentSummary(group.tool, group.args || {});
  const audit = group.audit?.details || {};
  const verified = state.chainVerification?.valid === true;
  node.className = "current-call";
  node.innerHTML = `<div class="overview-call">
    <div class="overview-task"><small>${esc(runtimeIdentityLabel(trace.agent_id))}</small><b>${esc(displayTaskSummary(trace.task, 180))}</b><span>${identifierRef("Trace", trace.trace_id)}</span></div>
    <div class="overview-code overview-tool-summary">${summary.rows.map(row => `<div><small>${esc(row.label)}</small><code>${esc(row.value)}</code></div>`).join("")}</div>
    <div class="overview-outcome">
      <div><small>${esc(decisionView.source)}</small><b>${esc(decisionView.status)} · ${esc(riskLabel(group.risk))}</b><span>${esc(fusionDecisionReason(group))}</span></div>
      <div><small>执行状态</small><b>${esc(execution.title)}</b><span>${esc(humanizeMachineText(execution.detail, trace.trace_id))}</span></div>
      <div><small>审计记录</small><b>${group.audit ? `事件 #${esc(audit.audit_seq)} · ${verified ? "校验通过" : "已写入"}` : "未找到记录"}</b><span>${group.audit ? `Hash ${esc(shortHash(audit.hash))}` : "Trace 中没有 audit_record"}</span></div>
    </div>
    ${rawDetails("查看原始记录", {trace_id: trace.trace_id, task: trace.task, agent_id: trace.agent_id, tool_call: {tool: group.tool, arguments: group.args}, audit}, {copyValue: trace.trace_id})}
  </div>`;
}

async function loadTrace(traceId, {quiet = false, render = true, clearFilter = true, lockSelection = false} = {}) {
  try {
    const trace = await api(`/api/traces/${encodeURIComponent(traceId)}`);
    if (!trace?.events) throw new Error("Trace 不存在或没有事件");
    delete state.resourceErrors.selectedTraceDetail;
    state.selectedTrace = trace;
    if (lockSelection) state.traceSelectionLocked = true;
    const groups = callGroups(trace);
    if (!groups.some(group => group.callId === state.selectedCallId)) state.selectedCallId = preferredCall(trace)?.callId || null;
    if (clearFilter && $("#history-search")) $("#history-search").value = "";
    syncAuditSelectionToCall(trace, state.selectedCallId);
    if (render) {
      renderWorkbench();
      renderHistory();
    }
    return trace;
  } catch (error) {
    if (!quiet) toast(`Trace 加载失败：${error.message}`);
    return null;
  }
}

function renderHistory() {
  const node = $("#trace-history");
  const term = ($("#history-search")?.value || "").trim().toLowerCase();
  const matches = state.traces.filter(trace => !term || `${trace.task} ${trace.trace_id} ${trace.agent_id}`.toLowerCase().includes(term));
  const selectedSummary = state.traces.find(trace => trace.trace_id === state.selectedTrace?.trace_id);
  const visible = selectedSummary
    ? [selectedSummary, ...matches.filter(trace => trace.trace_id !== selectedSummary.trace_id)]
    : matches;
  const grouped = new Map();
  visible.forEach(trace => {
    const identity = runtimeIdentity(trace.agent_id);
    const key = `${identity.kind}::${displayTask(trace.task)}`;
    if (!grouped.has(key)) grouped.set(key, {trace, count: 0, selected: false});
    const entry = grouped.get(key);
    entry.count += 1;
    if (trace.trace_id === state.selectedTrace?.trace_id) {
      entry.trace = trace;
      entry.selected = true;
    }
  });
  const traces = [...grouped.values()];
  if (state.resourceErrors.traces) {
    node.className = "trace-history empty-state";
    node.textContent = "Trace 列表读取失败";
    return;
  }
  if (!traces.length) {
    node.className = "trace-history empty-state";
    node.textContent = term ? "没有匹配的 Trace" : "暂无 Trace 记录";
    return;
  }
  node.className = "trace-history";
  node.innerHTML = traces.slice(0, 20).map(item => {
    const trace = item.trace;
    const identity = runtimeIdentity(trace.agent_id);
    return `<button type="button" class="${item.selected ? "active" : ""}" data-trace-id="${esc(trace.trace_id)}"><b>${esc(displayTaskSummary(trace.task, 50))}</b><span>${esc(identity.entry)} · Trace ${esc(shortTrace(trace.trace_id))} · ${esc(formatDate(trace.updated_at))}${item.count > 1 ? ` · ${item.count} 次同类运行` : ""}</span></button>`;
  }).join("");
}

function auditForGroup(group, traceId = state.selectedTrace?.trace_id) {
  return auditRecordsForGroup(group, traceId).at(-1) || null;
}

function renderWorkbench() {
  const trace = state.selectedTrace;
  const groups = callGroups(trace);
  const group = groups.find(item => item.callId === state.selectedCallId) || groups.at(-1);
  if (!trace || !group) {
    setText("#task-summary", "请从最近 Trace 选择一次调用，或在下方“Agent 任务与设置”中运行任务。");
    return;
  }
  state.selectedCallId = group.callId;
  $("#task-summary").className = "task-summary";
  $("#task-summary").innerHTML = `<small>${esc(runtimeIdentityLabel(trace.agent_id))}</small><b>${esc(displayTaskSummary(trace.task, 180))}</b>${identifierRef("Trace", trace.trace_id)}${rawDetails("查看完整任务", {task: trace.task, agent_id: trace.agent_id})}`;
  $("#call-timeline").innerHTML = groups.map((item, index) => {
    const summary = argumentSummary(item.tool, item.policy?.details?.normalized_arguments || item.args || {});
    return `<button type="button" class="call-item ${decisionClass(item.decision)} ${item.callId === group.callId ? "active" : ""}" data-call-id="${esc(item.callId)}"><i>${index + 1}</i><div><b>${esc(item.tool)}</b><small>${esc(truncate(summary.oneLine, 48))}</small></div><em>${esc(decisionLabel(item.decision))}</em></button>`;
  }).join("");
  requestAnimationFrame(() => {
    const timeline = $("#call-timeline");
    const active = timeline?.querySelector(".call-item.active");
    if (!timeline || !active) return;
    const top = active.offsetTop - timeline.offsetTop;
    if (top < timeline.scrollTop || top + active.offsetHeight > timeline.scrollTop + timeline.clientHeight) {
      timeline.scrollTop = Math.max(0, top - Math.round((timeline.clientHeight - active.offsetHeight) / 2));
    }
  });

  const rawTool = group.plan?.details?.raw_tool || group.plan?.details?.arguments?._opencode?.tool || group.tool;
  const rawArgs = group.plan?.details?.raw_arguments || group.plan?.details?.arguments?._opencode?.args || group.plan?.details?.arguments || group.args || {};
  const normalizedArgs = group.policy?.details?.normalized_arguments || group.action?.details?.arguments || group.args || {};
  const presentationArgs = presentationArgsForGroup(group, normalizedArgs);
  const argumentInfo = argumentSummary(group.tool, presentationArgs);
  $("#toolcall-detail").className = "toolcall-detail";
  $("#toolcall-detail").innerHTML = `${argumentInfo.rows.map((row, index) => `<div><small>${esc(index === 0 ? "原始工具" : row.label)}</small><${index === 0 ? "b" : "code"}>${esc(index === 0 ? rawTool : row.value)}</${index === 0 ? "b" : "code"}></div>`).join("")}
    <div><small>统一 ToolCall 类型</small><code>${esc(group.tool)}</code></div>
    ${rawDetails("查看原始 ToolCall", {raw_tool: rawTool, raw_arguments: rawArgs, normalized_tool: group.tool, normalized_arguments: normalizedArgs})}`;

  const semantics = semanticFor(group.tool, presentationArgs, group);
  setText("#semantic-object", semantics.object);
  setText("#semantic-action", semantics.action);
  setText("#semantic-effect", semantics.effect);

  const ct = group.ct?.details || {};
  const matches = ct.taint_matches || [];
  const edges = ct.provenance_edges || [];
  const provenanceNode = $("#provenance-panel");
  if (matches.length || edges.length || group.plan?.details?.tainted) {
    const source = sourceFrom(group, trace);
    const target = first(matches[0]?.argument, Object.keys(normalizedArgs)[0], "tool arguments");
    provenanceNode.className = "provenance-panel";
    provenanceNode.innerHTML = `<small>来源与污染路径</small><b>${esc(sourcePresentation(source))}</b><code>${esc(sourcePresentation(source))} → 参数 ${esc(target)} → ${esc(group.tool)}</code>${rawDetails("查看完整污染证据", {source, taint_matches: matches, provenance_edges: edges})}`;
  } else {
    provenanceNode.className = "provenance-panel empty-state";
    provenanceNode.innerHTML = `<small>来源与污染路径</small><b>${esc(sourcePresentation(sourceFrom(group, trace)))}</b><code>未检测到参数污染传播</code>`;
  }
  renderEvidence(group);
  renderDecision(group);
  renderTraceEvents(trace, group.callId);
}

function renderEvidence(group) {
  const policy = group.policy?.details || {};
  const ct = group.ct?.details || {};
  const dlp = group.dlp?.details || {};
  const outputDlp = group.outputDlp?.details || {};
  const hasPolicy = Boolean(group.policy);
  const hasCt = Boolean(group.ct);
  const hasDlp = Boolean(group.dlp);
  const policyRules = policyEvidence(group);
  const patterns = ct.risk_patterns || [];
  const features = ct.features || [];
  const dlpCount = Number(dlp.finding_count || 0);
  const outputDlpCount = Number(outputDlp.finding_count || 0);
  const policyLines = !hasPolicy ? ["Trace 未记录 Policy Engine 证据"] : policyRules.length ? policyRules.slice(0, 5).map(reasonText) : ["未命中基础阻断规则"];
  const ctLines = !hasCt ? ["Trace 未记录 CT-TRM 评估"] : [
    `风险分 ${Number(ct.total_score || 0)}${ct.hard_deny ? " · 命中不可降级的高风险证据" : ""}`,
    ...patterns.slice(0, 2).map(item => `${item.pattern_id || "模式"} · ${item.name || item.explanation}`),
    ...features.filter(item => ["AssetRisk", "ActionRisk", "BoundaryRisk", "TaintRisk"].includes(item.name)).slice(0, 2).map(item => `${item.name}: ${item.reason}`),
  ];
  const dlpLines = !hasDlp ? ["Trace 未记录裁决前 DLP 输入扫描，不能推断为无风险"] : [
    dlpCount ? `输入检测到 ${dlpCount} 项敏感内容` : "输入未检测到敏感明文",
    ...(dlp.findings || []).slice(0, 1).map(item => `${item.secret_type || item.type || "secret"} · ${item.masked_value || "已脱敏"}`),
    group.outputDlp ? (outputDlpCount ? `执行后输出检测到 ${outputDlpCount} 项敏感内容` : "执行后输出未检测到敏感明文") : (group.action?.details?.executed === false ? "工具未执行，无输出可扫描" : "未记录独立输出扫描事件"),
  ];
  $("#evidence-panel").innerHTML = [
    ["Policy Engine", hasPolicy ? "规则证据" : "未记录", policyLines, policyRules.length],
    ["CT-TRM", hasCt ? "风险评估" : "未记录", ctLines, patterns.length || Number(ct.total_score || 0) > 0],
    ["DLP", hasDlp ? "检测结果" : "未记录", dlpLines, dlpCount > 0],
  ].map(([title, status, lines, highlighted]) => `<article class="evidence-card ${highlighted ? "evidence-present" : ""}"><header><b>${esc(title)}</b><span>${esc(status)}</span></header><ul>${lines.map(line => `<li>${esc(humanizeMachineText(line, state.selectedTrace?.trace_id))}</li>`).join("")}</ul></article>`).join("")
    + rawDetails("查看完整模块返回值", {policy_engine: hasPolicy ? policy : null, ct_trm: hasCt ? ct : null, dlp_input: hasDlp ? dlp : null, dlp_output: group.outputDlp ? outputDlp : null}, {className: "evidence-raw"});
}

function findApproval(group) {
  if (state.resourceErrors.approvals) return null;
  const approvalId = group?.action?.details?.approval_id;
  if (!approvalId) return null;
  return state.approvals.find(item => item.approval_id === approvalId) || null;
}

function renderDecision(group) {
  const decisionView = callDecisionPresentation(group);
  const decision = decisionView.decision;
  const panel = $("#decision-panel");
  panel.className = `decision-panel ${decision}`;
  panel.innerHTML = `<small>${esc(decisionView.source)} · ${esc(riskLabel(group.risk))}</small><strong>${esc(decisionView.label)}</strong><p>${esc(fusionDecisionReason(group))}</p>`;
  const auditEvent = auditForGroup(group);
  const execution = executionState(group, auditEvent);
  const executionNode = $("#execution-panel");
  executionNode.className = "execution-panel";
  executionNode.innerHTML = `<small>受控执行状态</small><b>${esc(execution.title)}</b><span>${esc(humanizeMachineText(execution.detail, state.selectedTrace?.trace_id))}</span>`;

  const approval = findApproval(group);
  const approvalNode = $("#approval-panel");
  if (decision === "ask" && approval) {
    approvalNode.hidden = false;
    approvalNode.innerHTML = `<p>参数已冻结。批准会让后端重新执行策略判定；拒绝不会执行工具。</p><div class="button-row"><button class="primary" type="button" data-approval-id="${esc(approval.approval_id)}" data-approve="true">批准并执行</button><button class="secondary" type="button" data-approval-id="${esc(approval.approval_id)}" data-approve="false">拒绝操作</button></div>`;
  } else if (decision === "ask" && group.approval) {
    const approved = group.approval.details?.approved === true;
    approvalNode.hidden = false;
    approvalNode.innerHTML = `<p><b>审批结果｜${approved ? "用户批准" : "用户拒绝"}</b><span>${approved ? "调用已按冻结参数进入受控执行。" : "工具保持未执行，审批结论已写入审计链。"}</span></p>`;
  } else {
    approvalNode.hidden = true;
    approvalNode.innerHTML = "";
  }

  const embeddedAudit = group.audit?.details || {};
  const linkedAudit = auditForGroup(group);
  const audit = linkedAudit ? {
    audit_seq: linkedAudit.seq,
    hash: linkedAudit.hash,
    prev_hash: linkedAudit.prev_hash,
    event_type: linkedAudit.event_type,
  } : embeddedAudit;
  const recordNode = $("#record-panel");
  if (group.audit || linkedAudit) {
    const verified = state.chainVerification?.valid === true;
    const broken = state.chainVerification?.valid === false;
    const embeddedSeq = Number(embeddedAudit.audit_seq || 0);
    const auditSource = linkedAudit && Number(linkedAudit.seq) !== embeddedSeq
      ? "关联审计库 · 最终记录"
      : linkedAudit ? "Trace 与审计库已关联" : "Trace 内嵌记录";
    recordNode.className = "record-panel";
    recordNode.innerHTML = `<small>审计已写入 · ${esc(auditSource)}</small><div class="record-facts"><div><i>Trace</i>${identifierRef("Trace", state.selectedTrace?.trace_id)}</div><div><i>事件</i><b>#${esc(audit.audit_seq)}</b></div><div><i>Hash</i>${identifierRef("Hash", audit.hash)}</div><div><i>完整性</i><b>${verified ? "校验通过" : broken ? "校验失败" : "已写入"}</b></div></div>${rawDetails("查看完整审计标识", {trace_id: state.selectedTrace?.trace_id, trace_audit_record: group.audit || null, linked_audit_record: linkedAudit || null})}`;
  } else {
    recordNode.className = "record-panel empty-state";
    recordNode.textContent = "当前 ToolCall 未找到 audit_record";
  }
}

function traceEventPresentation(event, trace, group) {
  const details = event?.details || {};
  const phaseName = String(event?.phase || "");
  const normalizedArgs = group?.policy?.details?.normalized_arguments || group?.args || {};
  const presentationArgs = presentationArgsForGroup(group, normalizedArgs);
  const summary = argumentSummary(group?.tool, presentationArgs);
  if (phaseName === "user_task") return {actor: "用户", title: "任务已进入安全网关", summary: displayTaskSummary(trace?.task || event.summary, 110)};
  if (phaseName === "task_authorization") return {actor: "任务授权", title: "提取本次任务边界", summary: truncate(humanizeMachineText(event.summary || "已确定允许工具与资源范围", trace?.trace_id), 110)};
  if (phaseName === "agent_synthesis") return {actor: "Agent", title: "汇总受控工具结果", summary: truncate(humanizeMachineText(event.summary || "根据已执行结果生成回答", trace?.trace_id), 110)};
  if (phaseName === "final_answer") return {actor: "Agent", title: "任务结束", summary: truncate(humanizeMachineText(event.summary || "最终回答已记录", trace?.trace_id), 110)};
  if (phaseName === "agent_pause") return {actor: "审批", title: "调用暂停等待审批", summary: "工具尚未执行，参数保持冻结。"};
  if (phaseName === "agent_resume") return {actor: "审批", title: "审批流程已结束", summary: truncate(humanizeMachineText(event.summary || "Agent 根据审批结论继续", trace?.trace_id), 110)};
  if (phaseName === "agent_plan") return {actor: runtimeIdentity(trace?.agent_id).entry, title: "捕获并标准化工具调用", summary: `${group?.tool || "工具"} · ${summary.oneLine}`};
  if (phaseName === "dlp_scan") {
    const count = Number(details.finding_count || 0);
    const stage = String(first(details.scan_stage, details.direction, details.target, "input")).toLowerCase();
    const target = /output|result|response/.test(stage) ? "工具输出" : "输入参数";
    return {actor: "DLP", title: `完成${target}敏感内容检测`, summary: count ? `${target}检测到 ${count} 项敏感特征；细节已脱敏` : `${target}未检测到敏感明文`};
  }
  if (phaseName === "ct_trm_assessment") {
    const pattern = (details.risk_patterns || [])[0];
    return {actor: "CT-TRM", title: "形成上下文风险证据", summary: `风险分 ${Number(details.total_score || 0)}${pattern ? ` · ${pattern.name || pattern.explanation}` : " · 未识别到高风险模式"}`};
  }
  if (phaseName === "policy_decision") {
    const rules = (details.matched_rules || []).filter(Boolean);
    return {actor: "Policy Engine", title: "完成规则匹配", summary: rules.length ? `命中：${rules.slice(0, 3).map(reasonText).join("、")}` : "未命中基础阻断规则"};
  }
  if (phaseName === "decision_fusion") {
    const decision = first(details.decision, event.status, group?.decision);
    const reason = first(details.reason, details.explanation, (details.reasons || []).map(reasonText).join("；"), decisionReason(group));
    return {actor: "Decision Fusion", title: `输出最终裁决 ${String(decisionLabel(decision)).toUpperCase()}`, summary: humanizeMachineText(reason, trace?.trace_id)};
  }
  if (phaseName === "tool_action") {
    const executed = details.executed;
    const delegated = details.execution_delegated;
    return {actor: "Tool Proxy", title: executed ? "受控工具已执行" : delegated ? "已授权外部工具执行" : "工具在执行前被阻断", summary: executed ? "执行动作已记录" : delegated ? "等待 OpenCode 回报真实执行结果" : "未产生工具副作用"};
  }
  if (phaseName === "tool_result") {
    const result = details.result || {};
    const exitCode = first(result.exit_code, details.exit_code);
    const failed = event.status === "error" || result.error;
    const readOnly = group?.tool === "read_file" || (group?.tool === "run_command" && /^\s*(?:pwd|cat|head|tail|wc|stat|ls)\b/i.test(String(presentationArgs.cmd || presentationArgs.command || "")));
    const modification = first(result.files_modified, result.modified_files, details.files_modified, details.modified_files);
    const modifiedText = Array.isArray(modification) ? `修改 ${modification.length} 个文件` : modification === false || readOnly ? "未修改文件" : "未记录文件变更结论";
    const resultText = first(details.summary, result.summary, result.error, "执行结果已回报");
    return {actor: "外部工具", title: failed ? "执行失败" : "执行成功", summary: `${exitCode !== undefined ? `退出码 ${exitCode} · ` : ""}${modifiedText} · ${humanizeMachineText(truncate(resultText, 72), trace?.trace_id)}`};
  }
  if (phaseName === "approval_decision") return {actor: "审批", title: details.approved ? "用户已批准" : "用户已拒绝", summary: details.approved ? "冻结参数将重新进入策略检查" : "工具保持未执行"};
  if (phaseName === "audit_record") {
    const linked = details.audit_source === "audit_store";
    const conclusion = linked && event.audit_record?.event_type === "external_execution_result"
      ? "外部执行结果"
      : linked ? `${decisionLabel(event.audit_record?.decision)} 裁决结论` : "Trace 内嵌写入事件";
    return {actor: "Audit Hash Chain", title: linked ? "关联审计记录已写入" : "审计记录已写入", summary: `事件 #${details.audit_seq || "—"} · ${conclusion} · 已与前一记录建立关联`};
  }
  return {actor: event.label || event.actor || "Trace", title: event.title || "安全处理事件", summary: humanizeMachineText(event.summary || "详细证据可展开查看", trace?.trace_id)};
}

const TRACE_STAGE_DEFINITIONS = [
  {key: "request", title: "请求进入", phases: ["user_task", "task_authorization"]},
  {key: "toolcall", title: "ToolCall 标准化与语义解析", phases: ["agent_plan"]},
  {key: "policy", title: "Policy Engine", phases: ["policy_decision"]},
  {key: "ct", title: "CT-TRM", phases: ["ct_trm_assessment"]},
  {key: "dlp", title: "DLP", phases: ["dlp_scan"]},
  {key: "fusion", title: "Decision Fusion", phases: ["decision_fusion"]},
  {key: "approval", title: "人工审批", phases: ["agent_pause", "approval_decision", "agent_resume"]},
  {key: "proxy", title: "Tool Proxy", phases: ["tool_action", "tool_result"]},
  {key: "audit", title: "Audit 写入", phases: ["audit_record"]},
  {key: "answer", title: "Agent 响应", phases: ["agent_synthesis", "final_answer"]},
];

function compareTimelineEvents(left, right) {
  const leftTime = Date.parse(left?.timestamp || "");
  const rightTime = Date.parse(right?.timestamp || "");
  if (Number.isFinite(leftTime) && Number.isFinite(rightTime) && leftTime !== rightTime) return leftTime - rightTime;
  return Number(left?.seq || 0) - Number(right?.seq || 0);
}

function linkedAuditTraceEvents(trace, group, traceEvents) {
  const embeddedSeqs = new Set(traceEvents
    .filter(event => event.phase === "audit_record")
    .map(event => Number(event.details?.audit_seq || 0))
    .filter(Boolean));
  return auditRecordsForGroup(group, trace?.trace_id)
    .filter(record => !embeddedSeqs.has(Number(record.seq || 0)))
    .map(record => ({
      phase: "audit_record",
      status: "recorded",
      timestamp: record.timestamp,
      details: {
        audit_seq: record.seq,
        hash: record.hash,
        prev_hash: record.prev_hash,
        audit_source: "audit_store",
      },
      audit_record: record,
    }));
}

function continuousTraceStages(events) {
  const stages = [];
  events.forEach(event => {
    const definition = TRACE_STAGE_DEFINITIONS.find(item => item.phases.includes(event.phase));
    if (!definition) return;
    const current = stages.at(-1);
    if (current?.key === definition.key) current.events.push(event);
    else stages.push({...definition, events: [event]});
  });
  const totals = stages.reduce((counts, stage) => counts.set(stage.key, (counts.get(stage.key) || 0) + 1), new Map());
  const seen = new Map();
  return stages.map(stage => {
    const occurrence = (seen.get(stage.key) || 0) + 1;
    seen.set(stage.key, occurrence);
    return {
      ...stage,
      title: totals.get(stage.key) > 1 ? `${stage.title} · ${occurrence === 1 ? "初次" : `第 ${occurrence} 次`}` : stage.title,
    };
  });
}

function traceEventsForCall(trace, group) {
  if (!trace || !group) return [];
  const directlyGrouped = new Set(group.events);
  const auditSeqs = new Set(state.auditEvents
    .filter(event => event.trace_id === trace.trace_id && auditCallId(event) === group.callId)
    .map(event => Number(event.seq)));
  const isLastCall = latestCall(trace)?.callId === group.callId;
  const globalPhases = new Set(["user_task", "task_authorization", ...(isLastCall ? ["agent_synthesis", "final_answer"] : [])]);
  return (trace.events || []).filter(event => directlyGrouped.has(event)
    || globalPhases.has(event.phase)
    || (event.phase === "audit_record" && auditSeqs.has(Number(event.details?.audit_seq))))
    .sort(compareTimelineEvents);
}

function renderTraceEvents(trace, callId) {
  const node = $("#trace-events");
  const group = callGroups(trace).find(item => item.callId === callId) || preferredCall(trace);
  const traceEvents = traceEventsForCall(trace, group);
  const linkedAuditEvents = linkedAuditTraceEvents(trace, group, traceEvents);
  const events = [...traceEvents, ...linkedAuditEvents].sort(compareTimelineEvents);
  if (!events.length) {
    setText("#trace-drawer-summary", `Trace ${trace?.trace_id ? shortTrace(trace.trace_id) : "未选择"} · 暂无关联事件`);
    node.className = "trace-events empty-state";
    node.textContent = "暂无事件";
    return;
  }
  node.className = "trace-events";
  const stages = continuousTraceStages(events);
  setText("#trace-drawer-summary", `${stages.length} 个阶段 · ${traceEvents.length} 个 Trace 事件${linkedAuditEvents.length ? ` · ${linkedAuditEvents.length} 条关联审计` : ""} · Trace ${trace?.trace_id ? shortTrace(trace.trace_id) : "未选择"}`);
  const args = presentationArgsForGroup(group, group?.policy?.details?.normalized_arguments || group?.args || {});
  const semantics = semanticFor(group?.tool, args, group);
  node.innerHTML = stages.map((stage, index) => {
    const lastEvent = stage.events.at(-1);
    const readable = traceEventPresentation(lastEvent, trace, group);
    let summary = readable.summary;
    let status = String(lastEvent.status || "已记录").toUpperCase();
    if (stage.key === "toolcall") summary = `${group?.tool || "工具"} · ${semantics.object} · ${semantics.action}`;
    if (stage.key === "fusion") status = decisionLabel(first(lastEvent.details?.decision, lastEvent.status));
    if (stage.key === "proxy") {
      const stageAction = stage.events.filter(event => event.phase === "tool_action").at(-1);
      const stageResult = stage.events.filter(event => event.phase === "tool_result").at(-1);
      if (decisionClass(first(stageAction?.status, stageAction?.details?.decision)) === "ask" && stageAction?.details?.executed === false) {
        summary = "工具未执行 · 等待审批";
        status = "等待审批";
      } else if (stageResult?.status === "unavailable" || stageResult?.details?.result_unavailable) {
        summary = "已授权，等待外部执行结果回报";
        status = "已授权";
      } else {
        const execution = executionState(group, auditForGroup(group, trace.trace_id));
        summary = execution.title;
        status = execution.key === "blocked" || execution.key === "rejected" ? "未执行" : execution.key === "waiting" ? "等待审批" : "已处理";
      }
    }
    if (stage.key === "audit") {
      const linkedCount = stage.events.filter(event => event.details?.audit_source === "audit_store").length;
      const embeddedCount = stage.events.length - linkedCount;
      summary = [embeddedCount ? `${embeddedCount} 个 Trace 写入事件` : "", linkedCount ? `${linkedCount} 条关联审计记录` : ""].filter(Boolean).join(" · ");
      status = "已写入";
    }
    return `<details class="trace-stage"><summary><i>${String(index + 1).padStart(2, "0")}</i><div><b>${esc(stage.title)}</b><span>${esc(humanizeMachineText(summary, trace.trace_id))}</span></div><time>${esc(formatDate(lastEvent.timestamp).slice(11))}<em>${esc(status)}</em></time><u>${stage.events.length} 个事件</u></summary><div class="trace-stage-events">${stage.events.map(event => {
      const item = traceEventPresentation(event, trace, group);
      const sequence = event.details?.audit_source === "audit_store" ? `Audit #${event.details.audit_seq}` : `#${event.seq}`;
      return `<article class="trace-event"><header><span>${esc(sequence)} · ${esc(item.actor)}</span><time>${esc(formatDate(event.timestamp).slice(11))}</time></header><b>${esc(item.title)}</b><p>${esc(item.summary)}</p>${rawDetails(event.details?.audit_source === "audit_store" ? "查看关联审计记录" : "查看原始事件", event.audit_record || event)}</article>`;
    }).join("")}</div></details>`;
  }).join("");
}

async function resolveApproval(approvalId, approve) {
  const buttons = $$(`[data-approval-id="${CSS.escape(approvalId)}"]`);
  buttons.forEach(button => { button.disabled = true; });
  try {
    const result = await api("/api/approvals/resolve", {method: "POST", body: JSON.stringify({approval_id: approvalId, approve, actor: "dashboard-user"})});
    toast(approve ? "审批已提交；正在读取执行结果" : "操作已拒绝；工具不会执行");
    await refresh({quiet: true});
    if (result.trace_id) await loadTrace(result.trace_id, {quiet: true, render: true, lockSelection: true});
  } catch (error) {
    buttons.forEach(button => { button.disabled = false; });
    toast(`审批失败：${error.message}`);
  }
}

function groupAuditEvents(events = state.auditEvents) {
  const grouped = new Map();
  events.forEach(event => {
    const callId = auditCallId(event);
    const key = callId ? `${event.trace_id || "no-trace"}::${callId}` : `legacy::${auditLegacySignature(event)}`;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(event);
  });
  return [...grouped.entries()].map(([key, records]) => {
    const ordered = [...records].sort((a, b) => Number(a.seq || 0) - Number(b.seq || 0));
    const decisionEvents = ordered.filter(event => event.event_type !== "external_execution_result");
    const initialDecisionEvent = decisionEvents[0] || ordered[0];
    const decisionEvent = decisionEvents.at(-1) || ordered[0];
    const resultEvent = [...ordered].reverse().find(event => event.event_type === "external_execution_result") || null;
    return {key, callId: first(auditCallId(decisionEvent), auditCallId(resultEvent)), events: ordered, initialDecisionEvent, decisionEvent, resultEvent, representative: decisionEvent || resultEvent};
  }).sort((a, b) => Math.max(...b.events.map(item => Number(item.seq || 0))) - Math.max(...a.events.map(item => Number(item.seq || 0))));
}

function auditGroupLifecycle(group) {
  const initial = decisionClass(group?.initialDecisionEvent?.decision);
  const final = decisionClass(group?.decisionEvent?.decision);
  const reasons = reasonCodes(group?.decisionEvent?.reasons);
  if (initial === "ask" && final === "deny" && reasons.includes("user_rejected")) {
    return {decision: "ask", label: "ASK → 用户拒绝", execution: "未执行"};
  }
  if (initial === "ask" && (final === "allow" || group?.resultEvent)) {
    const delegated = /delegated|等待外部|外部执行结果未回报/i.test(String(group?.decisionEvent?.result_summary || ""));
    const execution = group?.resultEvent
      ? (group.resultEvent.execution_status === "error" ? "执行失败" : "已执行")
      : delegated ? "已批准，等待外部结果" : "已执行";
    return {decision: "ask", label: "ASK → 用户批准", execution};
  }
  return {decision: final, label: decisionLabel(final), execution: ""};
}

function traceAgentId(traceId) {
  return state.traces.find(trace => trace.trace_id === traceId)?.agent_id || "";
}

function auditGroupExecutionLabel(group) {
  const lifecycle = auditGroupLifecycle(group);
  if (lifecycle.execution) return lifecycle.execution;
  const event = group.decisionEvent || group.representative;
  if (group.resultEvent) return group.resultEvent.execution_status === "error" ? "执行失败" : "已执行";
  const decision = decisionClass(event?.decision);
  if (decision === "deny") return "未执行";
  if (decision === "ask") return "等待审批";
  const summary = String(event?.result_summary || "").toLowerCase();
  if (/delegated|外部.*执行|授权.*外部/.test(summary)) return "已授权，等待外部结果";
  if (/failed|error|失败/.test(summary)) return "执行失败";
  return decision === "allow" ? "已执行" : "执行状态见详情";
}

function auditGroupForSeq(seq) {
  return groupAuditEvents().find(group => group.events.some(event => Number(event.seq) === Number(seq))) || null;
}

function renderAuditList() {
  const node = $("#audit-list");
  const term = ($("#audit-search")?.value || "").trim().toLowerCase();
  const decision = $("#decision-filter")?.value || "";
  const allGroups = groupAuditEvents();
  const groups = allGroups.filter(group => {
    const event = group.decisionEvent || group.representative;
    const lifecycle = auditGroupLifecycle(group);
    const haystack = group.events.map(item => `${item.task} ${item.tool} ${item.trace_id} ${item.call_id || ""} ${(item.reasons || []).join(" ")} ${JSON.stringify(item.args || {})}`).join(" ").toLowerCase();
    return (!term || haystack.includes(term)) && (!decision || lifecycle.decision === decision);
  });
  if (state.resourceErrors.audit) {
    node.className = "audit-list empty-state";
    node.textContent = "审计数据读取失败，请刷新重试";
    return;
  }
  if (!groups.length) {
    node.className = "audit-list empty-state";
    node.textContent = "暂无匹配的审计记录";
    return;
  }
  node.className = "audit-list";
  node.innerHTML = groups.map(group => {
    const event = group.decisionEvent || group.representative;
    const lifecycle = auditGroupLifecycle(group);
    const resultText = auditGroupExecutionLabel(group);
    const active = group.events.some(item => Number(item.seq) === Number(state.selectedAuditSeq));
    const sameTrace = allGroups.filter(item => item.representative?.trace_id === event.trace_id).sort((a, b) => Number(a.events.at(-1)?.seq || 0) - Number(b.events.at(-1)?.seq || 0));
    const ordinal = sameTrace.findIndex(item => item.key === group.key) + 1;
    const semantics = semanticFor(event.tool, event.args || {});
    const identity = runtimeIdentity(traceAgentId(event.trace_id));
    return `<button class="audit-row ${active ? "active" : ""}" type="button" data-audit-seq="${event.seq}"><span class="${lifecycle.decision}">${esc(lifecycle.label)}</span><div><b>调用 ${ordinal || 1} · ${esc(event.tool)} · ${esc(truncate(semantics.object, 42))}</b><small>${esc(resultText)} · ${esc(displayTaskSummary(event.task, 54))}</small><code>${esc(identity.entry)} · Trace ${esc(shortTrace(event.trace_id))} · ${group.events.length} 条关联记录</code></div><time>${esc(formatDate(group.events.at(-1)?.timestamp).slice(5, 16))}</time></button>`;
  }).join("");
  requestAnimationFrame(() => {
    const active = node.querySelector(".audit-row.active");
    if (!active) return;
    const top = active.offsetTop - node.offsetTop;
    if (top < node.scrollTop || top + active.offsetHeight > node.scrollTop + node.clientHeight) {
      node.scrollTop = Math.max(0, top - 8);
    }
  });
}

async function selectAuditEvent(seq, focus = true) {
  const auditGroup = auditGroupForSeq(seq);
  const event = auditGroup?.decisionEvent || auditGroup?.representative;
  if (!event) return;
  state.selectedAuditSeq = Number(seq);
  renderAuditList();
  let trace = null;
  try {
    trace = await api(`/api/traces/${encodeURIComponent(event.trace_id)}`);
  } catch (_error) {
    trace = null;
  }
  renderAuditDetail(event, trace, auditGroup.events);
  if (focus) $("#audit-detail-panel").focus({preventScroll: true});
}

function groupForAudit(trace, auditEvent) {
  const groups = callGroups(trace);
  const callId = auditCallId(auditEvent);
  return groups.find(group => callId && group.callId === callId)
    || groups.find(group => group.events.some(item => item.phase === "audit_record" && Number(item.details?.audit_seq) === Number(auditEvent.seq)))
    || groups.filter(group => group.tool === auditEvent.tool).at(-1)
    || null;
}

function renderAuditDetail(event, trace, auditRecords = [event]) {
  const panel = $("#audit-detail-panel");
  const group = groupForAudit(trace, event);
  const recordGroup = groupAuditEvents(auditRecords)[0] || null;
  const lifecycle = recordGroup ? auditGroupLifecycle(recordGroup) : {decision: decisionClass(event.decision), label: decisionLabel(event.decision)};
  const decisionView = group ? callDecisionPresentation(group) : {decision: lifecycle.decision, label: lifecycle.label, status: lifecycle.label, source: "历史裁决记录"};
  const execution = executionState(group, event);
  const source = group ? sourceFrom(group, trace) : event.source || "未记录来源";
  const ct = group?.ct?.details || event.ct_trm || {};
  const patterns = ct.risk_patterns || [];
  const policyRules = group ? policyEvidence(group) : [];
  const legacyFusedReasons = group ? [] : reasonCodes(event.reasons);
  const dlp = group?.dlp?.details || {};
  const outputDlp = group?.outputDlp?.details || {};
  const approvalEvents = (group?.events || trace?.events || []).filter(item => ["agent_pause", "approval_decision", "agent_resume"].includes(item.phase));
  const integrityText = state.chainVerification?.valid === true
    ? `全局链已校验 ${state.chainVerification.events} 条记录，当前结论通过。`
    : state.chainVerification?.valid === false
      ? `全局链校验失败，断点 #${state.chainVerification.broken_at}。`
      : "当前只确认记录已写入，尚未取得全局校验结论。";
  const dangerWhy = [
    ...policyRules.slice(0, 3).map(reasonText),
    ...patterns.slice(0, 2).map(item => `${item.pattern_id || "模式"} ${item.name || item.explanation}`),
    ...legacyFusedReasons.slice(0, 3).map(reasonText),
  ].filter(Boolean).join("；") || "没有记录到阻断风险证据";
  const traceEvents = group ? traceEventsForCall(trace, group) : (trace?.events || []);
  const normalizedArgs = group?.policy?.details?.normalized_arguments || event.args || {};
  const presentationArgs = presentationArgsForGroup(group, normalizedArgs);
  const rawPlanArgs = group?.plan?.details?.raw_arguments || group?.plan?.details?.arguments || event.args || {};
  const rawPlanTool = group?.plan?.details?.raw_tool || event.tool;
  const semantics = semanticFor(event.tool, presentationArgs, group);
  const argumentInfo = argumentSummary(event.tool, presentationArgs);
  const resultRecord = [...auditRecords].reverse().find(item => item.event_type === "external_execution_result") || null;
  const approvalSummary = approvalEvents.length ? approvalEvents.map(item => item.phase === "approval_decision" ? (item.details?.approved ? "用户批准" : "用户拒绝") : item.title).filter(Boolean).join(" → ") : (lifecycle.label.includes("用户拒绝") ? "用户拒绝" : lifecycle.decision === "ask" ? "等待审批" : "本次调用无需审批");
  const dlpInputText = group?.dlp ? (Number(dlp.finding_count || 0) ? `输入检测到 ${Number(dlp.finding_count)} 项敏感特征` : "输入未检测到敏感明文") : "未记录独立输入 DLP 事件";
  const dlpOutputText = group?.outputDlp ? (Number(outputDlp.finding_count || 0) ? `输出检测到 ${Number(outputDlp.finding_count)} 项敏感特征` : "输出未检测到敏感明文") : (execution.key === "blocked" || execution.key === "rejected" ? "工具未执行，无输出可扫描" : "未记录独立输出 DLP 事件");
  const policyText = group
    ? (policyRules.length ? policyRules.map(reasonText).join("、") : "未命中基础阻断规则")
    : "历史审计未保留独立 Policy 证据归属";
  const currentAudit = auditRecords.at(-1) || event;
  const auditFlow = auditRecords.map(item => `事件 #${item.seq}（${item.event_type === "external_execution_result" ? "执行结果" : "裁决"}）`).join(" → ");
  const identity = runtimeIdentity(first(trace?.agent_id, traceAgentId(event.trace_id)));
  const chainStatus = state.chainVerification?.valid === true ? "校验通过" : state.chainVerification?.valid === false ? "校验失败" : "已写入，待校验";
  const chainCount = state.chainVerification?.events ?? "—";
  panel.innerHTML = `<div class="audit-detail-head"><div><span class="section-kicker">${esc(runtimeIdentityLabel(first(trace?.agent_id, traceAgentId(event.trace_id))))}</span><h2>${esc(event.tool)} · ${esc(displayTaskSummary(event.task, 140))}</h2>${identifierRef("Trace", event.trace_id)}</div><span class="decision-badge ${decisionView.decision}">${esc(decisionView.status)}</span></div>
    <div class="question-grid">
      <div class="question-card"><small>危险从哪里来？</small><b>${esc(sourcePresentation(source))}</b><span>${event.tainted ? "该来源被标记为低可信并进入参数传播分析。" : "未标记为污染来源。"}</span></div>
      <div class="question-card"><small>为什么危险？</small><b>${esc(truncate(humanizeMachineText(dangerWhy, event.trace_id), 92))}</b><span>依据真实 Policy / CT-TRM / DLP 事件。</span></div>
      <div class="question-card"><small>最终有没有执行？</small><b>${esc(execution.title)}</b><span>${esc(humanizeMachineText(execution.detail, event.trace_id))}</span></div>
    </div>
    <section class="detail-section"><h3>任务目标与待执行动作</h3><dl class="detail-facts"><div><dt>任务目标</dt><dd>${esc(displayTaskSummary(event.task, 260))}</dd></div><div><dt>运行入口</dt><dd>${esc(identity.entry)}</dd></div>${identity.adapter ? `<div><dt>适配器</dt><dd>${esc(identity.adapter)}</dd></div>` : ""}${argumentInfo.rows.map(row => `<div><dt>${esc(row.label)}</dt><dd>${esc(row.value)}</dd></div>`).join("")}</dl>${rawDetails("查看完整任务", {task: event.task, trace_id: event.trace_id, agent_id: first(trace?.agent_id, traceAgentId(event.trace_id))})}</section>
    <section class="detail-section"><h3>参数安全语义</h3><dl class="detail-facts three"><div><dt>访问对象</dt><dd>${esc(semantics.object)}</dd></div><div><dt>操作行为</dt><dd>${esc(semantics.action)}</dd></div><div><dt>可能影响</dt><dd>${esc(semantics.effect)}</dd></div></dl></section>
    <section class="detail-section"><h3>来源与污染路径</h3><p class="readable-evidence"><b>${esc(sourcePresentation(source))}</b><span>${event.tainted ? `低可信来源 → ${esc((ct.taint_matches || [])[0]?.argument || "工具参数")} → ${esc(event.tool)}` : "未检测到参数污染传播"}</span></p></section>
    <section class="detail-section"><h3>风险证据</h3><div class="audit-evidence-grid"><div><b>Policy Engine</b><span>${esc(policyText)}</span></div><div><b>CT-TRM</b><span>风险分 ${esc(Number(ct.total_score || 0))}${patterns.length ? ` · ${esc(patterns.slice(0, 2).map(item => item.name || item.explanation).join("、"))}` : ""}</span></div><div><b>DLP</b><span>${esc(dlpInputText)}；${esc(dlpOutputText)}</span></div></div></section>
    <section class="detail-section"><h3>裁决、审批与执行</h3><dl class="detail-facts three"><div><dt>${esc(decisionView.source)}</dt><dd>${esc(decisionView.label)} · ${esc(group ? fusionDecisionReason(group) : decisionReason({decision: event.decision}))}</dd></div><div><dt>审批过程</dt><dd>${esc(approvalSummary)}</dd></div><div><dt>执行状态</dt><dd>${esc(execution.title)}</dd></div></dl></section>
    <section class="detail-section"><h3>审计完整性</h3><dl class="detail-facts audit-integrity-facts"><div><dt>审计完整性</dt><dd>${esc(chainStatus)}</dd></div><div><dt>当前事件</dt><dd>#${esc(currentAudit.seq)}</dd></div><div><dt>全局审计链</dt><dd>${esc(chainCount)} 条记录${state.chainVerification?.valid === true ? "完整" : ""}</dd></div><div><dt>Transparency Trace</dt><dd>${esc(traceEvents.length)} 个关联事件</dd></div></dl><details class="raw-details integrity-details"><summary><span>查看完整证据链</span><em>展开</em></summary><div class="integrity-details-body"><p class="audit-record-flow">本次调用关联：${esc(auditFlow)}</p><div class="hash-link"><div><small>当前记录的前序 Hash</small>${identifierRef("Hash", currentAudit.prev_hash)}</div><i>→</i><div><small>当前记录 Hash</small>${identifierRef("Hash", currentAudit.hash)}</div></div><p>${esc(integrityText)} 任一关键记录被改动，后续记录将无法通过校验。</p></div></details></section>
    <section class="detail-section"><h3>关联 Transparency Trace</h3>${traceEvents.length ? `<div class="mini-trace">${traceEvents.map(item => { const readable = traceEventPresentation(item, trace, group); return `<div><span>#${esc(item.seq)}</span><b>${esc(readable.title)}</b><code>${esc(readable.summary)}</code></div>`; }).join("")}</div>` : `<div class="empty-state">该历史记录没有可读取的 Transparency Trace；审计记录仍然保留。</div>`}</section>
    <section class="raw-evidence-stack">${rawDetails("查看原始 ToolCall", {raw_tool: rawPlanTool, raw_arguments: rawPlanArgs, normalized_tool: event.tool, normalized_arguments: normalizedArgs})}${rawDetails("查看完整风险证据", {source, tainted: event.tainted, policy_rules: policyRules, legacy_fused_reasons: legacyFusedReasons, ct_trm: ct, dlp_input: dlp, dlp_output: outputDlp})}${rawDetails("查看完整执行结果", {execution, trace_result: group?.result?.details || null, audit_result: resultRecord})}${rawDetails("查看原始审计事件", auditRecords)}</section>`;
}

function renderAuditVerification(kind, title, detail) {
  const node = $("#audit-verification");
  node.className = `audit-verification ${kind}`;
  node.innerHTML = `<b>${esc(title)}</b><span>${esc(detail)}</span>`;
}

function renderCurrentAuditVerification() {
  const result = state.chainVerification;
  if (state.resourceErrors.overview || state.resourceErrors.chainVerification) {
    renderAuditVerification("unknown", "全局审计链状态不可用", "本次未取得后端校验结论；页面不会沿用旧状态。");
  } else if (result?.valid === true) {
    renderAuditVerification("valid", "全局 Audit Hash Chain 校验通过", `已检查 ${result.events} 条记录，未发现断点；Head ${shortHash(result.head)}。`);
  } else if (result?.valid === false) {
    renderAuditVerification("broken", "全局 Audit Hash Chain 校验失败", `在审计事件 #${result.broken_at} 检测到前后哈希不一致。`);
  } else {
    renderAuditVerification("unknown", "尚未取得校验状态", "校验结论不会在前端预设。");
  }
}

async function verifyChain() {
  const button = $("#verify-chain");
  button.disabled = true;
  try {
    const result = await api("/api/audit/verify");
    state.chainVerification = result;
    delete state.resourceErrors.chainVerification;
    renderCurrentAuditVerification();
    renderOverview();
    renderWorkbench();
    showDataStatus();
  } catch (error) {
    state.chainVerification = null;
    state.resourceErrors.chainVerification = error.message;
    renderAuditVerification("broken", "哈希链校验请求失败", error.message);
    renderOverview();
    renderWorkbench();
    showDataStatus();
  } finally {
    button.disabled = false;
  }
}

async function tamperTest() {
  const button = $("#tamper-test");
  button.disabled = true;
  try {
    const result = await api("/api/audit/integrity-experiment");
    if (result.detected) renderAuditVerification("broken", "隔离副本篡改已检出", `篡改副本在事件 #${result.tampered?.broken_at} 断链；原始数据库 ${result.original?.events || 0} 条记录未被修改。`);
    else renderAuditVerification("unknown", "篡改实验未执行", reasonText(result.reason || "未检测到断点"));
  } catch (error) {
    renderAuditVerification("broken", "篡改实验请求失败", error.message);
  } finally {
    button.disabled = false;
  }
}

function policyBoundaries(policy) {
  const text = `${policy?.name || ""} ${policy?.scope || ""} ${policy?.detail || ""}`.toLowerCase();
  const boundaries = [];
  if (/trusted|workspace|worktree|工作区/.test(text)) boundaries.push("当前可信工作区");
  if (/outside|external|escape|traversal|\.\.[\\/]|越界|边界/.test(text)) boundaries.push("工作区边界与工作区外");
  if (/home|user directory|主目录/.test(text)) boundaries.push("用户主目录");
  if (/desktop|桌面/.test(text)) boundaries.push("用户桌面");
  if (/\.ssh|\.env|credential|secret|sensitive|config|敏感|凭据/.test(text)) boundaries.push("敏感配置目录");
  return [...new Set(boundaries)].join("、") || humanizeMachineText(policy?.scope || "全部受控工具");
}

function policyTrigger(policy) {
  const text = `${policy?.name || ""} ${policy?.detail || ""}`.toLowerCase();
  if (/\.ssh|credential|secret|sensitive|敏感|凭据/.test(text)) return "访问敏感资源或凭据文件时触发";
  if (/outside|external|escape|traversal|\.\.[\\/]|越界|外部|边界/.test(text)) return "目标越过当前可信工作区边界时触发";
  if (/write|delete|move|modify|写入|删除|移动/.test(text)) return "工具将修改或删除受控资源时触发";
  if (/command|shell|run_command/.test(text)) return "Shell 命令命中资源或行为边界时触发";
  if (/network|http|email|网络|邮件/.test(text)) return "数据将离开本机边界时触发";
  return "满足该规则定义的匹配对象与处置条件";
}

function policyEvidenceType(policy) {
  const text = `${policy?.name || ""} ${policy?.scope || ""} ${policy?.detail || ""}`.toLowerCase();
  if (/credential|secret|sensitive|\.ssh|敏感|凭据/.test(text)) return "敏感资源证据";
  if (/outside|external|workspace|escape|traversal|边界|越界/.test(text)) return "资源边界证据";
  if (/command|shell|run_command/.test(text)) return "命令行为证据";
  if (/network|http|ssrf|email|网络|外发|邮件/.test(text)) return "数据流向证据";
  if (/write|delete|move|modify|写入|删除|移动|变更/.test(text)) return "副作用证据";
  return "策略匹配证据";
}

function renderPolicies() {
  const list = $("#policy-list");
  setText("#policy-count", state.resourceErrors.policies ? "不可用" : `${state.policies.length} 条规则`);
  if (state.resourceErrors.policies) {
    list.className = "policy-list empty-state";
    list.textContent = "策略接口读取失败";
  } else if (!state.policies.length) {
    list.className = "policy-list empty-state";
    list.textContent = "后端未返回策略描述";
  } else {
    list.className = "policy-list";
    list.innerHTML = state.policies.map(policy => {
      return `<details class="policy-row"><summary><b>${esc(policy.name)}</b><span>${esc(policyBoundaries(policy))}</span><em>${esc(policyEvidenceType(policy))}</em><code>${esc(policyTrigger(policy))}</code><i>展开</i></summary><div class="policy-definition"><dl><div><dt>策略定义动作</dt><dd>${esc(policy.action || "未记录")}</dd></div><div><dt>完整适用范围</dt><dd>${esc(policy.scope || "未记录")}</dd></div><div><dt>完整匹配值</dt><dd><code>${esc(policy.detail || "未记录")}</code></dd></div></dl><pre>${esc(safeJson(policy))}</pre></div></details>`;
    }).join("");
  }
  const tools = $("#tool-catalog");
  if (state.resourceErrors.tools) {
    tools.className = "tool-catalog empty-state";
    tools.textContent = "工具目录读取失败";
  } else if (!state.tools.length) {
    tools.className = "tool-catalog empty-state";
    tools.textContent = "后端未返回工具定义";
  } else {
    tools.className = "tool-catalog";
    const representative = state.tools.slice(0, 6).map(tool => tool.name).join("、");
    tools.innerHTML = `<details class="tool-catalog-disclosure"><summary><div><b>受控工具｜${state.tools.length} 类</b><span>${esc(representative)}${state.tools.length > 6 ? " 等" : ""}</span></div><em>查看全部</em></summary><div class="tool-catalog-list">${state.tools.map(tool => `<div class="tool-item"><b>${esc(tool.name)}</b><span>${esc(tool.description)}</span><code>参数：${esc(Object.keys(tool.parameters?.properties || {}).join("、") || "无")}</code></div>`).join("")}</div></details>`;
  }
}

function renderSettings() {
  const current = state.providerCurrent || state.health?.llm || {};
  const select = $("#provider-select");
  const previous = select.value || current.provider || state.providers[0]?.id || "";
  if (!state.resourceErrors.providers) {
    select.innerHTML = state.providers.map(provider => `<option value="${esc(provider.id)}">${esc(provider.name)}</option>`).join("");
    select.value = state.providers.some(provider => provider.id === previous) ? previous : state.providers[0]?.id || "";
    if (!state.settingsInitialized) {
      applyProviderPreset(false);
      if (current.configured) {
        $("#provider-url").value = current.base_url || "";
        $("#provider-model").value = current.model || "";
      }
      state.settingsInitialized = true;
    }
  }
  setText("#provider-status", state.resourceErrors.providers ? "状态不可用" : current.configured ? `${current.provider_name} · ${current.model}` : "未配置");
  renderTaskTools();
  renderTrustedWorkspaces();
  setText("#context-status", state.contextId ? `上下文 ${truncate(state.contextId, 24)}` : "新上下文");
}

function applyProviderPreset(overwrite = true) {
  const preset = state.providers.find(item => item.id === $("#provider-select").value);
  if (!preset) return;
  if (overwrite || !$("#provider-url").value) $("#provider-url").value = preset.base_url || "";
  if (overwrite || !$("#provider-model").value) $("#provider-model").value = preset.model || "";
  $("#provider-models").innerHTML = (preset.models || []).map(model => `<option value="${esc(model)}"></option>`).join("");
  setText("#provider-note", `${String(preset.protocol || "").toUpperCase()} · ${preset.note || "供应商预设"}`);
}

function renderTaskTools() {
  const node = $("#task-tool-auth");
  if (state.resourceErrors.tools) {
    node.textContent = "工具目录读取失败";
    return;
  }
  node.innerHTML = state.tools.map(tool => `<label><input type="checkbox" value="${esc(tool.name)}" checked> ${esc(tool.name)}</label>`).join("");
}

function renderTrustedWorkspaces() {
  const node = $("#trusted-workspace-list");
  setText("#trusted-workspace-count", state.resourceErrors.trusted ? "—" : state.trustedWorkspaces.length);
  if (state.resourceErrors.trusted) {
    node.className = "trusted-workspace-list empty-state";
    node.textContent = "可信工作区读取失败";
  } else if (!state.trustedWorkspaces.length) {
    node.className = "trusted-workspace-list empty-state";
    node.textContent = "未配置额外可信目录";
  } else {
    node.className = "trusted-workspace-list";
    node.innerHTML = state.trustedWorkspaces.map(root => `<div class="workspace-item"><code>${esc(root.path)}</code><button type="button" aria-label="移除可信工作区 ${esc(root.path)}" data-remove-workspace="${esc(root.path)}">移除</button></div>`).join("");
  }
}

async function saveProvider(test = false) {
  const button = test ? $("#test-provider") : $("#save-provider");
  button.disabled = true;
  try {
    const config = {provider: $("#provider-select").value, base_url: $("#provider-url").value.trim(), model: $("#provider-model").value.trim()};
    if ($("#provider-key").value.trim()) config.api_key = $("#provider-key").value.trim();
    await api("/api/llm/config", {method: "POST", body: JSON.stringify(config)});
    $("#provider-key").value = "";
    if (test) {
      const result = await api("/api/llm/test", {method: "POST", body: "{}"});
      toast(`连接成功：${result.model || "模型"}`);
    } else toast("模型配置已应用到当前本地服务进程");
    await refresh({quiet: true});
  } catch (error) {
    toast(`模型配置失败：${error.message}`);
  } finally {
    button.disabled = false;
  }
}

async function updateTrustedWorkspace(action, path) {
  const value = String(path || "").trim();
  if (!value) return toast("请输入或选择目录路径");
  try {
    const result = await api("/api/trusted-workspaces", {method: "POST", body: JSON.stringify({action, path: value})});
    state.trustedWorkspaces = result.roots || [];
    $("#trusted-workspace-path").value = "";
    renderTrustedWorkspaces();
    toast(action === "add" ? "可信工作区已生效" : "可信工作区已移除");
  } catch (error) {
    toast(`可信工作区更新失败：${error.message}`);
  }
}

async function chooseTrustedWorkspace() {
  const button = $("#choose-trusted-workspace");
  button.disabled = true;
  try {
    const result = await api("/api/trusted-workspaces/select", {method: "POST", body: "{}"});
    if (result.path) $("#trusted-workspace-path").value = result.path;
  } catch (error) {
    toast(`目录选择失败：${error.message}`);
  } finally {
    button.disabled = false;
  }
}

async function runAgent() {
  const prompt = $("#agent-prompt").value.trim();
  if (!prompt) return toast("请输入 Agent 任务");
  const button = $("#run-agent");
  button.disabled = true;
  button.textContent = "运行中…";
  const resultNode = $("#agent-run-result");
  resultNode.className = "agent-run-result";
  resultNode.textContent = "LLM 正在规划并通过 Tool Proxy 调用受控工具…";
  try {
    const autoBudget = $("#task-budget-auto").checked;
    const allowedTools = autoBudget ? null : [...$("#task-tool-auth").querySelectorAll("input:checked")].map(input => input.value);
    if (!autoBudget && !allowedTools.length) throw new Error("请至少授权一个工具");
    const contextMax = Math.max(1000, Math.min(200000, Number($("#context-max").value || 20000)));
    const result = await api("/api/agent/run", {method: "POST", body: JSON.stringify({prompt, allowed_tools: allowedTools, conversation_id: state.contextId, context_max_chars: contextMax, new_context: !state.contextId})});
    state.contextId = result.conversation?.conversation_id || state.contextId;
    if (state.contextId) localStorage.setItem("agentContextId", state.contextId);
    resultNode.textContent = result.status === "awaiting_approval" ? "任务已暂停等待审批；上方工作台已载入证据。" : "任务已完成；上方工作台已载入真实 Trace。";
    if (result.trace_id) {
      state.primaryTraceId = result.trace_id;
      state.traceSelectionLocked = true;
    }
    await refresh({quiet: true, preserveTrace: false});
    if (result.trace_id) {
      await loadTrace(result.trace_id, {quiet: true, render: true, clearFilter: true});
      state.latestTrace = state.selectedTrace;
      renderOverview();
    }
    $("#settings-drawer").open = false;
  } catch (error) {
    resultNode.textContent = `任务运行失败：${error.message}`;
  } finally {
    button.disabled = false;
    button.textContent = "运行 Agent";
  }
}

function newAgentContext() {
  state.contextId = null;
  localStorage.removeItem("agentContextId");
  $("#agent-prompt").value = "";
  setText("#context-status", "新上下文");
  $("#agent-prompt").focus();
  toast("已创建新的本地 Agent 上下文");
}

const LIVE_SYNC_INTERVAL_MS = 3000;
let liveSyncTimer = null;
const deferredLiveViews = new Set();
const liveScrollSelectors = [
  "#call-timeline", "#trace-history", "#audit-list", ".trusted-workspace-list",
];

function activeViewId() {
  return $(".view.active")?.dataset.viewId || location.hash.slice(1) || "dashboard";
}

function traceSummaryVersion(trace) {
  if (!trace) return "";
  return [trace.trace_id, trace.updated_at, trace.event_count].map(value => String(value ?? "")).join("|");
}

function traceListVersion(traces = state.traces) {
  return traces.map(traceSummaryVersion).join("\n");
}

function approvalListVersion(approvals = state.approvals) {
  return approvals.map(item => [item.approval_id, item.trace_id, item.call_id, item.status, item.expires_at].join("|")).sort().join("\n");
}

function activeViewHasOpenDetails(viewId) {
  return Boolean(document.getElementById(`view-${viewId}`)?.querySelector("details[open]"));
}

function captureLiveScrollState(viewId) {
  const root = document.getElementById(`view-${viewId}`);
  if (!root) return null;
  return {
    viewId,
    windowX: window.scrollX,
    windowY: window.scrollY,
    targets: liveScrollSelectors.map(selector => {
      const node = root.querySelector(selector);
      return node ? {selector, top: node.scrollTop, left: node.scrollLeft} : null;
    }).filter(Boolean),
  };
}

function restoreLiveScrollState(snapshot) {
  if (!snapshot || activeViewId() !== snapshot.viewId) return;
  const root = document.getElementById(`view-${snapshot.viewId}`);
  if (!root) return;
  snapshot.targets.forEach(item => {
    const node = root.querySelector(item.selector);
    if (!node) return;
    node.scrollTop = item.top;
    node.scrollLeft = item.left;
  });
  window.scrollTo(snapshot.windowX, snapshot.windowY);
}

async function loadLiveTrace(traceId, errorKey) {
  try {
    const trace = await api(`/api/traces/${encodeURIComponent(traceId)}`);
    if (!trace?.events) throw new Error("Trace 不存在或没有事件");
    delete state.resourceErrors[errorKey];
    return trace;
  } catch (error) {
    state.resourceErrors[errorKey] = error.message;
    return null;
  }
}

async function syncLiveData() {
  if (document.hidden || state.loading || liveSyncPromise) return;

  const previousTraces = new Map(state.traces.map(trace => [trace.trace_id, trace]));
  const previousTraceListVersion = traceListVersion();
  const previousApprovalListVersion = approvalListVersion();
  const previousOverviewVersion = JSON.stringify(state.overview || null);
  const previousHealthVersion = JSON.stringify(state.health || null);
  const previousChainState = state.chainVerification?.valid;
  const previousResourceErrors = JSON.stringify(state.resourceErrors);
  const previousLatestId = state.latestTrace?.trace_id || null;
  const selectedTraceId = state.selectedTrace?.trace_id || null;
  const previousSelectedCallId = state.selectedCallId;
  const viewId = activeViewId();
  const previousAuditHead = state.chainVerification?.head || null;

  const run = (async () => {
    const resources = [
      loadResource("overview", "/api/overview", result => {
        state.overview = result;
        state.chainVerification = result.chain || null;
      }),
      loadResource("traces", "/api/traces?limit=60", result => { state.traces = result.traces || []; }),
      loadResource("approvals", "/api/approvals", result => { state.approvals = result.approvals || []; }),
    ];
    if (!state.health || Date.now() - lastHealthSyncAt >= 15000) {
      resources.push(loadResource("health", "/api/health", result => {
        state.health = result;
        lastHealthSyncAt = Date.now();
      }));
    }
    await Promise.all(resources);
    if (state.resourceErrors.overview) state.chainVerification = null;
    else delete state.resourceErrors.chainVerification;
    const auditChanged = !state.resourceErrors.overview
      && state.chainVerification?.head !== previousAuditHead;
    if (viewId === "audit" || auditChanged || state.resourceErrors.audit) {
      await loadResource("audit", "/api/audit?limit=100", result => { state.auditEvents = result.events || []; });
      if (auditChanged && state.selectedTrace) syncAuditSelectionToCall(state.selectedTrace, state.selectedCallId);
    }

    const tracesAvailable = !state.resourceErrors.traces;
    const traceListChanged = traceListVersion() !== previousTraceListVersion;
    let automaticPrimary = null;
    if (tracesAvailable && !state.traceSelectionLocked && (traceListChanged || !state.primaryTraceId || !state.traces.some(trace => trace.trace_id === state.primaryTraceId))) {
      automaticPrimary = await choosePrimaryTrace(state.traces);
      if (automaticPrimary?.trace_id) state.primaryTraceId = automaticPrimary.trace_id;
    }
    const latestSummary = tracesAvailable
      ? (state.traces.find(trace => trace.trace_id === state.primaryTraceId) || state.traces[0])
      : null;
    const latestTraceId = latestSummary?.trace_id || null;
    if (latestTraceId) state.primaryTraceId = latestTraceId;
    const latestChanged = Boolean(latestTraceId) && (
      previousLatestId !== latestTraceId
      || !state.latestTrace
      || traceSummaryVersion(previousTraces.get(latestTraceId)) !== traceSummaryVersion(latestSummary)
    );
    const selectedSummary = selectedTraceId && tracesAvailable
      ? state.traces.find(trace => trace.trace_id === selectedTraceId)
      : null;
    const selectedChanged = Boolean(selectedSummary) && (
      !state.selectedTrace
      || Boolean(state.resourceErrors.selectedTraceDetail)
      || traceSummaryVersion(previousTraces.get(selectedTraceId)) !== traceSummaryVersion(selectedSummary)
    );

    if (!tracesAvailable) {
      state.latestTrace = null;
      delete state.resourceErrors.traceDetail;
    } else if (!latestTraceId) {
      state.latestTrace = null;
      delete state.resourceErrors.traceDetail;
    } else {
      let latestDetail = automaticPrimary;
      if (latestChanged && !latestDetail) latestDetail = await loadLiveTrace(latestTraceId, "traceDetail");
      if (latestDetail) state.latestTrace = latestDetail;

      if ((!state.traceSelectionLocked || !selectedTraceId) && latestDetail) {
        delete state.resourceErrors.selectedTraceDetail;
        state.selectedTrace = latestDetail;
        state.selectedCallId = preferredCall(latestDetail)?.callId || null;
        syncAuditSelectionToCall(latestDetail, state.selectedCallId);
      } else if (selectedTraceId === latestTraceId && latestDetail) {
        delete state.resourceErrors.selectedTraceDetail;
        state.selectedTrace = latestDetail;
        const groups = callGroups(latestDetail);
        if (!groups.some(group => group.callId === state.selectedCallId)) {
          state.selectedCallId = preferredCall(latestDetail)?.callId || null;
        }
        syncAuditSelectionToCall(latestDetail, state.selectedCallId);
      } else if (selectedChanged) {
        const selectedDetail = await loadLiveTrace(selectedTraceId, "selectedTraceDetail");
        if (selectedDetail) {
          state.selectedTrace = selectedDetail;
          const groups = callGroups(selectedDetail);
          if (!groups.some(group => group.callId === state.selectedCallId)) {
            state.selectedCallId = preferredCall(selectedDetail)?.callId || null;
          }
          syncAuditSelectionToCall(selectedDetail, state.selectedCallId);
        }
      }
    }

    const tracesChanged = traceListChanged;
    const approvalsChanged = approvalListVersion() !== previousApprovalListVersion;
    const overviewChanged = JSON.stringify(state.overview || null) !== previousOverviewVersion;
    const healthChanged = JSON.stringify(state.health || null) !== previousHealthVersion;
    const chainStateChanged = state.chainVerification?.valid !== previousChainState;
    const errorsChanged = JSON.stringify(state.resourceErrors) !== previousResourceErrors;
    const selectedInitialized = !selectedTraceId && Boolean(state.selectedTrace);
    const selectedCallChanged = previousSelectedCallId !== state.selectedCallId;

    let historyNeedsRender = tracesChanged || errorsChanged;
    let workbenchNeedsRender = selectedChanged || selectedInitialized || selectedCallChanged || approvalsChanged || auditChanged || chainStateChanged || healthChanged || errorsChanged || (!state.traceSelectionLocked && latestChanged);
    let overviewNeedsRender = overviewChanged || latestChanged || auditChanged || healthChanged || errorsChanged;
    let auditNeedsRender = auditChanged || chainStateChanged || errorsChanged || (!state.selectedAuditSeq && state.auditEvents.length > 0);
    const activeNeedsRender = viewId === "agent"
      ? historyNeedsRender || workbenchNeedsRender
      : viewId === "dashboard"
        ? overviewNeedsRender
        : viewId === "audit"
          ? auditNeedsRender
          : false;
    const interactionLocked = activeViewHasOpenDetails(viewId);
    if (interactionLocked && activeNeedsRender) deferredLiveViews.add(viewId);
    const flushDeferred = !interactionLocked && deferredLiveViews.has(viewId);
    if (flushDeferred && viewId === "agent") {
      historyNeedsRender = true;
      workbenchNeedsRender = true;
    } else if (flushDeferred && viewId === "dashboard") {
      overviewNeedsRender = true;
    } else if (flushDeferred && viewId === "audit") {
      auditNeedsRender = true;
    }
    const scrollState = !interactionLocked && (activeNeedsRender || flushDeferred) ? captureLiveScrollState(viewId) : null;

    if (healthChanged || errorsChanged) renderShell();
    if (historyNeedsRender && !(viewId === "agent" && interactionLocked)) renderHistory();
    if (workbenchNeedsRender && !(viewId === "agent" && interactionLocked)) renderWorkbench();
    if (overviewNeedsRender && !(viewId === "dashboard" && interactionLocked)) renderOverview();
    if (viewId === "audit" && (auditChanged || chainStateChanged || flushDeferred) && !interactionLocked) renderCurrentAuditVerification();
    if (viewId === "audit" && auditNeedsRender && !interactionLocked) {
      renderAuditList();
      if (!state.selectedAuditSeq && state.selectedTrace) syncAuditSelectionToCall(state.selectedTrace, state.selectedCallId);
      if (!state.selectedAuditSeq && state.auditEvents.length) {
        await selectAuditEvent(state.auditEvents[0].seq, false);
      } else if (state.selectedAuditSeq && state.auditEvents.some(event => event.seq === state.selectedAuditSeq)) {
        await selectAuditEvent(state.selectedAuditSeq, false);
      }
    }
    if (!interactionLocked && (activeNeedsRender || flushDeferred)) {
      deferredLiveViews.delete(viewId);
      restoreLiveScrollState(scrollState);
    }
    showDataStatus();
  })();

  liveSyncPromise = run;
  try {
    await run;
  } finally {
    if (liveSyncPromise === run) liveSyncPromise = null;
  }
}

function scheduleLiveSync(delay = LIVE_SYNC_INTERVAL_MS) {
  clearTimeout(liveSyncTimer);
  liveSyncTimer = setTimeout(async () => {
    try {
      await syncLiveData();
      delete state.resourceErrors.liveSync;
    } catch (error) {
      state.resourceErrors.liveSync = error?.message || "未知错误";
      showDataStatus();
    } finally {
      scheduleLiveSync();
    }
  }, delay);
}

document.addEventListener("click", event => {
  const copy = event.target.closest("[data-copy-value]");
  if (copy) {
    event.preventDefault();
    event.stopPropagation();
    copyText(copy.dataset.copyValue);
    return;
  }
  const nav = event.target.closest("[data-view]");
  if (nav) switchView(nav.dataset.view);
  const jump = event.target.closest("[data-jump]");
  if (jump) switchView(jump.dataset.jump);
  const trace = event.target.closest("[data-trace-id]");
  if (trace) loadTrace(trace.dataset.traceId, {lockSelection: true});
  const call = event.target.closest("[data-call-id]");
  if (call) {
    state.traceSelectionLocked = true;
    state.selectedCallId = call.dataset.callId;
    syncAuditSelectionToCall(state.selectedTrace, state.selectedCallId);
    renderWorkbench();
  }
  const audit = event.target.closest("[data-audit-seq]");
  if (audit) { switchView("audit"); selectAuditEvent(audit.dataset.auditSeq); }
  const approval = event.target.closest("[data-approval-id]");
  if (approval) resolveApproval(approval.dataset.approvalId, approval.dataset.approve === "true");
  const removeWorkspace = event.target.closest("[data-remove-workspace]");
  if (removeWorkspace) updateTrustedWorkspace("remove", removeWorkspace.dataset.removeWorkspace);
});

$("#refresh").addEventListener("click", () => refresh());
$("#history-search").addEventListener("input", renderHistory);
$("#audit-search").addEventListener("input", renderAuditList);
$("#decision-filter").addEventListener("change", renderAuditList);
$("#reset-audit").addEventListener("click", () => { $("#audit-search").value = ""; $("#decision-filter").value = ""; renderAuditList(); });
$("#verify-chain").addEventListener("click", verifyChain);
$("#tamper-test").addEventListener("click", tamperTest);
$("#provider-select").addEventListener("change", () => applyProviderPreset(true));
$("#save-provider").addEventListener("click", () => saveProvider(false));
$("#test-provider").addEventListener("click", () => saveProvider(true));
$("#choose-trusted-workspace").addEventListener("click", chooseTrustedWorkspace);
$("#add-trusted-workspace").addEventListener("click", () => updateTrustedWorkspace("add", $("#trusted-workspace-path").value));
$("#trusted-workspace-path").addEventListener("keydown", event => { if (event.key === "Enter") updateTrustedWorkspace("add", event.currentTarget.value); });
$("#task-budget-auto").addEventListener("change", event => { $(".manual-tools").hidden = event.target.checked; });
$("#run-agent").addEventListener("click", runAgent);
$("#new-agent-context").addEventListener("click", newAgentContext);
document.addEventListener("keydown", event => {
  if (event.key === "Escape") {
    $("#trace-drawer").open = false;
    $("#settings-drawer").open = false;
  }
});
document.addEventListener("toggle", event => {
  if (event.target instanceof HTMLDetailsElement && !event.target.open && deferredLiveViews.has(activeViewId())) {
    scheduleLiveSync(0);
  }
}, true);

const initialView = location.hash.slice(1);
switchView(["dashboard", "agent", "audit", "policies"].includes(initialView) ? initialView : "dashboard");
requestAnimationFrame(() => window.scrollTo(0, 0));
refresh({quiet: true});
scheduleLiveSync();
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) scheduleLiveSync(0);
});
