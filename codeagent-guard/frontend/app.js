const state = {
  events: [], overview: {}, policies: [], providers: [], tools: [],
  evaluation: null, currentAgentResult: null, taskToolsInitialized: false,
  traces: [], conversations: [], selectedTraceId: null,
  currentConversation: null,
  trustedWorkspaces: [],
  agentContextId: localStorage.getItem("agentContextId") || null,
  contextMaxChars: Number(localStorage.getItem("agentContextMaxChars") || 20000),
  forceNewContext: false, contextIsFull: false
};
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const time = (iso) => new Date(iso).toLocaleTimeString("zh-CN", {hour12:false});
const dateTime = (iso) => new Date(iso).toLocaleString("zh-CN", {
  month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", hour12:false
});
const fullDateTime = (iso) => {
  const value = new Date(iso);
  const pad = number => String(number).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth()+1)}-${pad(value.getDate())} ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`;
};
const short = (value, n=44) => String(value ?? "").length > n ? String(value).slice(0,n) + "…" : String(value ?? "");

function applyTheme(theme) {
  const nextTheme = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = nextTheme;
  const toggle = $("#theme-toggle");
  if (toggle) toggle.setAttribute("aria-pressed", String(nextTheme === "light"));
}

function toggleTheme() {
  const theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  localStorage.setItem("guardTheme", theme);
  applyTheme(theme);
}

async function api(path, options={}) {
  const response = await fetch(path, {
    headers: {"Content-Type": "application/json", ...(options.headers || {})},
    ...options
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 2600);
}

function readContextMax() {
  const input = $("#context-max");
  const raw = Number(input?.value || state.contextMaxChars || 20000);
  const value = Number.isFinite(raw)
    ? Math.max(1000, Math.min(raw, 200000))
    : 20000;
  state.contextMaxChars = value;
  localStorage.setItem("agentContextMaxChars", String(value));
  if (input) input.value = value;
  return value;
}

function applyConversationState(conversation) {
  if (!conversation?.conversation_id) return;
  state.agentContextId = conversation.conversation_id;
  state.forceNewContext = false;
  state.contextMaxChars = conversation.max_chars || state.contextMaxChars;
  localStorage.setItem("agentContextId", state.agentContextId);
  localStorage.setItem("agentContextMaxChars", String(state.contextMaxChars));
  renderContextStatus(conversation);
}

function renderContextStatus(conversation=null) {
  const context = conversation || state.currentAgentResult?.conversation || {
    conversation_id: state.agentContextId || "new",
    max_chars: state.contextMaxChars || 20000,
    used_chars: 0,
    stored_chars: 0,
    usage_ratio: 0,
    turns: 0,
    near_limit: false,
    truncated: false,
  };
  const max = context.max_chars || state.contextMaxChars || 20000;
  const used = Math.min(context.used_chars ?? context.stored_chars ?? 0, max);
  state.contextIsFull = (context.stored_chars || 0) >= max;
  const ratio = Math.max(0, Math.min(100, Math.round((used / max) * 100)));
  if ($("#context-max")) $("#context-max").value = max;
  if ($("#context-id")) $("#context-id").textContent = context.conversation_id || "new";
  if ($("#context-used")) $("#context-used").textContent = `${used}/${max}`;
  if ($("#context-turns")) $("#context-turns").textContent = `${context.turns || 0} turns`;
  if ($("#context-bar")) $("#context-bar").style.width = `${ratio}%`;
  const panel = $("#context-panel");
  if (panel) {
    panel.classList.toggle("near-limit", !!context.near_limit);
    panel.classList.toggle("truncated", !!context.truncated);
  }
  const warning = $("#context-warning");
  if (warning) {
    warning.textContent = context.truncated
      ? "上下文历史已超过本次最大可带入量，系统只会携带最近内容。建议新建上下文。"
      : context.near_limit
        ? "上下文接近最大量，建议完成当前问题后新建上下文。"
        : "当前上下文余量充足。";
  }
}

function newAgentContext() {
  state.agentContextId = null;
  state.currentAgentResult = null;
  state.selectedTraceId = null;
  state.forceNewContext = true;
  state.contextIsFull = false;
  localStorage.removeItem("agentContextId");
  $("#agent-output").innerHTML = `<span class="output-placeholder">已新建空白上下文，可以开始新的 Agent 对话。</span>`;
  $("#agent-prompt").value = "";
  renderContextStatus();
  $("#agent-prompt").focus();
  toast("已新建 Agent 上下文");
}

function switchView(id) {
  $$(".view").forEach(v => v.classList.toggle("active", v.id === id));
  $$(".nav").forEach(v => v.classList.toggle("active", v.dataset.view === id));
  const names = {dashboard:"安全总览", agent:"Agent 控制台", evaluation:"评测中心", audit:"审计日志", policies:"策略中心"};
  $("#page-title").textContent = names[id];
}

function renderOverview() {
  const o = state.overview;
  $("#metric-calls").textContent = o.calls || 0;
  $("#metric-blocked").textContent = o.blocked || 0;
  $("#metric-rate").textContent = `阻断率 ${o.block_rate || 0}%`;
  $("#metric-latency").textContent = o.avg_latency_ms || 0;
  $("#metric-chain").textContent = o.chain?.valid ? "VALID" : "BROKEN";
  $("#metric-chain").style.color = o.chain?.valid ? "var(--green)" : "var(--red)";
  $("#chain-count").textContent = `${o.chain?.events || 0} 个事件已校验`;
  const llm = $("#llm-state");
  llm.classList.toggle("ready", !!o.llm?.configured);
  llm.querySelector("b").textContent = o.llm?.configured ? `${o.llm.model || "LLM"} 已连接` : "LLM 未配置 · 演示可用";

  const risks = {critical:0, high:0, medium:0, low:0, ...(o.risks || {})};
  const total = Object.values(risks).reduce((a,b)=>a+b,0);
  $("#risk-total").textContent = total;
  let angle = 0;
  const critical = total ? risks.critical/total*360 : 0; angle += critical;
  const high = total ? risks.high/total*360 : 0; angle += high;
  const medium = total ? risks.medium/total*360 : 0; angle += medium;
  $("#risk-donut").style.cssText = `--critical:${critical}deg;--high:${critical+high}deg;--medium:${angle}deg`;
  const colors = {critical:"var(--red)",high:"var(--amber)",medium:"#3c9bd6",low:"#2d8f89"};
  $("#risk-legend").innerHTML = Object.entries(risks).map(([risk,count]) =>
    `<div class="legend-row"><i style="background:${colors[risk]}"></i><span>${risk.toUpperCase()}</span><b>${count}</b></div>`
  ).join("");
  const max = Math.max(1, ...(o.tools || []).map(t=>t.count));
  $("#tool-bars").innerHTML = (o.tools || []).slice(0,3).map(t =>
    `<div class="tool-bar"><span>${esc(t.tool)}</span><div><i style="width:${t.count/max*100}%"></i></div><b>${t.count}</b></div>`
  ).join("");
}

function renderTimeline() {
  const events = state.events.slice(0, 5);
  const node = $("#timeline");
  if (!events.length) { node.className="timeline empty-state"; node.textContent="暂无调用记录"; return; }
  node.className="timeline";
  node.innerHTML = events.map(e => `
    <div class="timeline-item ${e.decision}" data-seq="${e.seq}">
      <time>${time(e.timestamp)}</time><div class="timeline-marker"></div>
      <div class="timeline-main"><b>${esc(e.tool)}</b><span>${esc(short(JSON.stringify(e.args), 60))}</span></div>
      <span class="badge ${e.decision}">${e.decision.toUpperCase()}</span>
    </div>`).join("");
}

function renderAlerts() {
  const alerts = state.events.filter(e => e.decision !== "allow").slice(0,3);
  const node = $("#alerts");
  if (!alerts.length) { node.className="alerts empty-state"; node.textContent="暂无风险告警"; return; }
  node.className="alerts";
  node.innerHTML = alerts.map(e => `
    <div class="alert ${e.decision}" data-seq="${e.seq}">
      <div class="alert-head"><b>${esc(e.tool)}</b><time>${time(e.timestamp)}</time></div>
      <p>${esc(e.reasons.join(" · ") || "user_confirmation_required")}</p>
      <small>${esc(e.trace_id)} · ${e.risk_level.toUpperCase()}</small>
    </div>`).join("");
}

function renderAudit() {
  const term = $("#audit-search")?.value.toLowerCase() || "";
  const decision = $("#decision-filter")?.value || "";
  const selectedTrace = $("#audit-session-filter")?.value || "";
  const events = state.events.filter(e => {
    const haystack = `${e.trace_id} ${e.task} ${e.tool} ${e.reasons.join(" ")} ${JSON.stringify(e.args)}`.toLowerCase();
    return (!term || haystack.includes(term))
      && (!decision || e.decision === decision)
      && (!selectedTrace || e.trace_id === selectedTrace);
  });
  const sessions = new Map();
  events.forEach(event => {
    if (!sessions.has(event.trace_id)) sessions.set(event.trace_id, []);
    sessions.get(event.trace_id).push(event);
  });
  $("#audit-body").innerHTML = [...sessions.entries()].map(([traceId, items]) => {
    const latest = items[0];
    const counts = {
      allow: items.filter(item => item.decision === "allow").length,
      ask: items.filter(item => item.decision === "ask").length,
      deny: items.filter(item => item.decision === "deny").length,
    };
    const rows = items.map(e => `
      <tr class="audit-event-row" data-seq="${e.seq}">
        <td>#${String(e.seq).padStart(4,"0")}</td>
        <td class="audit-date">${esc(fullDateTime(e.timestamp))}</td>
        <td><strong>${esc(e.tool)}</strong></td>
        <td><span class="badge ${e.decision}">${e.decision.toUpperCase()}</span></td>
        <td>${e.risk_level.toUpperCase()}</td>
        <td>${esc(short(e.reasons.join(", ") || "—", 42))}</td>
        <td>${Number(e.latency_ms).toFixed(2)} ms</td>
        <td class="hash">${e.hash.slice(0,10)}…</td>
      </tr>`).join("");
    return `
      <tr class="audit-session-row">
        <td colspan="8">
          <div class="audit-session-head">
            <div>
              <span>会话</span>
              <b>${esc(traceId)}</b>
              <strong>${esc(short(latest.task || "未命名任务", 100))}</strong>
            </div>
            <div class="audit-session-meta">
              <span>${items.length} 条记录</span>
              <i class="allow">${counts.allow} ALLOW</i>
              <i class="ask">${counts.ask} ASK</i>
              <i class="deny">${counts.deny} DENY</i>
              <time>${esc(fullDateTime(latest.timestamp))}</time>
            </div>
          </div>
        </td>
      </tr>
      ${rows}`;
  }).join("") || `<tr><td colspan="8" style="text-align:center;padding:40px">暂无匹配事件</td></tr>`;
}

function renderAuditSessionFilter() {
  const select = $("#audit-session-filter");
  if (!select) return;
  const selected = select.value;
  const sessions = new Map();
  state.events.forEach(event => {
    if (!sessions.has(event.trace_id)) {
      sessions.set(event.trace_id, event.task || "未命名任务");
    }
  });
  select.innerHTML = `<option value="">全部会话（${sessions.size}）</option>`
    + [...sessions.entries()].map(([traceId, task]) =>
      `<option value="${esc(traceId)}">${esc(short(task, 36))} · ${esc(traceId)}</option>`
    ).join("");
  select.value = sessions.has(selected) ? selected : "";
}

function renderPolicies() {
  $("#policy-list").innerHTML = state.policies.map((p,i) => `
    <div class="policy-row"><b>${String(i+1).padStart(2,"0")} · ${esc(p.name)}</b>
    <span>${esc(p.scope)}</span><em>${esc(p.action.toUpperCase())}</em><span>${esc(p.detail)}</span></div>`).join("");
}

function renderTools() {
  $("#tool-catalog").innerHTML = state.tools.map(tool =>
    `<span class="tool-chip" title="${esc(tool.description)}">${esc(tool.name)}</span>`
  ).join("");
  if ($("#tool-count")) $("#tool-count").textContent = `${state.tools.length} TOOLS`;
  renderTaskTools();
}

function renderTrustedWorkspaces(payload={}) {
  state.trustedWorkspaces = payload.roots || [];
  const node = $("#trusted-workspace-list");
  if (!node) return;
  $("#trusted-workspace-count").textContent = state.trustedWorkspaces.length;
  if (!state.trustedWorkspaces.length) {
    node.className = "trusted-workspace-list empty-state";
    node.textContent = "暂无额外可信工作环境";
    return;
  }
  node.className = "trusted-workspace-list";
  node.innerHTML = state.trustedWorkspaces.map(root => `
    <div class="trusted-workspace-item ${root.active ? "" : "inactive"}">
      <i></i>
      <b title="${esc(root.path)}">${esc(root.path)}</b>
      <button title="移除可信环境" aria-label="移除可信环境"
        data-remove-trusted-workspace="${esc(root.path)}">×</button>
    </div>`).join("");
}

async function chooseTrustedWorkspace() {
  const button = $("#choose-trusted-workspace");
  button.disabled = true;
  try {
    const result = await api("/api/trusted-workspaces/select", {
      method:"POST",
      body:"{}",
    });
    if (result.path) {
      $("#trusted-workspace-path").value = result.path;
      $("#trusted-workspace-path").focus();
    }
  } catch (error) {
    toast(`目录选择失败：${error.message}`);
  } finally {
    button.disabled = false;
  }
}

async function updateTrustedWorkspace(action, path) {
  const normalizedPath = String(path || "").trim();
  if (!normalizedPath) return toast("请选择或输入可信工作环境目录");
  try {
    const result = await api("/api/trusted-workspaces", {
      method:"POST",
      body:JSON.stringify({action, path:normalizedPath}),
    });
    renderTrustedWorkspaces(result);
    if (action === "add") {
      $("#trusted-workspace-path").value = "";
      toast("可信工作环境已生效");
    } else {
      toast("可信工作环境已移除");
    }
    await refresh();
  } catch (error) {
    toast(`可信工作环境更新失败：${error.message}`);
  }
}

function renderTaskTools() {
  const node = $("#task-tool-auth");
  if (!node) return;
  const selected = new Set(
    state.taskToolsInitialized
      ? [...node.querySelectorAll("input:checked")].map(input => input.value)
      : ["read_file", "write_file", "run_command", "list_directory", "search_files", "open_directory", "make_directory", "move_path", "delete_path"]
  );
  node.innerHTML = state.tools.map(tool =>
    `<label class="tool-auth-option"><input type="checkbox" value="${esc(tool.name)}" ${selected.has(tool.name) ? "checked" : ""}>${esc(tool.name)}</label>`
  ).join("");
  state.taskToolsInitialized = true;
}

function renderAgentHistory() {
  const node = $("#agent-history");
  if (!node) return;
  const term = ($("#history-search")?.value || "").trim().toLowerCase();
  const conversations = state.conversations.filter(conversation =>
    !term || `${conversation.title} ${conversation.conversation_id}`.toLowerCase().includes(term)
  );
  $("#history-count").textContent = state.conversations.length;
  if (!conversations.length) {
    node.className = "agent-history empty-state";
    node.textContent = term ? "没有匹配的旧对话" : "暂无 Agent 对话记录";
    return;
  }
  node.className = "agent-history";
  node.innerHTML = conversations.map(conversation => {
    const lastStatus = String(conversation.last_status || "recorded");
    return `<button class="history-item ${state.agentContextId === conversation.conversation_id ? "active" : ""}"
      data-history-conversation="${esc(conversation.conversation_id)}">
      <b>${esc(short(conversation.title || "未命名对话", 72))}</b>
      <span class="history-item-meta">
        <span>${esc(dateTime(conversation.updated_at || conversation.created_at))}</span>
        <span>${conversation.turns || 0} 轮</span>
        <span class="history-item-status ${esc(lastStatus)}">${esc(lastStatus.toUpperCase())}</span>
      </span>
    </button>`;
  }).join("");
}

function traceToAgentResult(trace) {
  const events = trace.events || [];
  const decisions = events.filter(event => event.phase === "policy_decision");
  const toolCallIds = new Set(
    decisions.map((event, index) => event.details?.call_id || `decision-${index}`)
  );
  const finalEvent = [...events].reverse().find(event => event.phase === "final_answer");
  const conversation = finalEvent?.details?.context || trace.metadata?.context || null;
  return {
    trace_id: trace.trace_id,
    task: trace.task || "",
    answer: finalEvent?.details?.answer || finalEvent?.summary || "",
    events,
    steps: [],
    status: finalEvent?.status || trace.last_event?.status || "recorded",
    read_only: true,
    conversation,
    transparency_notice: trace.notice,
    execution_summary: {
      provider: trace.metadata?.provider_name || trace.agent_id || "Agent",
      model: trace.metadata?.model || "历史记录",
      agent_id: trace.agent_id,
      event_count: events.length,
      tool_calls: toolCallIds.size,
      allowed: decisions.filter(event => event.status === "allow").length,
      asked: decisions.filter(event => event.status === "ask").length,
      denied: decisions.filter(event => event.status === "deny").length,
    },
  };
}

async function loadAgentTrace(traceId) {
  try {
    const trace = await api(`/api/traces/${encodeURIComponent(traceId)}`);
    state.selectedTraceId = traceId;
    state.currentAgentResult = traceToAgentResult(trace);
    renderAgentHistory();
    renderAgentExecution(state.currentAgentResult);
  } catch (error) {
    toast(`历史记录加载失败：${error.message}`);
  }
}

async function loadAgentConversation(conversationId, pendingResult=null) {
  try {
    const conversation = await api(`/api/agent/conversations/${encodeURIComponent(conversationId)}`);
    state.currentConversation = conversation;
    state.agentContextId = conversation.conversation_id || conversationId;
    state.contextMaxChars = conversation.max_chars || state.contextMaxChars;
    localStorage.setItem("agentContextId", state.agentContextId);
    localStorage.setItem("agentContextMaxChars", String(state.contextMaxChars));
    renderAgentHistory();
    renderConversationThread(conversation, pendingResult);
  } catch (error) {
    toast(`对话加载失败：${error.message}`);
  }
}

function resultFromTurn(turn, conversation) {
  const events = turn.events || [];
  const decisions = events.filter(event => event.phase === "policy_decision");
  return {
    trace_id: turn.trace_id,
    task: turn.prompt,
    answer: turn.answer,
    events,
    steps: [],
    status: turn.status || "completed",
    read_only: true,
    conversation,
    transparency_notice: conversation.notice || "",
    execution_summary: {
      provider: state.overview?.llm?.provider_name || "Agent",
      model: state.overview?.llm?.model || "history",
      agent_id: "builtin-agent",
      event_count: events.length,
      tool_calls: new Set(decisions.map((event, index) => event.details?.call_id || index)).size,
      allowed: decisions.filter(event => event.status === "allow").length,
      asked: decisions.filter(event => event.status === "ask").length,
      denied: decisions.filter(event => event.status === "deny").length,
    },
  };
}

function eventTimelineHtml(result) {
  const icons = {
    user_task:"U", task_authorization:"TA", agent_plan:"AI",
    policy_decision:"PE", tool_action:"TP", tool_result:"R",
    agent_pause:"PA", approval_decision:"OK", agent_resume:"RE",
    audit_record:"AU", agent_synthesis:"S", final_answer:"END"
  };
  const events = result.events || [];
  if (!events.length) return `<div class="empty-state">暂无链路事件</div>`;
  return events.map(event => {
    const details = JSON.stringify(event.details || {}, null, 2);
    const approval = !result.read_only && event.phase === "tool_action" && event.status === "ask" && event.details?.approval_id
      ? `<div class="approval-actions">
          <button class="approve-button" data-approval="${esc(event.details.approval_id)}" data-approve="true">批准并执行</button>
          <button class="reject-button" data-approval="${esc(event.details.approval_id)}" data-approve="false">拒绝操作</button>
        </div>`
      : "";
    return `<article class="execution-event phase-${esc(event.phase)} status-${esc(event.status)}">
      <div class="event-rail"><i>${icons[event.phase] || "·"}</i><span></span></div>
      <div class="event-body">
        <div class="event-meta">
          <span class="actor-tag actor-${esc(event.actor)}">${esc(event.label)}</span>
          <span class="event-status">${esc(String(event.status).toUpperCase())}</span>
          <time>#${String(event.seq).padStart(2,"0")}</time>
        </div>
        <h3>${esc(event.title)}</h3>
        <p>${esc(event.summary)}</p>
        ${approval}
        <details>
          <summary>查看透明详情</summary>
          <pre>${esc(details)}</pre>
        </details>
      </div>
    </article>`;
  }).join("");
}

function renderConversationThread(conversation, pendingResult=null) {
  if (!conversation?.conversation_id) {
    renderAgentExecution(pendingResult || state.currentAgentResult || {});
    return;
  }
  renderContextStatus(conversation);
  const turns = (conversation.turns_detail || []).map(turn => resultFromTurn(turn, conversation));
  if (pendingResult && !turns.some(turn => turn.trace_id === pendingResult.trace_id)) {
    turns.push(pendingResult);
  }
  const contextNotice = conversation.near_limit || conversation.truncated
    ? `<div class="context-notice ${conversation.truncated ? "truncated" : "near"}">
        <b>${conversation.truncated ? "上下文已截断" : "上下文接近上限"}</b>
        <span>${conversation.truncated ? "本对话历史已超过最大可带入量，建议新建上下文。" : "建议完成当前问题后新建上下文。"}</span>
      </div>`
    : "";
  const turnHtml = turns.map((turn, index) => {
    const summary = turn.execution_summary || {};
    const isPending = turn.status === "awaiting_approval";
    const isLatest = index === turns.length - 1;
    return `<details class="conversation-turn ${isPending ? "pending" : ""}" ${isLatest || isPending ? "open" : ""}>
      <summary class="turn-boundary start">
        <i></i>
        <b>START #${index + 1}</b>
        <strong>${esc(short(turn.task || "未命名问题", 64))}</strong>
        <span>${esc(turn.trace_id || "pending")} · ${esc(String(turn.status || "completed").toUpperCase())}</span>
        <em aria-hidden="true"></em>
      </summary>
      <div class="turn-content">
        <div class="turn-question">
          <span>USER</span>
          <p>${esc(turn.task || "")}</p>
        </div>
        <div class="execution-header compact">
          <div><span>TRACE ID</span><b>${esc(turn.trace_id || "pending")}</b></div>
          <div><span>TOOL CALLS</span><b>${summary.tool_calls || 0}</b></div>
          <div><span>DECISIONS</span><b class="decision-counts"><i>${summary.allowed || 0} allow</i><em>${summary.asked || 0} ask</em><strong>${summary.denied || 0} deny</strong></b></div>
        </div>
        <div class="execution-timeline">${eventTimelineHtml(turn)}</div>
        <div class="turn-answer">
          <span>ANSWER</span>
          <p>${esc(turn.answer || (isPending ? "等待审批后继续生成最终回答。" : "暂无回答"))}</p>
        </div>
        <div class="turn-boundary end"><i></i><b>END #${index + 1}</b><span>${esc(String(turn.status || "completed").toUpperCase())}</span></div>
      </div>
    </details>`;
  }).join("") || `<div class="output-placeholder">这个上下文还没有问题。输入任务后会在这里形成连续对话。</div>`;
  $("#agent-output").innerHTML = `
    <div class="conversation-head">
      <div><span>CONVERSATION</span><b>${esc(conversation.title || "未命名对话")}</b></div>
      <div><span>ID</span><b>${esc(conversation.conversation_id)}</b></div>
      <div><span>TURNS</span><b>${conversation.turns || turns.length}</b></div>
    </div>
    ${contextNotice}
    <div class="conversation-thread">${turnHtml}</div>`;
}

function renderProviders(current) {
  const select = $("#provider-select");
  const selected = select.value || current?.provider || "openai";
  select.innerHTML = state.providers.map(provider =>
    `<option value="${esc(provider.id)}">${esc(provider.name)}</option>`
  ).join("");
  select.value = selected;
  applyProviderPreset(false);
  if (current?.configured) {
    $("#provider-url").value = current.base_url || "";
    $("#provider-model").value = current.model || "";
    $("#provider-status").textContent = `${current.provider_name} · ${current.model}`;
    $("#provider-status").style.color = "var(--green)";
  }
}

function applyProviderPreset(overwrite=true) {
  const preset = state.providers.find(item => item.id === $("#provider-select").value);
  if (!preset) return;
  if (overwrite || !$("#provider-url").value) $("#provider-url").value = preset.base_url || "";
  if (overwrite || !$("#provider-model").value) $("#provider-model").value = preset.model || "";
  $("#provider-models").innerHTML = (preset.models || []).map(model => `<option value="${esc(model)}"></option>`).join("");
  $("#provider-note").textContent = `${preset.protocol.toUpperCase()} · ${preset.note}`;
}

function renderEvaluation(report) {
  if (!report?.available && report?.total === undefined) return;
  state.evaluation = report;
  $("#eval-accuracy").textContent = `${report.accuracy}%`;
  $("#eval-summary").textContent = `${report.passed}/${report.total} 通过 · ${report.failed} 失败`;
  $("#eval-passed").textContent = report.passed;
  $("#eval-asr").textContent = `${report.attack_success_rate ?? 0}%`;
  $("#eval-block-rate").textContent = `${report.defense_block_rate ?? report.block_rate}%`;
  $("#eval-fpr").textContent = `${report.false_positive_rate}%`;
  $("#eval-p95").textContent = report.p95_latency_ms;
  $("#eval-integrity").textContent = report.audit_integrity?.detected ? "DETECTED" : "NOT RUN";
  $("#eval-integrity").style.color = report.audit_integrity?.detected ? "var(--green)" : "var(--amber)";
  const node = $("#eval-tools");
  node.className = "eval-tools";
  node.innerHTML = Object.entries(report.by_tool || {}).map(([tool, result]) => {
    const rate = result.total ? result.passed / result.total * 100 : 0;
    return `<div class="eval-tool"><div class="eval-tool-head"><span>${esc(tool)}</span><b>${result.passed}/${result.total}</b></div>
      <div class="eval-progress"><i style="width:${rate}%"></i></div></div>`;
  }).join("");
  $("#eval-failures").textContent = report.failures?.length
    ? `失败用例：${report.failures.map(item => `${item.id} ${item.expected_action}→${item.actual_action}`).join("；")}`
    : "全部 100 条用例符合预期。";
}

function showDetail(seq) {
  const e = state.events.find(item => item.seq === Number(seq));
  if (!e) return;
  $("#detail-title").textContent = `${e.tool} · ${e.decision.toUpperCase()}`;
  $("#detail-content").innerHTML = `<div class="detail-grid">
    <div class="detail-block"><label>TRACE ID</label><div>${esc(e.trace_id)}</div></div>
    <div class="detail-block"><label>风险 / 决策</label><div>${e.risk_level.toUpperCase()} · ${e.decision.toUpperCase()}</div></div>
    <div class="detail-block full"><label>完整时间</label><div>${esc(fullDateTime(e.timestamp))}</div></div>
    <div class="detail-block full"><label>任务</label><div>${esc(e.task)}</div></div>
    <div class="detail-block full"><label>参数摘要</label><pre>${esc(JSON.stringify(e.args,null,2))}</pre></div>
    <div class="detail-block full"><label>策略命中 / 阻断原因</label><div>${esc(e.reasons.join("\n") || "无")}</div></div>
    <div class="detail-block"><label>PREV HASH</label><div>${esc(e.prev_hash)}</div></div>
    <div class="detail-block"><label>EVENT HASH</label><div>${esc(e.hash)}</div></div>
    <div class="detail-block full"><label>执行结果</label><pre>${esc(e.result_summary)}</pre></div>
  </div>`;
  $("#detail-modal").classList.add("open");
}

async function refresh() {
  try {
    const [overview, audit, policies, health, providers, tools, evaluation, traces, conversations, trusted] = await Promise.all([
      api("/api/overview"), api("/api/audit?limit=500"), api("/api/policies"), api("/api/health"),
      api("/api/llm/providers"), api("/api/tools"), api("/api/evaluation"),
      api("/api/traces?limit=100&agent_id=builtin-agent"),
      api("/api/agent/conversations?limit=100"),
      api("/api/trusted-workspaces")
    ]);
    state.overview = overview;
    state.events = audit.events;
    state.policies = policies.policies;
    state.providers = providers.providers;
    state.tools = tools.tools;
    state.traces = traces.traces || [];
    state.conversations = conversations.conversations || [];
    $("#workspace-label").textContent = health.workspace;
    $("#build-label").textContent = health.build || "unknown build";
    renderAuditSessionFilter();
    renderOverview(); renderTimeline(); renderAlerts(); renderAudit(); renderPolicies();
    renderTools(); renderProviders(providers.current); renderEvaluation(evaluation);
    renderTrustedWorkspaces(trusted);
    renderAgentHistory();
    renderContextStatus();
    if (traces.traces?.length) {
      const latestTrace = await api(`/api/traces/${encodeURIComponent(traces.traces[0].trace_id)}`);
      renderDynamicFlow(latestTrace);
    }
  } catch (error) { toast(`刷新失败：${error.message}`); }
}

function renderDynamicFlow(trace) {
  const node = $("#control-flow");
  if (!node || !trace?.events?.length) return;
  const phaseMap = [
    ["user_task", "U", "用户任务", "Prompt"],
    ["agent_plan", "AI", trace.agent_id || "Agent", "Tool Request"],
    ["policy_decision", "PE", "Policy Engine", "Allow · Ask · Deny"],
    ["tool_action", "TP", "Tool Proxy", "Controlled Action"],
    ["audit_record", "AU", "Audit Chain", "SHA-256"],
  ];
  const present = phaseMap.filter(([phase]) => trace.events.some(event => event.phase === phase));
  const policyEvents = trace.events.filter(event => event.phase === "policy_decision");
  const riskOrder = {low:0, medium:1, high:2, critical:3};
  const risk = policyEvents.reduce(
    (highest, event) => riskOrder[event.details?.risk_level] > riskOrder[highest]
      ? event.details.risk_level : highest,
    "low"
  );
  const toolCalls = trace.events.filter(event => event.phase === "agent_plan").length;
  const blocked = policyEvents.filter(event => event.status === "deny").length;
  $("#latest-trace-id").textContent = trace.trace_id || "—";
  $("#latest-task-name").textContent = trace.task || "—";
  $("#latest-agent-id").textContent = trace.agent_id || "—";
  $("#latest-risk").textContent = risk.toUpperCase();
  $("#latest-risk").style.color = risk === "critical" || risk === "high" ? "var(--red)" : risk === "medium" ? "var(--amber)" : "var(--green)";
  $("#latest-call-count").textContent = `${toolCalls} / ${blocked}`;
  node.innerHTML = present.map(([phase, icon, title, subtitle], index) => {
    const event = [...trace.events].reverse().find(item => item.phase === phase);
    const riskClass = event?.status === "deny" ? " shield" : phase === "tool_action" ? " active" : "";
    const flowNode = `<div class="flow-node${riskClass}"><span>${String(index+1).padStart(2,"0")}</span><i>${icon}</i><b>${esc(title)}</b><small>${esc(subtitle)} · ${esc(event?.status || "active")}</small></div>`;
    return index < present.length - 1 ? `${flowNode}<div class="flow-line"><em></em></div>` : flowNode;
  }).join("");
}

async function saveProvider(test=false) {
  const button = test ? $("#test-provider") : $("#save-provider");
  button.disabled = true;
  try {
    const config = {
      provider: $("#provider-select").value,
      base_url: $("#provider-url").value.trim(),
      model: $("#provider-model").value.trim(),
    };
    if ($("#provider-key").value.trim()) config.api_key = $("#provider-key").value.trim();
    const status = await api("/api/llm/config", {method:"POST", body:JSON.stringify(config)});
    $("#provider-status").textContent = `${status.provider_name} · ${status.model}`;
    $("#provider-status").style.color = "var(--green)";
    if (test) {
      const result = await api("/api/llm/test", {method:"POST", body:"{}"});
      toast(`连接成功：${result.model} · ${result.reply || "OK"}`);
    } else {
      toast("LLM 配置已在当前服务进程中生效");
    }
    $("#provider-key").value = "";
    await refresh();
  } catch (error) { toast(`LLM 配置失败：${error.message}`); }
  finally { button.disabled = false; }
}

async function generateCases() {
  const button = $("#generate-cases"); button.disabled = true;
  try {
    const result = await api("/api/evaluation/generate", {method:"POST", body:"{}"});
    toast(`已生成 ${result.generated} 条测试用例`);
  } catch (error) { toast(`生成失败：${error.message}`); }
  finally { button.disabled = false; }
}

async function runEvaluation() {
  const button = $("#run-evaluation"); button.disabled = true; button.textContent = "评测中…";
  try {
    const report = await api("/api/evaluation/run", {method:"POST", body:"{}"});
    renderEvaluation(report);
    toast(`评测完成：准确率 ${report.accuracy}%`);
  } catch (error) { toast(`评测失败：${error.message}`); }
  finally { button.disabled = false; button.textContent = "运行评测"; }
}

async function runScenario(scenario, button) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<i>…</i><div><b>正在复现</b><span>策略引擎判定中</span></div><em>RUNNING</em>`;
  try {
    const result = await api(`/api/demo/${scenario}`, {method:"POST", body:"{}"});
    renderReplay(result);
    toast(result.blocked ? `攻击已阻断 · ${result.trace_id}` : `场景执行完成 · ${result.trace_id}`);
    await refresh();
    switchView("dashboard");
  } catch (error) { toast(`复现失败：${error.message}`); }
  finally { button.disabled = false; button.innerHTML = original; }
}

function renderReplay(result) {
  const replay = result.replay || {};
  const node = $("#replay-result");
  node.className = "replay-result";
  $("#replay-result-status").textContent = String(replay.attack_result || "unknown").toUpperCase();
  $("#replay-result-status").style.color = result.blocked ? "var(--red)" : "var(--green)";
  node.innerHTML = `
    <div class="replay-item"><label>攻击类型</label><b>${esc(replay.attack_type || result.scenario)}</b></div>
    <div class="replay-item"><label>恶意载体</label><b>${esc(replay.carrier || "—")}</b></div>
    <div class="replay-item"><label>风险 / 决策</label><b>${esc(String(replay.risk_level || "low").toUpperCase())} · ${esc(String(replay.decision || "allow").toUpperCase())}</b></div>
    <div class="replay-item"><label>审计链</label><b>${replay.audit_chain_valid ? "VALID" : "UNKNOWN"}</b></div>
    <div class="replay-item wide"><label>诱导行为</label><b>${esc(replay.induced_behavior || "—")}</b></div>
    <div class="replay-item wide danger"><label>阻断原因</label><b>${esc((replay.block_reasons || []).join(" · ") || "无")}</b></div>
    <div class="replay-item wide"><label>实际调用</label><pre>${esc(JSON.stringify(replay.actual_calls || [], null, 2))}</pre></div>
    <div class="replay-item wide"><label>TRACE ID</label><b>${esc(result.trace_id)}</b></div>`;
}

async function runAgent() {
  const prompt = $("#agent-prompt").value.trim();
  if (!prompt) return toast("请输入 Agent 任务");
  const button = $("#run-agent");
  button.disabled = true; button.firstChild.textContent = "运行中 ";
  $("#agent-output").innerHTML = `<span class="output-placeholder">LLM 正在规划并调用受控工具…</span>`;
  try {
    const allowedTools = [...$("#task-tool-auth").querySelectorAll("input:checked")].map(input => input.value);
    if (!allowedTools.length) throw new Error("请至少授权一个任务工具");
    const contextMaxChars = readContextMax();
    if (state.contextIsFull && !state.forceNewContext) {
      state.agentContextId = null;
      state.forceNewContext = true;
      localStorage.removeItem("agentContextId");
      toast("当前上下文已满，本轮将自动开启新上下文");
    }
    const result = await api("/api/agent/run", {
      method:"POST",
      body:JSON.stringify({
        prompt,
        allowed_tools: allowedTools,
        conversation_id: state.agentContextId,
        context_max_chars: contextMaxChars,
        new_context: state.forceNewContext,
      })
    });
    result.task = prompt;
    result.read_only = false;
    applyConversationState(result.conversation);
    state.currentAgentResult = result;
    state.selectedTraceId = result.trace_id;
    await refresh();
    await loadAgentConversation(result.conversation?.conversation_id || state.agentContextId, result);
  } catch (error) {
    $("#agent-output").innerHTML = `<div class="answer" style="color:var(--red)">${esc(error.message)}</div>`;
  } finally { button.disabled = false; button.firstChild.textContent = "运行 Agent "; }
}

function renderAgentExecution(result) {
  const summary = result.execution_summary || {
    provider: state.overview?.llm?.provider_name || "LLM",
    model: state.overview?.llm?.model || "unknown",
    tool_calls: result.steps?.length || 0,
    allowed: (result.steps || []).filter(step => step.action === "allow").length,
    asked: (result.steps || []).filter(step => step.action === "ask").length,
    denied: (result.steps || []).filter(step => step.action === "deny").length,
  };
  if (result.read_only) {
    renderContextStatus(result.conversation);
  } else {
    applyConversationState(result.conversation);
  }
  const icons = {
    user_task:"U", task_authorization:"TA", agent_plan:"AI",
    policy_decision:"PE", tool_action:"TP", tool_result:"R",
    agent_pause:"⏸", approval_decision:"OK", agent_resume:"▶",
    audit_record:"AU", agent_synthesis:"Σ", final_answer:"✓"
  };
  const events = (result.events?.length ? result.events : [{
    seq: 1,
    phase: "final_answer",
    actor: "system",
    label: result.answer ? "兼容模式结果" : "执行异常",
    status: result.answer ? "completed" : "error",
    title: result.answer ? "后端返回了旧格式结果" : "后端未返回执行内容",
    summary: result.answer || "没有收到事件、工具步骤或最终回答。请刷新页面后重新运行；若问题持续，请检查服务日志。",
    details: {
      answer: result.answer || "",
      steps: result.steps || [],
      raw_status: result.status || "unknown",
    },
  }]);
  const eventHtml = events.map(event => {
    const details = JSON.stringify(event.details || {}, null, 2);
    const approval = !result.read_only && event.phase === "tool_action" && event.status === "ask" && event.details?.approval_id
      ? `<div class="approval-actions">
          <button class="approve-button" data-approval="${esc(event.details.approval_id)}" data-approve="true">批准并执行</button>
          <button class="reject-button" data-approval="${esc(event.details.approval_id)}" data-approve="false">拒绝操作</button>
        </div>`
      : "";
    return `<article class="execution-event phase-${esc(event.phase)} status-${esc(event.status)}">
      <div class="event-rail"><i>${icons[event.phase] || "·"}</i><span></span></div>
      <div class="event-body">
        <div class="event-meta">
          <span class="actor-tag actor-${esc(event.actor)}">${esc(event.label)}</span>
          <span class="event-status">${esc(String(event.status).toUpperCase())}</span>
          <time>#${String(event.seq).padStart(2,"0")}</time>
        </div>
        <h3>${esc(event.title)}</h3>
        <p>${esc(event.summary)}</p>
        ${approval}
        <details>
          <summary>查看透明详情</summary>
          <pre>${esc(details)}</pre>
        </details>
      </div>
    </article>`;
  }).join("");
  const awaitingApproval = result.status === "awaiting_approval"
    ? `<div class="approval-waiting">
        <b>任务已暂停，等待你的决定</b>
        <span>高风险工具尚未执行。系统不会自动批准；点击链路中的“批准并执行”或“拒绝操作”后，Agent 会继续生成最终回答。</span>
      </div>`
    : "";
  const context = result.conversation || {};
  const contextNotice = context.near_limit || context.truncated
    ? `<div class="context-notice ${context.truncated ? "truncated" : "near"}">
        <b>${context.truncated ? "上下文已截断" : "上下文接近上限"}</b>
        <span>${context.truncated ? "本次只携带了最近历史，建议新建上下文。" : "建议完成当前问题后新建上下文。"}</span>
      </div>`
    : "";
  $("#agent-output").innerHTML = `
    <div class="execution-task">
      <span>USER TASK</span>
      <b>${esc(result.task || events.find(event => event.phase === "user_task")?.summary || "未记录任务内容")}</b>
    </div>
    <div class="execution-header">
      <div><span>TRACE ID</span><b>${esc(result.trace_id)}</b></div>
      <div><span>MODEL</span><b>${esc(summary.provider || "LLM")} · ${esc(summary.model || "unknown")}</b></div>
      <div><span>TOOL CALLS</span><b>${summary.tool_calls || 0}</b></div>
      <div><span>DECISIONS</span><b class="decision-counts"><i>${summary.allowed || 0} allow</i><em>${summary.asked || 0} ask</em><strong>${summary.denied || 0} deny</strong></b></div>
    </div>
    <div class="transparency-notice"><b>透明度说明</b><span>${esc(result.transparency_notice || "展示可审计执行信息。")}</span></div>
    ${contextNotice}
    ${awaitingApproval}
    <div class="execution-timeline">${eventHtml}</div>`;
}

async function resolveApproval(approvalId, approve) {
  const buttons = [...document.querySelectorAll(`[data-approval="${approvalId}"]`)];
  buttons.forEach(button => button.disabled = true);
  try {
    const result = await api("/api/approvals/resolve", {
      method:"POST",
      body:JSON.stringify({approval_id: approvalId, approve, actor:"dashboard-user"})
    });
    if (result.execution_summary) {
      result.read_only = false;
      result.task = result.task || state.currentAgentResult?.task || "";
      state.currentAgentResult = result;
    } else {
      if (!state.currentAgentResult) state.currentAgentResult = {trace_id:result.trace_id, steps:[], answer:""};
      state.currentAgentResult.events = result.events;
      state.currentAgentResult.steps = state.currentAgentResult.steps || [];
      state.currentAgentResult.steps.push({
        tool: result.audit?.tool || "approved_tool",
        action: result.action,
        reasons: result.reasons || []
      });
      state.currentAgentResult.execution_summary = null;
    }
    state.selectedTraceId = result.trace_id;
    await refresh();
    await loadAgentConversation(result.conversation?.conversation_id || state.agentContextId, result);
    toast(
      result.status === "awaiting_approval"
        ? "当前步骤完成，Agent 正等待下一项审批"
        : approve ? "操作已批准，Agent 已继续完成任务" : "操作已拒绝，Agent 已继续处理"
    );
  } catch (error) {
    buttons.forEach(button => button.disabled = false);
    toast(`审批失败：${error.message}`);
  }
}

document.addEventListener("click", event => {
  const nav = event.target.closest(".nav"); if (nav) switchView(nav.dataset.view);
  const jump = event.target.closest("[data-jump]"); if (jump) switchView(jump.dataset.jump);
  const conversation = event.target.closest("[data-history-conversation]");
  if (conversation) loadAgentConversation(conversation.dataset.historyConversation);
  const item = event.target.closest("[data-seq]"); if (item) showDetail(item.dataset.seq);
  const demo = event.target.closest("[data-scenario]"); if (demo) runScenario(demo.dataset.scenario, demo);
  const approval = event.target.closest("[data-approval]");
  if (approval) resolveApproval(approval.dataset.approval, approval.dataset.approve === "true");
  const trustedWorkspace = event.target.closest("[data-remove-trusted-workspace]");
  if (trustedWorkspace) {
    updateTrustedWorkspace(
      "remove",
      trustedWorkspace.dataset.removeTrustedWorkspace,
    );
  }
  if (event.target.closest(".modal-close") || event.target.classList.contains("modal-backdrop")) $("#detail-modal").classList.remove("open");
});
applyTheme(document.documentElement.dataset.theme);
$("#theme-toggle").addEventListener("click", toggleTheme);
$("#refresh").addEventListener("click", refresh);
$("#run-agent").addEventListener("click", runAgent);
$("#new-agent-context").addEventListener("click", newAgentContext);
$("#choose-trusted-workspace").addEventListener("click", chooseTrustedWorkspace);
$("#add-trusted-workspace").addEventListener("click", () => {
  updateTrustedWorkspace("add", $("#trusted-workspace-path").value);
});
$("#trusted-workspace-path").addEventListener("keydown", event => {
  if (event.key === "Enter") {
    event.preventDefault();
    updateTrustedWorkspace("add", event.currentTarget.value);
  }
});
$("#context-max").addEventListener("change", () => {
  readContextMax();
  renderContextStatus();
});
$("#provider-select").addEventListener("change", () => applyProviderPreset(true));
$("#save-provider").addEventListener("click", () => saveProvider(false));
$("#test-provider").addEventListener("click", () => saveProvider(true));
$("#generate-cases").addEventListener("click", generateCases);
$("#run-evaluation").addEventListener("click", runEvaluation);
$("#audit-search").addEventListener("input", renderAudit);
$("#decision-filter").addEventListener("change", renderAudit);
$("#audit-session-filter").addEventListener("change", renderAudit);
$("#history-search").addEventListener("input", renderAgentHistory);
$("#verify-chain").addEventListener("click", async () => {
  try { const r=await api("/api/audit/verify"); toast(r.valid ? `哈希链完整，共 ${r.events} 个事件` : `哈希链在 #${r.broken_at} 处损坏`); } catch(e){toast(e.message)}
});
$("#tamper-test").addEventListener("click", async () => {
  try {
    const r=await api("/api/audit/integrity-experiment");
    toast(r.detected ? `篡改已检出，断点 #${r.tampered?.broken_at}` : `实验未通过：${r.reason || "未检测到"}`);
  } catch(e){toast(e.message)}
});
$("#reset-audit").addEventListener("click", async () => {
  if (!confirm("确认清空全部演示审计数据？")) return;
  await api("/api/audit/reset", {method:"POST", body:"{}"}); await refresh(); toast("审计数据已清空");
});
refresh();
setInterval(refresh, 10000);

