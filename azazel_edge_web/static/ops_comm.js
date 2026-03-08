const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const STATUS_INTERVAL_MS = 8000;
let lastQuestion = '';
let currentAudience = 'operator';
const SHORTCUTS = {
    operator: [
        { label: 'Gateway / Uplink', question: 'gateway と uplink を確認したい' },
        { label: 'DNS Failure', question: 'DNS が引けないとき何を確認するか' },
        { label: 'Service Status', question: 'service の異常時に何を確認するか' },
        { label: 'EPD Diff', question: 'EPD 表示差異を確認したい' },
        { label: 'AI Logs', question: 'AI ログを確認したい' },
        { label: 'Wi-Fi Intake', question: 'Wi-Fi に繋がらない利用者へどう案内するか' },
    ],
    beginner: [
        { label: 'Wi-Fi Trouble', question: 'Wi-Fi に繋がらない利用者へどう案内するか' },
        { label: 'Reconnect Guide', question: '再接続できない利用者へどう案内するか' },
        { label: 'Device Onboarding', question: '初回接続の利用者へどう案内するか' },
        { label: 'DNS Failure', question: 'DNS が引けないとき何を確認するか' },
        { label: 'Current Status', question: '利用者へ現在の状況をどう説明するか' },
    ],
};

function audienceHintText(audience) {
    if (audience === 'beginner') {
        return 'Temporary mode: simpler wording, one action at a time, and user-facing guidance first.';
    }
    return 'Professional mode: concise operator guidance and runbook-first responses.';
}

function syncAudienceUi() {
    const operatorBtn = document.getElementById('audienceOperatorBtn');
    const beginnerBtn = document.getElementById('audienceBeginnerBtn');
    const hint = document.getElementById('audienceHint');
    if (operatorBtn) operatorBtn.className = currentAudience === 'operator' ? 'btn btn-primary active' : 'btn btn-secondary';
    if (beginnerBtn) beginnerBtn.className = currentAudience === 'beginner' ? 'btn btn-primary active' : 'btn btn-secondary';
    if (hint) hint.textContent = audienceHintText(currentAudience);
    renderShortcuts();
}

function renderShortcuts() {
    const root = document.getElementById('opsShortcuts');
    if (!root) return;
    root.innerHTML = '';
    const items = SHORTCUTS[currentAudience] || [];
    for (const item of items) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.dataset.symptomQuestion = item.question;
        btn.textContent = item.label;
        root.appendChild(btn);
    }
}

function authHeaders() {
    return {
        'Content-Type': 'application/json',
        'X-Auth-Token': AUTH_TOKEN,
    };
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setBadge(id, text, ok = false) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = `badge ${ok ? 'active' : 'inactive'}`;
}

function runbookDomId(runbookId) {
    return String(runbookId || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function escapeHtml(text) {
    return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function formatReview(review) {
    if (!review || !review.final_status) return '-';
    const findings = Array.isArray(review.findings) && review.findings.length
        ? ` findings=${review.findings.join(' | ')}`
        : '';
    const changes = Array.isArray(review.required_changes) && review.required_changes.length
        ? ` changes=${review.required_changes.join(' | ')}`
        : '';
    return `${review.final_status}${findings}${changes}`;
}

async function loadStatus() {
    try {
        const res = await fetch('/api/mattermost/status', { headers: authHeaders() });
        const data = await res.json();
        if (!data.ok) {
            setBadge('mmReachability', 'ERROR', false);
            setText('mmMode', data.error || 'failed');
            return;
        }
        setBadge('mmReachability', data.reachable ? 'REACHABLE' : 'UNREACHABLE', !!data.reachable);
        setText('mmMode', data.mode || '-');
        setText('mmBaseUrl', data.base_url || '-');
        setText('mmChannelId', data.channel_id || '-');
        const triggers = Array.isArray(data.command_triggers) && data.command_triggers.length
            ? ` triggers=/${data.command_triggers.join(', /')}`
            : '';
        setText('mmCommandStatus', data.command_enabled ? `enabled (${data.command_endpoint || '/api/mattermost/command'})${triggers}` : 'disabled');
        const link = document.getElementById('mattermostLink');
        if (link) link.href = data.open_url || data.base_url || '#';
    } catch (e) {
        setBadge('mmReachability', 'ERROR', false);
        setText('mmMode', String(e));
    }
}

function renderMessages(items) {
    const list = document.getElementById('messagesList');
    const empty = document.getElementById('messagesEmpty');
    if (!list || !empty) return;
    list.innerHTML = '';
    if (!Array.isArray(items) || items.length === 0) {
        empty.style.display = 'block';
        return;
    }
    empty.style.display = 'none';
    for (const item of items) {
        const li = document.createElement('li');
        li.className = 'ops-message-item';
        const when = item.create_at ? new Date(Number(item.create_at)).toLocaleString() : '-';
        li.innerHTML = `
            <div class="ops-message-head">
                <span class="ops-message-user">${item.user_id || 'unknown-user'}</span>
                <span class="ops-message-time">${when}</span>
            </div>
            <div class="ops-message-body">${escapeHtml(item.message || '')}</div>
        `;
        list.appendChild(li);
    }
}

function renderRunbookCandidates(items) {
    const list = document.getElementById('runbookCandidates');
    const empty = document.getElementById('runbookCandidatesEmpty');
    if (!list || !empty) return;
    list.innerHTML = '';
    if (!Array.isArray(items) || items.length === 0) {
        empty.style.display = 'block';
        return;
    }
    empty.style.display = 'none';
    for (const item of items) {
        const reviewText = formatReview(item.review || null);
        const reasons = Array.isArray(item.selection_reasons) ? item.selection_reasons.join(' | ') : '-';
        const reviewStatus = item.review && item.review.final_status ? item.review.final_status : 'unknown';
        const domId = runbookDomId(item.runbook_id || '');
        const executeButton = (item.effect === 'read_only' || item.effect === 'controlled_exec')
            ? `<button class="btn btn-primary" data-runbook-action="execute" data-runbook-id="${escapeHtml(item.runbook_id || '')}">Execute</button>`
            : '';
        const schema = item.args_schema && typeof item.args_schema === 'object' ? item.args_schema : { properties: {}, required: [] };
        const properties = schema.properties && typeof schema.properties === 'object' ? schema.properties : {};
        const required = Array.isArray(schema.required) ? schema.required : [];
        const argFields = Object.entries(properties).map(([key, spec]) => {
            const fieldId = `runbookArg-${domId}-${key}`;
            const s = spec && typeof spec === 'object' ? spec : {};
            const kind = String(s.type || 'string');
            const label = `${key}${required.includes(key) ? ' *' : ''}`;
            if (Array.isArray(s.enum) && s.enum.length) {
                return `
                    <div class="ops-runbook-arg">
                        <label for="${fieldId}">${escapeHtml(label)}</label>
                        <select id="${fieldId}" data-runbook-arg="${escapeHtml(key)}">
                            <option value="">-</option>
                            ${s.enum.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('')}
                        </select>
                    </div>
                `;
            }
            if (kind === 'boolean') {
                return `
                    <div class="ops-runbook-arg">
                        <label for="${fieldId}">${escapeHtml(label)}</label>
                        <select id="${fieldId}" data-runbook-arg="${escapeHtml(key)}">
                            <option value="">-</option>
                            <option value="true">true</option>
                            <option value="false">false</option>
                        </select>
                    </div>
                `;
            }
            const inputType = kind === 'integer' ? 'number' : 'text';
            const attrs = [];
            if (kind === 'integer') {
                if (s.minimum !== undefined) attrs.push(`min="${escapeHtml(s.minimum)}"`);
                if (s.maximum !== undefined) attrs.push(`max="${escapeHtml(s.maximum)}"`);
            }
            if (s.maxLength !== undefined) attrs.push(`maxlength="${escapeHtml(s.maxLength)}"`);
            return `
                <div class="ops-runbook-arg">
                    <label for="${fieldId}">${escapeHtml(label)}</label>
                    <input id="${fieldId}" type="${inputType}" ${attrs.join(' ')} data-runbook-arg="${escapeHtml(key)}">
                </div>
            `;
        }).join('');
        const div = document.createElement('div');
        div.className = 'ops-runbook-item';
        div.innerHTML = `
            <div class="ops-runbook-head">
                <div class="ops-runbook-title">${escapeHtml(item.title || item.runbook_id || '-')}</div>
                <span class="badge ${reviewStatus === 'approved' ? 'active' : 'inactive'}">${escapeHtml(reviewStatus)}</span>
            </div>
            <div class="ops-runbook-meta">
                <span>${escapeHtml(item.runbook_id || '-')}</span>
                <span>${escapeHtml(item.domain || '-')}</span>
                <span>${escapeHtml(item.effect || '-')}</span>
                <span>score=${escapeHtml(item.score || '-')}</span>
                <span>approval=${item.requires_approval ? 'required' : 'optional'}</span>
            </div>
            <div class="ops-runbook-review">reasons=${escapeHtml(reasons)}\nreview=${escapeHtml(reviewText)}</div>
            ${argFields ? `<div class="ops-runbook-args">${argFields}</div>` : ''}
            <div class="ops-runbook-actions">
                <button class="btn btn-primary" data-runbook-action="preview" data-runbook-id="${escapeHtml(item.runbook_id || '')}">Preview</button>
                <button class="btn btn-success" data-runbook-action="approve" data-runbook-id="${escapeHtml(item.runbook_id || '')}">Approve</button>
                ${executeButton}
            </div>
            <div class="ops-runbook-output" id="runbookOutput-${domId}">-</div>
        `;
        list.appendChild(div);
    }
}

function renderCapabilities(payload) {
    const summary = document.getElementById('capabilitiesSummary');
    const list = document.getElementById('capabilitiesList');
    if (!summary || !list) return;
    list.innerHTML = '';
    if (!payload || !payload.ok) {
        summary.textContent = 'Failed to load capabilities';
        return;
    }
    const routed = Array.isArray(payload.manual_router_categories) ? payload.manual_router_categories.join(', ') : '-';
    const triggers = Array.isArray(payload.mattermost_triggers) ? payload.mattermost_triggers.map((x) => `/${x}`).join(', ') : '-';
    summary.textContent = `Audience=${currentAudience} / Routed categories=${routed} / Mattermost=${triggers}`;
    const items = Array.isArray(payload.capabilities) ? payload.capabilities : [];
    for (const item of items) {
        const node = document.createElement('div');
        node.className = 'ops-capability-item';
        node.innerHTML = `
            <div class="ops-capability-title">${escapeHtml(item.title || '-')}</div>
            <div class="ops-capability-detail">${escapeHtml(item.detail || '-')}</div>
        `;
        list.appendChild(node);
    }
}

async function loadCapabilities() {
    try {
        const res = await fetch('/api/ai/capabilities', { headers: authHeaders() });
        const data = await res.json();
        renderCapabilities(data);
    } catch (_e) {
        renderCapabilities(null);
    }
}

async function loadRunbookCandidates(question) {
    const q = String(question || '').trim();
    lastQuestion = q;
    if (!q) {
        renderRunbookCandidates([]);
        return;
    }
    const res = await fetch('/api/runbooks/propose', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ question: q, audience: currentAudience, context: { page: 'ops-comm', audience: currentAudience }, max_items: 3 }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
        renderRunbookCandidates([]);
        return;
    }
    renderRunbookCandidates(data.items || []);
}

async function runRunbookAction(runbookId, action) {
    const senderInput = document.getElementById('senderInput');
    const domId = runbookDomId(runbookId);
    const outputId = `runbookOutput-${domId}`;
    const output = document.getElementById(outputId);
    const actor = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const args = {};
    document.querySelectorAll(`[id^="runbookArg-${domId}-"]`).forEach((node) => {
        if (!(node instanceof HTMLInputElement) && !(node instanceof HTMLSelectElement)) return;
        const key = node.dataset.runbookArg;
        if (!key) return;
        const value = node.value;
        if (value === '') return;
        args[key] = value;
    });
    try {
        const res = await fetch('/api/runbooks/act', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
                runbook_id: runbookId,
                action,
                approved: action !== 'preview',
                args,
                actor,
                question: lastQuestion,
                audience: currentAudience,
                note: 'ops-comm',
            }),
        });
        const data = await res.json();
        if (!output) return;
        if (!res.ok || !data.ok) {
            output.textContent = `Failed: ${data.error || 'unknown error'}`;
            return;
        }
        if (action === 'preview') {
            const command = data.command ? `${data.command.exec} ${(data.command.argv || []).join(' ')}` : '(guidance only)';
            output.textContent = `Preview OK\ncommand=${command}\nargs=${JSON.stringify(args)}\nsteps=${(data.steps || []).join(' | ')}\nuser=${data.user_message || '-'}`;
            return;
        }
        if (action === 'approve') {
            output.textContent = `Approved\nargs=${JSON.stringify(args)}\nsteps=${(data.steps || []).join(' | ')}\nuser=${data.user_message || data.user_message_template || '-'}`;
            return;
        }
        output.textContent = `Executed\nargs=${JSON.stringify(args)}\nuser=${data.user_message || '-'}\nexit=${data.exit_code ?? '-'}\nstdout=${data.stdout || '-'}\nstderr=${data.stderr || '-'}`;
    } catch (e) {
        if (output) output.textContent = `Failed: ${e}`;
    }
}

async function loadMessages() {
    try {
        const res = await fetch('/api/mattermost/messages?limit=40', { headers: authHeaders() });
        const data = await res.json();
        if (!data.ok) {
            renderMessages([]);
            return;
        }
        renderMessages(data.items || []);
    } catch (_e) {
        renderMessages([]);
    }
}

async function sendMessage() {
    const senderInput = document.getElementById('senderInput');
    const messageInput = document.getElementById('messageInput');
    const result = document.getElementById('sendResult');
    const aiResult = document.getElementById('aiResult');
    const userGuidanceResult = document.getElementById('userGuidanceResult');
    const runbookResult = document.getElementById('runbookResult');
    const runbookReviewResult = document.getElementById('runbookReviewResult');
    const sender = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const message = messageInput ? messageInput.value.trim() : '';
        if (!message) {
            if (result) result.textContent = 'Message is empty';
            if (aiResult) aiResult.textContent = 'M.I.O.: -';
            if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
            if (runbookResult) runbookResult.textContent = 'Runbook: -';
            if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
            return;
        }
    try {
        const res = await fetch('/api/mattermost/message', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ sender, message, ask_ai: false }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
            if (result) result.textContent = `Sent (${data.result.mode})`;
            if (aiResult) aiResult.textContent = 'M.I.O.: -';
            if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
            if (runbookResult) runbookResult.textContent = 'Runbook: -';
            if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
            if (messageInput) messageInput.value = '';
            await loadMessages();
            return;
        }
        if (result) result.textContent = `Failed: ${data.error || 'unknown error'}`;
        if (aiResult) aiResult.textContent = 'M.I.O.: -';
        if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
        if (runbookResult) runbookResult.textContent = 'Runbook: -';
        if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
    } catch (e) {
        if (result) result.textContent = `Failed: ${e}`;
        if (aiResult) aiResult.textContent = 'M.I.O.: -';
        if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
        if (runbookResult) runbookResult.textContent = 'Runbook: -';
        if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
    }
}

async function askAi() {
    const senderInput = document.getElementById('senderInput');
    const messageInput = document.getElementById('messageInput');
    const result = document.getElementById('sendResult');
    const aiResult = document.getElementById('aiResult');
    const userGuidanceResult = document.getElementById('userGuidanceResult');
    const runbookResult = document.getElementById('runbookResult');
    const runbookReviewResult = document.getElementById('runbookReviewResult');
    const sender = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const question = messageInput ? messageInput.value.trim() : '';
    if (!question) {
        if (result) result.textContent = 'Question is empty';
        if (aiResult) aiResult.textContent = 'M.I.O.: -';
        if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
        if (runbookResult) runbookResult.textContent = 'Runbook: -';
        if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
        return;
    }
    try {
        const res = await fetch('/api/ai/ask', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ question, sender, source: 'ops-comm', context: { page: 'ops-comm', audience: currentAudience } }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
            if (result) result.textContent = `AI completed (${data.model || '-'})`;
            if (aiResult) aiResult.textContent = `M.I.O.: ${data.answer || '-'}${data.runbook_id ? ` [runbook=${data.runbook_id}]` : ''}`;
            if (userGuidanceResult) {
                userGuidanceResult.textContent = data.user_message
                    ? `User Guidance: ${data.user_message}`
                    : 'User Guidance: -';
            }
            if (runbookResult) {
                runbookResult.textContent = data.runbook_id
                    ? `Runbook: ${data.runbook_id}`
                    : 'Runbook: no suggestion';
            }
            if (runbookReviewResult) {
                const review = data.runbook_review || null;
                if (review && review.final_status) {
                    const changes = Array.isArray(review.required_changes) && review.required_changes.length
                        ? ` / changes=${review.required_changes.join(' | ')}`
                        : '';
                    runbookReviewResult.textContent = `Review: ${review.final_status}${changes}`;
                } else {
                    runbookReviewResult.textContent = 'Review: -';
                }
            }
            await loadRunbookCandidates(question);
            return;
        }
        if (result) result.textContent = `AI failed: ${data.error || data.reason || 'unknown error'}`;
        if (aiResult) aiResult.textContent = 'M.I.O.: -';
        if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
        if (runbookResult) runbookResult.textContent = 'Runbook: -';
        if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
        renderRunbookCandidates([]);
    } catch (e) {
        if (result) result.textContent = `AI failed: ${e}`;
        if (aiResult) aiResult.textContent = 'M.I.O.: -';
        if (userGuidanceResult) userGuidanceResult.textContent = 'User Guidance: -';
        if (runbookResult) runbookResult.textContent = 'Runbook: -';
        if (runbookReviewResult) runbookReviewResult.textContent = 'Review: -';
        renderRunbookCandidates([]);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refreshBtn');
    const sendBtn = document.getElementById('sendBtn');
    const askAiBtn = document.getElementById('askAiBtn');
    const messageInput = document.getElementById('messageInput');
    const operatorBtn = document.getElementById('audienceOperatorBtn');
    const beginnerBtn = document.getElementById('audienceBeginnerBtn');
    syncAudienceUi();
    if (refreshBtn) refreshBtn.addEventListener('click', async () => {
        await loadStatus();
        await loadMessages();
        await loadCapabilities();
        if (lastQuestion) await loadRunbookCandidates(lastQuestion);
    });
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    if (askAiBtn) askAiBtn.addEventListener('click', askAi);
    if (operatorBtn) operatorBtn.addEventListener('click', () => {
        currentAudience = 'operator';
        syncAudienceUi();
    });
    if (beginnerBtn) beginnerBtn.addEventListener('click', () => {
        currentAudience = 'beginner';
        syncAudienceUi();
    });
    document.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const action = target.dataset.runbookAction;
        const runbookId = target.dataset.runbookId;
        if (!action || !runbookId) return;
        await runRunbookAction(runbookId, action);
    });
    document.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const symptomQuestion = target.dataset.symptomQuestion;
        if (!symptomQuestion) return;
        if (messageInput && 'value' in messageInput) {
            messageInput.value = symptomQuestion;
        }
        await askAi();
    });
    loadStatus();
    loadMessages();
    loadCapabilities();
    setInterval(() => {
        loadStatus();
        loadMessages();
    }, STATUS_INTERVAL_MS);
});
