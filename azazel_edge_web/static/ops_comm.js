const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const LANG_KEY = 'azazel_lang';
const CURRENT_LANG = window.AZAZEL_LANG || localStorage.getItem(LANG_KEY) || 'ja';
const I18N = window.AZAZEL_I18N || {};
const STATUS_INTERVAL_MS = 8000;
let lastQuestion = '';
let currentAudience = 'operator';
let demoScenarios = [];
let triageIntentItems = [];
let triageSession = null;

function tr(key, fallback, vars = null) {
    const base = I18N[key] || fallback || key;
    if (!vars || typeof base !== 'string') return base;
    return base.replace(/\{([a-zA-Z0-9_]+)\}/g, (_m, name) => {
        return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : `{${name}}`;
    });
}

function switchLanguage(lang) {
    const next = lang === 'en' ? 'en' : 'ja';
    localStorage.setItem(LANG_KEY, next);
    const url = new URL(window.location.href);
    url.searchParams.set('lang', next);
    window.location.assign(url.toString());
}

function syncLanguageUi() {
    const jaBtn = document.getElementById('langJaBtn');
    const enBtn = document.getElementById('langEnBtn');
    if (jaBtn) {
        jaBtn.classList.toggle('active', CURRENT_LANG === 'ja');
        jaBtn.classList.toggle('lang-active-ja', CURRENT_LANG === 'ja');
        jaBtn.classList.remove('lang-active-en');
    }
    if (enBtn) {
        enBtn.classList.toggle('active', CURRENT_LANG === 'en');
        enBtn.classList.toggle('lang-active-en', CURRENT_LANG === 'en');
        enBtn.classList.remove('lang-active-ja');
    }
}
const SHORTCUTS = {
    operator: [
        {
            label: tr('ops.shortcut_gateway_uplink', 'Gateway / Uplink'),
            question: tr('dashboard.question_gateway_uplink', 'What should I verify when the gateway or uplink looks unhealthy?'),
        },
        {
            label: tr('ops.shortcut_dns_failure', 'DNS Failure'),
            question: tr('dashboard.question_dns_failure', 'What should I verify when DNS lookup fails?'),
        },
        {
            label: tr('ops.shortcut_service_status', 'Service Status'),
            question: tr('dashboard.question_service_status', 'What should I verify when a service appears unhealthy?'),
        },
        {
            label: tr('ops.shortcut_epd_diff', 'EPD Diff'),
            question: tr('ops.question_epd_diff', 'I want to inspect the EPD display difference'),
        },
        {
            label: tr('ops.shortcut_ai_logs', 'AI Logs'),
            question: tr('ops.question_ai_logs', 'I want to review recent AI logs'),
        },
        {
            label: tr('ops.shortcut_wifi_intake', 'Wi-Fi Intake'),
            question: tr('dashboard.question_wifi_trouble', 'How should I guide a user who cannot connect to Wi-Fi?'),
        },
    ],
    beginner: [
        {
            label: tr('ops.shortcut_wifi_trouble', 'Wi-Fi Trouble'),
            question: tr('dashboard.question_wifi_trouble', 'How should I guide a user who cannot connect to Wi-Fi?'),
        },
        {
            label: tr('ops.shortcut_reconnect_guide', 'Reconnect Guide'),
            question: tr('dashboard.question_reconnect', 'How should I guide a user who cannot reconnect?'),
        },
        {
            label: tr('ops.shortcut_device_onboarding', 'Device Onboarding'),
            question: tr('dashboard.question_onboarding', 'How should I guide a first-time onboarding user?'),
        },
        {
            label: tr('ops.shortcut_dns_failure', 'DNS Failure'),
            question: tr('dashboard.question_dns_failure', 'What should I verify when DNS lookup fails?'),
        },
        {
            label: tr('ops.shortcut_current_status', 'Current Status'),
            question: tr('ops.question_current_status', 'How should I explain the current situation to the user?'),
        },
    ],
};

function audienceHintText(audience) {
    if (audience === 'beginner') {
        return tr('ops.temporary_hint', 'Temporary mode: simpler wording, one action at a time, and user-facing guidance first.');
    }
    return tr('ops.professional_hint', 'Professional mode: concise operator guidance and runbook-first responses.');
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

function queryParams() {
    return new URLSearchParams(window.location.search);
}

function triageAudienceMode() {
    return currentAudience === 'beginner' ? 'temporary' : 'professional';
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
        'X-AZAZEL-LANG': CURRENT_LANG,
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

function resetAiPanels() {
    setText('aiResult', 'M.I.O.: -');
    setText('userGuidanceResult', `${tr('ops.user_guidance', 'User Guidance')}: -`);
    setText('runbookResult', `${tr('ops.runbook', 'Runbook')}: -`);
    setText('runbookReviewResult', `${tr('ops.review', 'Review')}: -`);
    setText('rationaleResult', `${tr('ops.rationale', 'Rationale')}: -`);
    setText('handoffResult', `${tr('ops.handoff', 'Handoff')}: -`);
}

function formatDemoSummary(result) {
    const noc = result?.noc?.summary?.status || '-';
    const soc = result?.soc?.summary?.status || '-';
    const action = result?.arbiter?.action || '-';
    const reason = result?.arbiter?.reason || '-';
    return `${tr('ops.scenario', 'Scenario')}=${result?.scenario_id || '-'} | NOC=${noc} | SOC=${soc} | action=${action} | reason=${reason}`;
}

function buildDemoQuestion(result) {
    const scenarioId = result?.scenario_id || 'demo';
    const noc = result?.noc?.summary?.status || '-';
    const soc = result?.soc?.summary?.status || '-';
    const action = result?.arbiter?.action || '-';
    const reason = result?.arbiter?.reason || '-';
    return tr(
        'ops.demo_question_template',
        'Explain why demo {scenario} resulted in NOC={noc} SOC={soc} action={action} reason={reason}, and list the next checks.',
        { scenario: scenarioId, noc, soc, action, reason },
    );
}

function renderAiPanels(data) {
    const surfaceMessages = data.surface_messages && typeof data.surface_messages === 'object' ? data.surface_messages : {};
    const opsSurface = surfaceMessages['ops-comm'] || data.surface_message || '';
    if (opsSurface) {
        setText('aiResult', opsSurface);
    } else {
        setText('aiResult', `M.I.O.: ${data.answer || '-'}${data.runbook_id ? ` [runbook=${data.runbook_id}]` : ''}`);
    }
    setText('userGuidanceResult', data.user_message ? `${tr('ops.user_guidance', 'User Guidance')}: ${data.user_message}` : `${tr('ops.user_guidance', 'User Guidance')}: -`);
    setText('runbookResult', data.runbook_id ? `${tr('ops.runbook', 'Runbook')}: ${data.runbook_id}` : `${tr('ops.runbook', 'Runbook')}: ${tr('api.no_suggestion', 'no suggestion')}`);
    const review = data.runbook_review || null;
    if (review && review.final_status) {
        const changes = Array.isArray(review.required_changes) && review.required_changes.length
            ? ` / changes=${review.required_changes.join(' | ')}`
            : '';
        setText('runbookReviewResult', `${tr('ops.review', 'Review')}: ${review.final_status}${changes}`);
    } else {
        setText('runbookReviewResult', `${tr('ops.review', 'Review')}: -`);
    }
    const rationale = Array.isArray(data.rationale) && data.rationale.length
        ? data.rationale.join(' | ')
        : '-';
    setText('rationaleResult', `${tr('ops.rationale', 'Rationale')}: ${rationale}`);
    const handoff = data.handoff && typeof data.handoff === 'object' ? data.handoff : {};
    const parts = [];
    if (handoff.ops_comm) parts.push(`Ops Comm ${handoff.ops_comm}`);
    if (handoff.mattermost) parts.push(`Mattermost ${handoff.mattermost}`);
    setText('handoffResult', `${tr('ops.handoff', 'Handoff')}: ${parts.length ? parts.join(' / ') : '-'}`);
}

async function loadStatus() {
    try {
        const res = await fetch('/api/mattermost/status', { headers: authHeaders() });
        const data = await res.json();
        if (!data.ok) {
            setBadge('mmReachability', tr('ops.error', 'ERROR'), false);
            setText('mmMode', data.error || tr('ops.failed', 'Failed: {error}', { error: tr('ops.unknown_error', 'unknown error') }));
            return;
        }
        setBadge('mmReachability', data.reachable ? tr('ops.reachable', 'REACHABLE') : tr('ops.unreachable', 'UNREACHABLE'), !!data.reachable);
        setText('mmMode', data.mode || '-');
        setText('mmBaseUrl', data.base_url || '-');
        setText('mmChannelId', data.channel_id || '-');
        const triggers = Array.isArray(data.command_triggers) && data.command_triggers.length
            ? ` triggers=/${data.command_triggers.join(', /')}`
            : '';
        setText(
            'mmCommandStatus',
            data.command_enabled
                ? tr('ops.command_enabled', 'enabled ({endpoint}){triggers}', { endpoint: data.command_endpoint || '/api/mattermost/command', triggers })
                : tr('ops.command_disabled', 'disabled')
        );
        const link = document.getElementById('mattermostLink');
        if (link) link.href = data.open_url || data.base_url || '#';
    } catch (e) {
        setBadge('mmReachability', tr('ops.error', 'ERROR'), false);
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

function renderTriageAudit(items) {
    const list = document.getElementById('triageAuditList');
    const empty = document.getElementById('triageAuditEmpty');
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
        li.innerHTML = `
            <div class="ops-message-head">
                <span class="ops-message-user">${escapeHtml(item.title || item.kind || 'triage')}</span>
                <span class="ops-message-time">${escapeHtml(item.ts_iso || '-')}</span>
            </div>
            <div class="ops-message-body">${escapeHtml(item.detail || '-')}</div>
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
            ? `<button class="btn btn-primary" data-runbook-action="execute" data-runbook-id="${escapeHtml(item.runbook_id || '')}">${tr('ops.execute', 'Execute')}</button>`
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
                <span>${item.requires_approval ? tr('ops.approval_required', 'approval=required') : tr('ops.approval_optional', 'approval=optional')}</span>
            </div>
            <div class="ops-runbook-review">${tr('ops.reasons_label', 'reasons')}=${escapeHtml(reasons)}\n${tr('ops.review_label', 'review')}=${escapeHtml(reviewText)}</div>
            ${argFields ? `<div class="ops-runbook-args">${argFields}</div>` : ''}
            <div class="ops-runbook-actions">
                <button class="btn btn-primary" data-runbook-action="preview" data-runbook-id="${escapeHtml(item.runbook_id || '')}">${tr('ops.preview', 'Preview')}</button>
                <button class="btn btn-success" data-runbook-action="approve" data-runbook-id="${escapeHtml(item.runbook_id || '')}">${tr('ops.approve', 'Approve')}</button>
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
        summary.textContent = tr('ops.capabilities_failed', 'Failed to load capabilities');
        return;
    }
    const routed = Array.isArray(payload.manual_router_categories) ? payload.manual_router_categories.join(', ') : '-';
    const triggers = Array.isArray(payload.mattermost_triggers) ? payload.mattermost_triggers.map((x) => `/${x}`).join(', ') : '-';
    summary.textContent = tr('ops.capabilities_summary', 'Audience={audience} / Routed categories={routed} / Mattermost={triggers}', {
        audience: currentAudience,
        routed,
        triggers,
    });
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

function resetTriageUi() {
    triageSession = null;
    setText('triageSessionMeta', tr('ops.triage_no_session', 'No active triage session'));
    setText('triagePreface', tr('ops.triage_preface_idle', 'M.I.O. will add a short preface before the next deterministic question.'));
    setText('triageQuestion', '-');
    setText('triageDiagnostic', '-');
    setText('triageMioSummary', tr('ops.triage_summary_idle', 'No triage summary yet.'));
    setText('triageHandoff', tr('ops.triage_handoff_idle', 'No handoff is required.'));
    const choices = document.getElementById('triageChoices');
    if (choices) choices.innerHTML = '';
    const runbooks = document.getElementById('triageRunbooks');
    if (runbooks) runbooks.innerHTML = '';
    const input = document.getElementById('triageTextAnswer');
    if (input) input.value = '';
    const wrap = document.getElementById('triageTextAnswerWrap');
    if (wrap) wrap.style.display = 'none';
}

function buildTriageHandoffMessage() {
    if (!triageSession || !triageSession.diagnostic_state) return '';
    const diagnosticText = document.getElementById('triageDiagnostic')?.textContent || triageSession.diagnostic_state;
    const summaryText = document.getElementById('triageMioSummary')?.textContent || '-';
    const handoffText = document.getElementById('triageHandoff')?.textContent || '-';
    const runbookNodes = Array.from(document.querySelectorAll('#triageRunbooks .ops-triage-runbook-item strong'));
    const runbooks = runbookNodes.map((node) => node.textContent || '-').filter(Boolean);
    return [
        '[Triage Handoff]',
        `audience=${triageAudienceMode()}`,
        `intent=${triageSession.selected_intent || '-'}`,
        `diagnostic=${diagnosticText}`,
        `summary=${summaryText}`,
        `handoff=${handoffText}`,
        `runbooks=${runbooks.length ? runbooks.join(' | ') : '-'}`,
    ].join('\n');
}

function renderTriageIntents(items) {
    const root = document.getElementById('triageIntentButtons');
    if (!root) return;
    root.innerHTML = '';
    triageIntentItems = Array.isArray(items) ? items : [];
    for (const item of triageIntentItems) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-secondary';
        btn.dataset.triageIntent = item.intent_id;
        btn.textContent = item.label || item.intent_id;
        root.appendChild(btn);
    }
}

function renderTriageCandidates(items) {
    const root = document.getElementById('triageCandidates');
    const empty = document.getElementById('triageCandidatesEmpty');
    if (!root || !empty) return;
    root.innerHTML = '';
    const candidates = Array.isArray(items) ? items : [];
    if (!candidates.length) {
        empty.style.display = 'block';
        empty.textContent = tr('ops.triage_no_candidates', 'No triage candidates yet');
        return;
    }
    empty.style.display = 'none';
    for (const item of candidates) {
        const node = document.createElement('div');
        node.className = 'ops-triage-candidate';
        node.innerHTML = `
            <div class="ops-triage-candidate-copy">
                <strong>${escapeHtml(item.label || item.intent_id || '-')}</strong>
                <div class="ops-triage-candidate-meta">${tr('ops.triage_confidence', 'confidence')}=${Math.round((item.confidence || 0) * 100)}% / ${escapeHtml(item.source || 'classifier')}</div>
            </div>
            <button class="btn btn-secondary" data-triage-intent="${escapeHtml(item.intent_id || '')}">${tr('ops.triage_start', 'Start')}</button>
        `;
        root.appendChild(node);
    }
}

function renderTriageRunbooks(items) {
    const root = document.getElementById('triageRunbooks');
    if (!root) return;
    root.innerHTML = '';
    const runbooks = Array.isArray(items) ? items : [];
    for (const item of runbooks) {
        const node = document.createElement('div');
        node.className = 'ops-triage-runbook-item';
        const review = item.review && item.review.final_status ? item.review.final_status : 'unknown';
        node.innerHTML = `
            <div class="ops-triage-runbook-head">
                <strong>${escapeHtml(item.title || item.runbook_id || '-')}</strong>
                <span class="badge ${review === 'approved' ? 'active' : 'inactive'}">${escapeHtml(review)}</span>
            </div>
            <div class="ops-triage-runbook-detail">${escapeHtml(item.runbook_id || '-')} | ${escapeHtml(item.effect || '-')}</div>
            <div class="ops-triage-runbook-detail">${escapeHtml(item.user_message_template || '-')}</div>
        `;
        root.appendChild(node);
    }
}

function renderTriageProgress(payload) {
    triageSession = payload && payload.session ? payload.session : null;
    const session = triageSession || {};
    const nextStep = payload && payload.next_step ? payload.next_step : null;
    const diagnostic = payload && payload.diagnostic_state ? payload.diagnostic_state : null;
    const mio = payload && payload.mio ? payload.mio : {};
    setText(
        'triageSessionMeta',
        triageSession
            ? `${payload.flow_label || payload.flow_id || triageSession.selected_intent || '-'} | state=${triageSession.current_state || triageSession.diagnostic_state || '-'}`
            : tr('ops.triage_no_session', 'No active triage session')
    );
    setText('triagePreface', mio.preface || tr('ops.triage_preface_idle', 'M.I.O. will add a short preface before the next deterministic question.'));
    setText('triageMioSummary', mio.summary || tr('ops.triage_summary_idle', 'No triage summary yet.'));
    setText('triageHandoff', mio.handoff || tr('ops.triage_handoff_idle', 'No handoff is required.'));
    const choicesRoot = document.getElementById('triageChoices');
    if (choicesRoot) choicesRoot.innerHTML = '';
    const textWrap = document.getElementById('triageTextAnswerWrap');
    if (textWrap) textWrap.style.display = 'none';
    if (nextStep) {
        setText('triageQuestion', nextStep.question || '-');
        setText('triageDiagnostic', tr('ops.triage_in_progress', 'Triage in progress'));
        if (nextStep.answer_type === 'text') {
            if (textWrap) textWrap.style.display = 'flex';
            const textInput = document.getElementById('triageTextAnswer');
            if (textInput) textInput.focus();
        } else if (choicesRoot && Array.isArray(nextStep.choices)) {
            for (const choice of nextStep.choices) {
                const btn = document.createElement('button');
                btn.className = 'btn btn-primary';
                btn.dataset.triageAnswer = String(choice.value || '');
                const labels = choice.label_i18n || {};
                btn.textContent = labels[CURRENT_LANG] || labels.en || choice.value || '-';
                choicesRoot.appendChild(btn);
            }
        }
    } else {
        setText('triageQuestion', '-');
    }
    if (diagnostic) {
        const summary = diagnostic.summary_i18n || {};
        const localizedSummary = summary[CURRENT_LANG] || summary.en || diagnostic.state_id;
        setText('triageDiagnostic', `${tr('ops.triage_diagnostic', 'Diagnostic State')}: ${localizedSummary}`);
        renderTriageRunbooks(payload.runbooks || []);
        renderRunbookCandidates(payload.runbooks || []);
    } else {
        renderTriageRunbooks([]);
    }
}

async function loadTriageIntents() {
    try {
        const res = await fetch('/api/triage/intents', { headers: authHeaders() });
        const data = await res.json();
        if (!res.ok || !data.ok) return;
        renderTriageIntents(data.items || []);
        const intro = document.getElementById('triageIntro');
        if (intro && Array.isArray(data.items) && data.items.length) {
            intro.textContent = tr('ops.triage_intro_ready', 'Choose a symptom family first, or classify the current issue text to narrow it down.');
        }
    } catch (_e) {
        renderTriageIntents([]);
    }
}

async function classifyTriageText() {
    const input = document.getElementById('triageInput');
    const text = input ? input.value.trim() : '';
    if (!text) {
        setText('triageSessionMeta', tr('ops.triage_text_required', 'Enter a symptom before classification.'));
        return;
    }
    try {
        const res = await fetch('/api/triage/classify', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ text }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') }));
            return;
        }
        renderTriageCandidates(data.items || []);
        setText('triageSessionMeta', tr('ops.triage_candidates_ready', 'Select one of the triage candidates.'));
    } catch (e) {
        setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: String(e) }));
    }
}

async function startTriage(intentId) {
    if (!intentId) return;
    try {
        const res = await fetch('/api/triage/start', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ intent_id: intentId, audience: triageAudienceMode() }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') }));
            return;
        }
        renderTriageProgress(data);
    } catch (e) {
        setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: String(e) }));
    }
}

async function answerTriage(answerValue) {
    if (!triageSession || !triageSession.session_id) return;
    try {
        const res = await fetch('/api/triage/answer', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ session_id: triageSession.session_id, answer: answerValue }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') }));
            return;
        }
        renderTriageProgress(data);
    } catch (e) {
        setText('triageSessionMeta', tr('ops.failed', 'Failed: {error}', { error: String(e) }));
    }
}

async function sendTriageHandoff() {
    const payloadMessage = buildTriageHandoffMessage();
    if (!payloadMessage) {
        setText('triageSessionMeta', tr('ops.triage_handoff_missing', 'No diagnostic handoff is ready yet.'));
        return;
    }
    const senderInput = document.getElementById('senderInput');
    const sender = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const result = document.getElementById('sendResult');
    try {
        const res = await fetch('/api/mattermost/message', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({
                sender,
                message: payloadMessage,
                lang: CURRENT_LANG,
                ask_ai: false,
                send_to_mattermost: true,
            }),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            if (result) result.textContent = tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') });
            return;
        }
        if (result) result.textContent = tr('ops.triage_handoff_sent', 'Sent triage handoff to Mattermost ({mode})', { mode: data.result?.mode || '-' });
    } catch (e) {
        if (result) result.textContent = tr('ops.failed', 'Failed: {error}', { error: String(e) });
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

function updateDemoScenarioDescription() {
    const select = document.getElementById('demoScenarioSelect');
    const selected = String(select?.value || '').trim();
    const item = demoScenarios.find((row) => row.scenario_id === selected) || demoScenarios[0];
    if (!item) {
        setText('demoScenarioDescription', tr('ops.no_scenario_available', 'No scenario available.'));
        return;
    }
    if (select && !select.value) select.value = item.scenario_id;
    setText('demoScenarioDescription', `${item.description || '-'} | events=${item.event_count ?? 0}`);
}

async function loadDemoScenarios() {
    const select = document.getElementById('demoScenarioSelect');
    if (!select) return;
    try {
        const res = await fetch('/api/demo/scenarios', { headers: authHeaders() });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('demoScenarioDescription', tr('ops.demo_load_failed', 'Failed to load scenarios: {error}', { error: data.error || 'unknown error' }));
            return;
        }
        demoScenarios = Array.isArray(data.items) ? data.items : [];
        if (!demoScenarios.length) {
            select.innerHTML = '<option value=\"\">No scenario</option>';
            setText('demoScenarioDescription', tr('ops.no_scenario_available', 'No scenario available.'));
            return;
        }
        select.innerHTML = demoScenarios
            .map((item) => `<option value="${escapeHtml(item.scenario_id)}">${escapeHtml(item.scenario_id)}</option>`)
            .join('');
        updateDemoScenarioDescription();
    } catch (e) {
        setText('demoScenarioDescription', tr('ops.demo_load_failed', 'Failed to load scenarios: {error}', { error: String(e) }));
    }
}

async function runDemoScenario() {
    const select = document.getElementById('demoScenarioSelect');
    const scenarioId = String(select?.value || '').trim();
    if (!scenarioId) {
        setText('demoResult', tr('ops.scenario_required', 'Scenario is required.'));
        return;
    }
    setText('demoResult', tr('ops.demo_running', 'Running demo scenario...'));
    setText('demoOperatorSummary', tr('ops.demo_preparing', 'Operator wording: preparing replay...'));
    setText('demoNextChecks', tr('ops.demo_waiting', 'Next checks: waiting for result...'));
    try {
        const res = await fetch(`/api/demo/run/${encodeURIComponent(scenarioId)}`, {
            method: 'POST',
            headers: authHeaders(),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('demoResult', tr('ops.demo_failed', 'Demo failed: {error}', { error: data.error || 'unknown error' }));
            return;
        }
        const result = data.result || {};
        setText('demoResult', formatDemoSummary(result));
        setText(
            'demoOperatorSummary',
            tr('ops.operator_wording_line', 'Operator wording: {value}', { value: result.explanation?.operator_wording || '-' }),
        );
        setText(
            'demoNextChecks',
            tr('ops.next_checks_line', 'Next checks: {value}', { value: (result.explanation?.next_checks || []).join(' | ') || '-' }),
        );
        const question = buildDemoQuestion(result);
        const messageInput = document.getElementById('messageInput');
        if (messageInput) messageInput.value = question;
        await askAi(question);
    } catch (e) {
        setText('demoResult', tr('ops.demo_failed', 'Demo failed: {error}', { error: String(e) }));
    }
}

async function clearDemoOverlay() {
    try {
        const res = await fetch('/api/demo/overlay/clear', {
            method: 'POST',
            headers: authHeaders(),
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            setText('demoResult', tr('ops.demo_failed', 'Demo failed: {error}', { error: data.error || 'unknown error' }));
            return;
        }
        setText('demoResult', tr('ops.demo_cleared', 'Demo overlay cleared.'));
        setText('demoOperatorSummary', `${tr('ops.operator_wording', 'Operator wording')}: -`);
        setText('demoNextChecks', `${tr('ops.next_checks', 'Next checks')}: -`);
    } catch (e) {
        setText('demoResult', tr('ops.demo_failed', 'Demo failed: {error}', { error: String(e) }));
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
        body: JSON.stringify({ question: q, audience: currentAudience, lang: CURRENT_LANG, context: { page: 'ops-comm', audience: currentAudience, lang: CURRENT_LANG }, max_items: 3 }),
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
                lang: CURRENT_LANG,
                note: 'ops-comm',
            }),
        });
        const data = await res.json();
        if (!output) return;
        if (!res.ok || !data.ok) {
            output.textContent = tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') });
            return;
        }
        if (action === 'preview') {
            const command = data.command ? `${data.command.exec} ${(data.command.argv || []).join(' ')}` : '(guidance only)';
            output.textContent = `${tr('ops.preview_ok', 'Preview OK')}\n${tr('ops.command_label', 'command')}=${command}\n${tr('ops.args_label', 'args')}=${JSON.stringify(args)}\n${tr('ops.steps_label', 'steps')}=${(data.steps || []).join(' | ')}\n${tr('ops.user_label', 'user')}=${data.user_message || '-'}`;
            return;
        }
        if (action === 'approve') {
            output.textContent = `${tr('ops.approved', 'Approved')}\n${tr('ops.args_label', 'args')}=${JSON.stringify(args)}\n${tr('ops.steps_label', 'steps')}=${(data.steps || []).join(' | ')}\n${tr('ops.user_label', 'user')}=${data.user_message || data.user_message_template || '-'}`;
            return;
        }
        output.textContent = `${tr('ops.executed', 'Executed')}\n${tr('ops.args_label', 'args')}=${JSON.stringify(args)}\n${tr('ops.user_label', 'user')}=${data.user_message || '-'}\n${tr('ops.exit_label', 'exit')}=${data.exit_code ?? '-'}\n${tr('ops.stdout_label', 'stdout')}=${data.stdout || '-'}\n${tr('ops.stderr_label', 'stderr')}=${data.stderr || '-'}`;
    } catch (e) {
        if (output) output.textContent = tr('ops.failed', 'Failed: {error}', { error: String(e) });
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

async function loadTriageAudit() {
    try {
        const res = await fetch('/api/triage/audit?limit=12', { headers: authHeaders() });
        const data = await res.json();
        if (!data.ok) {
            renderTriageAudit([]);
            return;
        }
        renderTriageAudit(data.items || []);
    } catch (_e) {
        renderTriageAudit([]);
    }
}

async function sendMessage() {
    const senderInput = document.getElementById('senderInput');
    const messageInput = document.getElementById('messageInput');
    const result = document.getElementById('sendResult');
    const sender = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const message = messageInput ? messageInput.value.trim() : '';
        if (!message) {
            if (result) result.textContent = tr('ops.message_empty', 'Message is empty');
            resetAiPanels();
            return;
        }
    try {
        const res = await fetch('/api/mattermost/message', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ sender, message, lang: CURRENT_LANG, ask_ai: false }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
            if (result) result.textContent = tr('ops.sent', 'Sent ({mode})', { mode: data.result.mode });
            resetAiPanels();
            if (messageInput) messageInput.value = '';
            await loadMessages();
            return;
        }
        if (result) result.textContent = tr('ops.failed', 'Failed: {error}', { error: data.error || tr('ops.unknown_error', 'unknown error') });
        resetAiPanels();
    } catch (e) {
        if (result) result.textContent = tr('ops.failed', 'Failed: {error}', { error: String(e) });
        resetAiPanels();
    }
}

async function askAi(forcedQuestion = '') {
    const senderInput = document.getElementById('senderInput');
    const messageInput = document.getElementById('messageInput');
    const result = document.getElementById('sendResult');
    const sender = senderInput ? senderInput.value.trim() : 'M.I.O. Console';
    const question = String(forcedQuestion || (messageInput ? messageInput.value.trim() : '')).trim();
    if (!question) {
        if (result) result.textContent = tr('ops.question_empty', 'Question is empty');
        resetAiPanels();
        return;
    }
    try {
        const res = await fetch('/api/ai/ask', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ question, sender, lang: CURRENT_LANG, source: 'ops-comm', context: { page: 'ops-comm', audience: currentAudience, lang: CURRENT_LANG } }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
            if (result) result.textContent = tr('ops.ai_completed', 'AI completed ({model})', { model: data.model || '-' });
            renderAiPanels(data);
            await loadRunbookCandidates(question);
            return;
        }
        if (result) result.textContent = tr('ops.ai_failed', 'AI failed: {error}', { error: data.error || data.reason || tr('ops.unknown_error', 'unknown error') });
        resetAiPanels();
        renderRunbookCandidates([]);
    } catch (e) {
        if (result) result.textContent = tr('ops.ai_failed', 'AI failed: {error}', { error: String(e) });
        resetAiPanels();
        renderRunbookCandidates([]);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.documentElement.lang = CURRENT_LANG;
    syncLanguageUi();
    const refreshBtn = document.getElementById('refreshBtn');
    const sendBtn = document.getElementById('sendBtn');
    const askAiBtn = document.getElementById('askAiBtn');
    const messageInput = document.getElementById('messageInput');
    const demoRunBtn = document.getElementById('demoRunBtn');
    const demoClearBtn = document.getElementById('demoClearBtn');
    const demoScenarioSelect = document.getElementById('demoScenarioSelect');
    const operatorBtn = document.getElementById('audienceOperatorBtn');
    const beginnerBtn = document.getElementById('audienceBeginnerBtn');
    const triageClassifyBtn = document.getElementById('triageClassifyBtn');
    const triageAnswerBtn = document.getElementById('triageAnswerBtn');
    const triageHandoffBtn = document.getElementById('triageHandoffBtn');
    const triageResetBtn = document.getElementById('triageResetBtn');
    document.getElementById('langJaBtn')?.addEventListener('click', () => switchLanguage('ja'));
    document.getElementById('langEnBtn')?.addEventListener('click', () => switchLanguage('en'));
    syncAudienceUi();
    resetTriageUi();
    if (refreshBtn) refreshBtn.addEventListener('click', async () => {
        await loadStatus();
        await loadMessages();
        await loadTriageAudit();
        await loadCapabilities();
        if (lastQuestion) await loadRunbookCandidates(lastQuestion);
    });
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    if (askAiBtn) askAiBtn.addEventListener('click', askAi);
    if (demoRunBtn) demoRunBtn.addEventListener('click', runDemoScenario);
    if (demoClearBtn) demoClearBtn.addEventListener('click', clearDemoOverlay);
    if (triageClassifyBtn) triageClassifyBtn.addEventListener('click', classifyTriageText);
    if (triageAnswerBtn) triageAnswerBtn.addEventListener('click', async () => {
        const input = document.getElementById('triageTextAnswer');
        const value = input && 'value' in input ? input.value.trim() : '';
        if (!value) {
            setText('triageSessionMeta', tr('ops.triage_answer_required', 'Enter an answer before continuing.'));
            return;
        }
        await answerTriage(value);
        if (input) input.value = '';
    });
    if (triageResetBtn) triageResetBtn.addEventListener('click', resetTriageUi);
    if (triageHandoffBtn) triageHandoffBtn.addEventListener('click', sendTriageHandoff);
    const triageInput = document.getElementById('triageInput');
    if (triageInput) triageInput.addEventListener('keydown', async (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            await classifyTriageText();
        }
    });
    if (demoScenarioSelect) demoScenarioSelect.addEventListener('change', updateDemoScenarioDescription);
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
    document.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const triageIntent = target.dataset.triageIntent;
        if (!triageIntent) return;
        await startTriage(triageIntent);
    });
    document.addEventListener('click', async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const triageAnswer = target.dataset.triageAnswer;
        if (triageAnswer === undefined) return;
        await answerTriage(triageAnswer);
    });
    loadStatus();
    loadMessages();
    loadTriageAudit();
    loadCapabilities();
    loadDemoScenarios();
    loadTriageIntents();
    const params = queryParams();
    const audienceParam = String(params.get('audience') || '').trim().toLowerCase();
    if (audienceParam === 'beginner') {
        currentAudience = 'beginner';
        syncAudienceUi();
    } else if (audienceParam === 'operator') {
        currentAudience = 'operator';
        syncAudienceUi();
    }
    const messageParam = String(params.get('message') || '').trim();
    const triageIntentParam = String(params.get('triage_intent') || '').trim();
    if (messageParam && messageInput && 'value' in messageInput) {
        messageInput.value = messageParam;
        const triageInput = document.getElementById('triageInput');
        if (triageInput && 'value' in triageInput) triageInput.value = messageParam;
    }
    if (triageIntentParam) {
        startTriage(triageIntentParam);
    }
    setInterval(() => {
        loadStatus();
        loadMessages();
        loadTriageAudit();
    }, STATUS_INTERVAL_MS);
});
