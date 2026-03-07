const AUTH_TOKEN = localStorage.getItem('azazel_token') || 'azazel-default-token-change-me';
const STATUS_INTERVAL_MS = 8000;

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
        const link = document.getElementById('mattermostLink');
        if (link && data.base_url) link.href = data.base_url;
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
            <div class="ops-message-body">${(item.message || '').replace(/</g, '&lt;')}</div>
        `;
        list.appendChild(li);
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
    const sender = senderInput ? senderInput.value.trim() : 'Azazel-Edge WebUI';
    const message = messageInput ? messageInput.value.trim() : '';
    if (!message) {
        if (result) result.textContent = 'Message is empty';
        return;
    }
    try {
        const res = await fetch('/api/mattermost/message', {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ sender, message }),
        });
        const data = await res.json();
        if (res.ok && data.ok) {
            if (result) result.textContent = `Sent (${data.result.mode})`;
            if (messageInput) messageInput.value = '';
            await loadMessages();
            return;
        }
        if (result) result.textContent = `Failed: ${data.error || 'unknown error'}`;
    } catch (e) {
        if (result) result.textContent = `Failed: ${e}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refreshBtn');
    const sendBtn = document.getElementById('sendBtn');
    if (refreshBtn) refreshBtn.addEventListener('click', async () => {
        await loadStatus();
        await loadMessages();
    });
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    loadStatus();
    loadMessages();
    setInterval(() => {
        loadStatus();
        loadMessages();
    }, STATUS_INTERVAL_MS);
});
