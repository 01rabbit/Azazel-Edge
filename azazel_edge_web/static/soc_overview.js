/* Optional, read-only SOC overview. Uses the existing atomic refresh only. */
(function () {
    'use strict';
    function number(v) { return typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null; }
    function text(v, limit) { return typeof v === 'string' ? v.slice(0, limit || 180) : ''; }
    function rowsOf(evidence) {
        var queues = evidence.alert_queues || {}, rows = [], known = false;
        ['now', 'watch', 'backlog'].forEach(function (band) {
            var items = (queues[band] || {}).items;
            if (!Array.isArray(items)) return;
            known = true;
            items.slice(0, 100).forEach(function (raw) {
                if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return;
                var row = { band: band, time: text(raw.ts_iso || raw.ts), source: text(raw.src_ip),
                    destination: text(raw.dst_ip), reason: text(raw.attack_type || raw.signature),
                    sid: number(raw.sid), risk: number(raw.risk_score), evidence: text(raw.evidence_id),
                    decisionTrace: text(raw.decision_trace_id) };
                // Never derive a decision reference from alert.trace_id/SID/IP.
                row.key = JSON.stringify([row.band, row.time, row.source, row.destination, row.reason, row.sid, row.evidence, row.decisionTrace]);
                rows.push(row);
            });
        });
        rows.sort(function (a, b) {
            var rank = {now: 0, watch: 1, backlog: 2};
            return rank[a.band] - rank[b.band] || (b.risk === null ? -1 : b.risk) - (a.risk === null ? -1 : a.risk) || b.time.localeCompare(a.time);
        });
        return { known: known, rows: rows };
    }
    function build(detail, now, hours, band, failed) {
        detail = detail || {};
        hours = [1, 6, 24].indexOf(hours) >= 0 ? hours : 1;
        band = ['all', 'now', 'watch', 'backlog'].indexOf(band) >= 0 ? band : 'all';
        var state = detail.state || {}, health = detail.health || {}, summary = detail.summary || {};
        var flags = health.stale_flags || {}, epoch = number(state.snapshot_epoch);
        var freshness = failed ? 'offline' : epoch === null || typeof flags.snapshot !== 'boolean' ? 'unknown'
            : flags.snapshot || (summary.command_strip || {}).stale_warning || now - epoch > 30 ? 'stale'
            : epoch > now + 5 ? 'unknown' : 'current';
        var evidence = detail.evidence || {}, source = rowsOf(evidence);
        var rows = source.rows.filter(function (r) { return band === 'all' || r.band === band; });
        var points = ((detail.trends || {}).points || []);
        if (!Array.isArray(points)) points = [];
        points = points.slice(-60).filter(function (p) { return p && number(p.ts) !== null && p.ts <= now + 5 && p.ts >= now - hours * 3600; })
            .sort(function (a, b) { return a.ts - b.ts; }).map(function (p) {
                return {time: p.ts, value: p.stale_snapshot === false ? number(p.queue_depth) : null};
            });
        var booth = detail.boothFocus || {}, decision = booth.decision || {}, action = text(decision.action).toUpperCase();
        if (['OBSERVE','NOTIFY','THROTTLE','REDIRECT','ISOLATE'].indexOf(action) < 0) action = '';
        return { freshness: freshness, epoch: epoch, rows: rows, allRows: source.rows, queueKnown: source.known,
            queueNow: number(((evidence.alert_queues || {}).now || {}).count),
            recentCount: Array.isArray(evidence.recent_alerts) ? evidence.recent_alerts.length : null,
            action: action, noc: text(((summary.noc_focus || {}).path_health || {}).status, 32),
            points: points, trace: text((booth.audit || {}).trace_id), reason: text(decision.reason, 500),
            dryRun: (booth.safety || {}).dry_run === true, storageWarning: (detail.trends || {}).storage_warning === true };
    }
    if (typeof module !== 'undefined' && module.exports) module.exports = {build: build, rowsOf: rowsOf};
    if (typeof document === 'undefined') return;
    var root = document.getElementById('socOverview');
    if (!root) return;
    var latest = {}, failed = false, hours = 1, band = 'all', selected = null, expiryTimer = null;
    function tr(key) { return (window.AZAZEL_I18N || {})[key] || key; }
    function node(tag, value, cls) { var el = document.createElement(tag); if (value != null) el.textContent = String(value); if (cls) el.className = cls; return el; }
    function put(id, value) { document.getElementById(id).textContent = value; }
    function stamp(epoch) { return epoch === null ? '—' : new Date(epoch * 1000).toLocaleString(); }
    function draw(points) {
        var box = document.getElementById('socOverviewTrend'); box.textContent = '';
        var valid = points.filter(function (p) { return p.value !== null; });
        if (!valid.length) { box.appendChild(node('p', tr('overview.no_history'))); return; }
        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 720 100'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', tr('overview.trend'));
        var first = points[0].time, span = Math.max(1, points[points.length - 1].time - first);
        var max = Math.max(1, Math.max.apply(null, valid.map(function (p) { return p.value; })));
        points.forEach(function (p, i) {
            if (p.value !== null) { var dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle'); dot.setAttribute('cx', 8 + (p.time - first) / span * 704); dot.setAttribute('cy', 92 - p.value / max * 80); dot.setAttribute('r', 2); svg.appendChild(dot); }
            var prev = points[i - 1];
            if (!prev || p.value === null || prev.value === null || p.time - prev.time > 60) return;
            var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', 8 + (prev.time - first) / span * 704); line.setAttribute('x2', 8 + (p.time - first) / span * 704);
            line.setAttribute('y1', 92 - prev.value / max * 80); line.setAttribute('y2', 92 - p.value / max * 80); svg.appendChild(line);
        });
        box.appendChild(svg);
        box.appendChild(node('p', stamp(first) + ' → ' + stamp(points[points.length - 1].time) + ' · ' + valid.length + ' ' + tr('overview.samples') + ' · max ' + max, 'soc-overview-note'));
    }
    function renderDetail(model) {
        var box = document.getElementById('socOverviewDetail'); box.textContent = '';
        if (!selected) { box.appendChild(node('p', tr('overview.select'))); return; }
        var row = model.allRows.find(function (r) { return r.key === selected; });
        if (!row) { box.appendChild(node('p', tr('overview.selection_gone'))); return; }
        var dl = node('dl');
        [[tr('overview.time'), row.time], [tr('overview.source'), row.source + ' → ' + row.destination], [tr('overview.reason'), row.reason],
            [tr('overview.evidence'), row.evidence || tr('overview.not_supplied')], [tr('overview.decision_trace'), row.decisionTrace || tr('overview.not_supplied')],
            [tr('overview.decision'), row.decisionTrace && row.decisionTrace === model.trace ? model.action + ' · ' + model.reason : tr('overview.no_bound_decision')],
            [tr('overview.execution'), row.decisionTrace && row.decisionTrace === model.trace && model.dryRun ? tr('overview.dry_run') : tr('overview.unverified')]].forEach(function (pair) {
                dl.appendChild(node('dt', pair[0])); dl.appendChild(node('dd', pair[1] || '—'));
            });
        box.appendChild(dl); box.appendChild(node('p', tr('overview.advisory'), 'soc-overview-note'));
    }
    function render() {
        var model = build(latest, Date.now() / 1000, hours, band, failed);
        if (expiryTimer) window.clearTimeout(expiryTimer);
        if (model.freshness === 'current') expiryTimer = window.setTimeout(render, Math.max(200, (model.epoch + 31 - Date.now() / 1000) * 1000));
        root.dataset.freshness = model.freshness;
        put('socOverviewFreshness', ({current: tr('overview.current'), stale: tr('overview.stale'), offline: tr('overview.offline'), unknown: tr('overview.unknown')})[model.freshness] + ' · ' + stamp(model.epoch));
        put('socOverviewQueueValue', model.queueNow === null ? '—' : model.queueNow);
        put('socOverviewRecentValue', model.recentCount === null ? '—' : model.recentCount);
        put('socOverviewDecisionValue', model.action || '—');
        put('socOverviewNocValue', model.noc || '—');
        put('socOverviewScope', tr('overview.snapshot_scope') + ' · ' + model.rows.length + ' ' + tr('overview.filtered') + ' / ' + model.allRows.length + ' ' + tr('overview.retained'));
        put('socOverviewHistoryState', model.storageWarning ? tr('overview.history_unavailable') : tr('overview.history_scope'));
        draw(model.points);
        var focusKey = document.activeElement && document.activeElement.dataset.overviewKey;
        var body = document.getElementById('socOverviewRows'); body.textContent = '';
        if (!model.rows.length) {
            var empty = node('tr'), cell = node('td', model.queueKnown ? tr('overview.empty') : tr('overview.unavailable'));
            cell.colSpan = 5; empty.appendChild(cell); body.appendChild(empty);
        }
        model.rows.slice(0, 24).forEach(function (row) {
            var line = node('tr');
            [row.time || '—', row.band.toUpperCase(), row.source || '—', row.reason || (row.sid === null ? '—' : '#' + row.sid)].forEach(function (value) { line.appendChild(node('td', value)); });
            var cell = node('td'), button = node('button', tr('overview.details'));
            button.type = 'button'; button.dataset.overviewKey = row.key; button.setAttribute('aria-pressed', String(selected === row.key));
            button.addEventListener('click', function () { selected = row.key; renderDetail(model); document.getElementById('socOverviewDetail').focus(); });
            cell.appendChild(button); line.appendChild(cell); body.appendChild(line);
            if (focusKey && row.key === focusKey) button.focus({preventScroll: true});
        });
        renderDetail(model);
    }
    document.getElementById('socOverviewToggle').addEventListener('click', function () {
        var on = root.hidden; root.hidden = !on; document.body.dataset.socOverview = on ? 'on' : 'off';
        this.setAttribute('aria-pressed', String(on));
        if (on) render();
    });
    document.getElementById('socOverviewHours').addEventListener('change', function () { hours = Number(this.value); render(); });
    document.getElementById('socOverviewBand').addEventListener('change', function () { band = this.value; render(); });
    document.getElementById('socOverviewEvidence').addEventListener('click', function () { document.getElementById('sentinelTierEvidence').click(); });
    document.addEventListener('azazel:refresh', function (event) { latest = event.detail || {}; failed = false; render(); });
    document.addEventListener('azazel:refresh-error', function () { failed = true; render(); });
    render();
})();
