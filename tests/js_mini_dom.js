/* A tiny DOM for the node console tests (no dependency: CI runs plain `node`
   with no npm install, so jsdom is not available). It implements only what
   static/sentinel.js uses: an element tree parsed from well-formed markup,
   getElementById / querySelector(All) for one compound selector (tag, .class,
   [attr], [attr="v"], [attr~="v"]), classList, attributes, textContent,
   hidden/tabIndex/focus, and bubbling events. It has no innerHTML on purpose:
   anything the console renders must go through textContent/createElement.

   Edge#348. Not a browser: it proves the renderers' logic (no throw, the
   false-green law, ARIA state, keyboard handling), not layout or contrast. */
'use strict';

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#34': '"', nbsp: ' ' };

function decode(s) {
    return String(s).replace(/&(amp|lt|gt|quot|#39|#34|nbsp);/g, function (_m, e) { return ENTITIES[e]; });
}

class ClassList {
    constructor(el) { this.el = el; }
    _get() { return (this.el.getAttribute('class') || '').split(/\s+/).filter(Boolean); }
    _set(list) { this.el.setAttribute('class', list.join(' ')); }
    contains(c) { return this._get().indexOf(c) !== -1; }
    add() { const l = this._get(); for (const c of arguments) if (l.indexOf(c) === -1) l.push(c); this._set(l); }
    remove() { const drop = Array.from(arguments); this._set(this._get().filter(function (c) { return drop.indexOf(c) === -1; })); }
    toggle(c, force) {
        const on = force === undefined ? !this.contains(c) : !!force;
        if (on) this.add(c); else this.remove(c);
        return on;
    }
}

class Node {
    constructor(doc) { this.ownerDocument = doc; this.parentNode = null; this.childNodes = []; }
    get textContent() { return this.childNodes.map(function (c) { return c.textContent; }).join(''); }
    set textContent(v) {
        this.childNodes.forEach(function (c) { c.parentNode = null; });
        this.childNodes = [];
        const s = String(v == null ? '' : v);
        if (s) this.appendChild(this.ownerDocument.createTextNode(s));
    }
    appendChild(child) {
        if (child.parentNode) child.parentNode.removeChild(child);
        child.parentNode = this;
        this.childNodes.push(child);
        return child;
    }
    removeChild(child) {
        const i = this.childNodes.indexOf(child);
        if (i !== -1) { this.childNodes.splice(i, 1); child.parentNode = null; }
        return child;
    }
    get children() { return this.childNodes.filter(function (c) { return c instanceof Element; }); }
    get firstChild() { return this.childNodes[0] || null; }
    get firstElementChild() { return this.children[0] || null; }
    contains(other) {
        for (let n = other; n; n = n.parentNode) if (n === this) return true;
        return false;
    }
    _descendants(out) {
        this.children.forEach(function (c) { out.push(c); c._descendants(out); });
        return out;
    }
    querySelectorAll(sel) {
        const m = compile(sel);
        return this._descendants([]).filter(m);
    }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

class Text extends Node {
    constructor(doc, data) { super(doc); this.data = String(data); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
}

class Element extends Node {
    constructor(doc, tag) {
        super(doc);
        this.tagName = String(tag).toUpperCase();
        this.attrs = {};
        this.style = { setProperty: function (k, v) { this[k] = v; } };
        this.listeners = {};
        this.offsetWidth = 0;
        this.offsetHeight = 0;
    }
    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }
    get classList() { return new ClassList(this); }
    get hidden() { return this.hasAttribute('hidden'); }
    set hidden(v) { if (v) this.setAttribute('hidden', ''); else this.removeAttribute('hidden'); }
    get tabIndex() {
        const v = this.getAttribute('tabindex');
        return v == null ? (['BUTTON', 'A'].indexOf(this.tagName) !== -1 ? 0 : -1) : Number(v);
    }
    set tabIndex(v) { this.setAttribute('tabindex', String(v)); }
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    hasAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k); }
    removeAttribute(k) { delete this.attrs[k]; }
    closest(sel) {
        const m = compile(sel);
        for (let n = this; n instanceof Element; n = n.parentNode) if (m(n)) return n;
        return null;
    }
    focus() { this.ownerDocument.activeElement = this; }
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
    dispatchEvent(ev) {
        ev.target = ev.target || this;
        for (let n = this; n; n = n.parentNode) {
            (n.listeners && n.listeners[ev.type] || []).forEach(function (fn) { fn(ev); });
        }
        return !ev.defaultPrevented;
    }
}

// One compound selector: tag?(.class|[attr]|[attr="v"]|[attr~="v"])*
function compile(sel) {
    const s = String(sel).trim();
    const re = /^([a-zA-Z][a-zA-Z0-9-]*)?((?:\.[\w-]+|\[[\w-]+(?:[~]?="[^"]*")?\])*)$/;
    const m = s.match(re);
    if (!m) throw new Error('mini_dom: unsupported selector ' + s);
    const tag = m[1] ? m[1].toUpperCase() : null;
    const parts = [];
    const pr = /\.([\w-]+)|\[([\w-]+)(?:(~?)="([^"]*)")?\]/g;
    let p;
    while ((p = pr.exec(m[2] || ''))) parts.push(p);
    return function (el) {
        if (tag && el.tagName !== tag) return false;
        return parts.every(function (q) {
            if (q[1]) return el.classList.contains(q[1]);
            const v = el.getAttribute(q[2]);
            if (v == null) return false;
            if (q[4] === undefined) return true;
            return q[3] === '~' ? v.split(/\s+/).indexOf(q[4]) !== -1 : v === q[4];
        });
    };
}

class Document extends Node {
    constructor() {
        super(null);
        this.ownerDocument = this;
        this.readyState = 'complete';
        this.listeners = {};
        this.documentElement = new Element(this, 'html');
        this.body = new Element(this, 'body');
        this.appendChild(this.documentElement);
        this.documentElement.appendChild(this.body);
        this.activeElement = this.body;
    }
    createElement(tag) { return new Element(this, tag); }
    createElementNS(_ns, tag) { return new Element(this, tag); }
    createTextNode(s) { return new Text(this, s); }
    getElementById(id) { return this.querySelector('[id="' + id + '"]'); }
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
    dispatchEvent(ev) { (this.listeners[ev.type] || []).forEach(function (fn) { fn(ev); }); return true; }
}

// Parse well-formed markup (the console's own template) into `parent`.
function parseInto(doc, parent, html) {
    const tok = /<!--[\s\S]*?-->|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[\w:-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'))?)*)\s*(\/?)>|([^<]+)/g;
    const stack = [parent];
    let m;
    while ((m = tok.exec(html))) {
        const top = stack[stack.length - 1];
        if (m[1]) {
            const tag = m[1].toUpperCase();
            for (let i = stack.length - 1; i > 0; i--) {
                if (stack[i].tagName === tag) { stack.length = i; break; }
            }
        } else if (m[2]) {
            const el = doc.createElement(m[2]);
            const ar = /([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/g;
            let a;
            while ((a = ar.exec(m[3] || ''))) el.setAttribute(a[1], decode(a[2] != null ? a[2] : (a[3] != null ? a[3] : '')));
            top.appendChild(el);
            if (!m[4] && !VOID.has(m[2].toLowerCase())) stack.push(el);
        } else if (m[5] && m[5].trim()) {
            top.appendChild(doc.createTextNode(decode(m[5])));
        }
    }
}

function keydown(target, key) {
    const ev = { type: 'keydown', key: key, target: target, defaultPrevented: false, preventDefault: function () { this.defaultPrevented = true; } };
    target.dispatchEvent(ev);
    return ev;
}
function click(target) {
    target.dispatchEvent({ type: 'click', target: target, preventDefault: function () {} });
}

// Install `doc` (and a minimal window) as the globals a browser script sees.
function install(doc, opts) {
    opts = opts || {};
    const win = {
        document: doc,
        AZAZEL_I18N: opts.catalog,
        setTimeout: function () { return 0; },
        addEventListener: function () {},
        matchMedia: function () { return { matches: !!opts.reducedMotion }; }
    };
    global.window = win;
    global.document = doc;
    global.MutationObserver = class { observe() {} };
    global.location = { search: opts.search || '' };
    return win;
}
function uninstall() {
    delete global.window; delete global.document; delete global.MutationObserver; delete global.location;
}

module.exports = { Document, Element, parseInto, install, uninstall, keydown, click };
