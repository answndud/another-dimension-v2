const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ReprotectWork = require('./reprotect-work.js');

// The page is markup in index.html plus a stylesheet in app.css (the CSP forbids inline
// styles), so tests that check either read both.
function pageSource() {
  return `${fs.readFileSync(`${__dirname}/index.html`, 'utf8')}\n${fs.readFileSync(`${__dirname}/app.css`, 'utf8')}`;
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function response(body = '', status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

function deferredJsonResponse(status = 200) {
  const json = deferred();
  let jsonStartedResolve;
  const jsonStarted = new Promise((resolve) => { jsonStartedResolve = resolve; });
  return {
    json,
    jsonStarted,
    response: {
      ok: status >= 200 && status < 300,
      status,
      text: async () => '',
      json: () => { jsonStartedResolve(); return json.promise; },
    },
  };
}

function file(name, contents) {
  const bytes = Buffer.from(contents);
  return {
    name,
    size: bytes.length,
    dataUrl: `data:application/octet-stream;base64,${Buffer.from(contents).toString('base64')}`,
    slice(start = 0, end = bytes.length) {
      const selected = bytes.subarray(start, end);
      return { arrayBuffer: async () => selected.buffer.slice(selected.byteOffset, selected.byteOffset + selected.byteLength) };
    },
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

function createHarness(options = {}) {
  const elements = new Map();
  const requests = [];
  const transferFiles = new Map();
  let transferSequence = 0;
  const storage = new Map();
  const themeStorage = options.themeStorage || new Map();
  const element = (selector) => {
    if (!elements.has(selector)) {
      const target = {
        selector,
        value: '', hidden: false, disabled: false, checked: false, open: false,
        dataset: {}, style: {}, listeners: {}, children: [],
        _textContent: '', textContentSetCount: 0,
        addEventListener(type, callback) { this.listeners[type] = callback; },
        contains(node) { return (this.containsNodes || []).includes(node); },
        querySelector(selector) { return element(`${selector} inside ${selector}`); },
        querySelectorAll() { return []; },
        replaceChildren(...children) { this.children = children; },
        append(...children) { this.children.push(...children); },
        appendChild(child) { this.children.push(child); return child; },
        focus() { this.focused = true; this.focusCalls = (this.focusCalls || 0) + 1; document.activeElement = this; }, click() {}, remove() {}, setAttribute() {},
        requestSubmit() {
          this.requestSubmitCalls = (this.requestSubmitCalls || 0) + 1;
          if (this.listeners.submit) return this.listeners.submit({ preventDefault() {} });
        },
        showModal() { this.open = true; },
        close() {
          this.open = false;
          if (this.listeners.close) this.listeners.close();
        },
        classList: { add() {}, remove() {}, toggle() {} },
      };
      Object.defineProperty(target, 'value', {
        get() { return this._value || ''; },
        set(value) {
          this._value = String(value);
          if (selector === '#history-backup-file' && this._value === '') this.files = [];
        },
      });
      Object.defineProperty(target, 'textContent', {
        get() { return this._textContent; },
        set(value) { this.textContentSetCount += 1; this._textContent = String(value); },
      });
      elements.set(selector, target);
    }
    return elements.get(selector);
  };
  const document = {
    documentElement: { dataset: {}, setAttribute() {} },
    listeners: {},
    addEventListener(type, callback) { this.listeners[type] = callback; },
    querySelector: element,
    querySelectorAll: (selector) => selector === '.disconnect' ? [element('#disconnect')] : [],
    createElement: (tag) => element(`created:${tag}:${elements.size}`),
    createTextNode: (text) => ({ textContent: text }),
  };
  document.body = element('body');
  document.activeElement = document.body;
  const window = {
    ReprotectWork,
    confirm: () => false,
    openedUrls: [],
    open(url, target, features) { this.openedUrls.push({ url, target, features }); },
    showOpenFilePicker: null,
    showSaveFilePicker: null,
  };
  const fetch = (path, init) => {
    const pending = deferred();
    const item = { path, init, ...pending };
    requests.push(item);
    if (path === '/api/identity/logout') pending.resolve(response('ok'));
    if (path === '/api/history/backup-transfer') {
      const payload = JSON.parse(init.body);
      if (payload.action === 'upload-start') {
        const transferId = `upload-${++transferSequence}`;
        transferFiles.set(transferId, Buffer.alloc(0));
        pending.resolve(response(JSON.stringify({ transferId })));
      } else if (payload.action === 'upload-chunk') {
        const prior = transferFiles.get(payload.transferId) || Buffer.alloc(0);
        const bytes = Buffer.from(payload.data, 'base64');
        transferFiles.set(payload.transferId, Buffer.concat([prior, bytes]));
        if (options.uploadChunkReject) pending.reject(new Error('upload failed'));
        else if (!options.manualUploadChunks) pending.resolve(response(JSON.stringify({ offset: prior.length + bytes.length })));
      } else if (payload.action === 'cleanup') {
        transferFiles.delete(payload.transferId);
        pending.resolve(response('{"ok":true}'));
      } else if (payload.action === 'read') {
        const bytes = transferFiles.get(payload.transferId) || Buffer.alloc(0);
        const chunk = bytes.subarray(payload.offset, payload.offset + 256 * 1024);
        pending.resolve(response(JSON.stringify({
          transferId: payload.transferId, offset: payload.offset, size: bytes.length,
          data: chunk.toString('base64'), done: payload.offset + chunk.length === bytes.length,
        })));
      } else if (payload.action === 'verify') {
        pending.resolve(response(JSON.stringify({ peerId: 'ab'.repeat(32), messageCount: 1 })));
      } else if (payload.action === 'export' || payload.action === 'bundle-export') {
        if (payload.action === 'bundle-export' && options.bundleExportReject) {
          pending.reject(new Error('bundle export failed'));
        } else if (payload.action === 'bundle-export' && options.manualBundleExport) {
          // The test resolves this after a dialog transition to model a late server result.
        } else {
          const transferId = `export-${++transferSequence}`;
          transferFiles.set(transferId, Buffer.from('exported backup'));
          pending.resolve(response(JSON.stringify({ transferId, size: transferFiles.get(transferId).length })));
        }
      } else if (payload.action === 'import') {
        if (options.importFetchReject) pending.reject(new Error('connection lost'));
        else if (options.importTextReject) pending.resolve({
          ok: false, status: 500, text: async () => { throw new Error('response body unavailable'); },
        });
        else if (!options.manualImport) {
          pending.resolve(options.importFailure
            ? response(options.importFailure, 400)
            : response(options.importResult
              || JSON.stringify({ peerId: 'ab'.repeat(32), messageCount: 1, linkedIdentityRestored: false })));
        }
      }
    }
    return pending.promise;
  };
  class FileReader {
    readAsDataURL(input) {
      queueMicrotask(() => {
        this.result = input.dataUrl;
        this.onload();
      });
    }
  }
  const sessionStorage = {
    getItem: (key) => storage.get(key) || null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  };
  const localStorage = {
    getItem: (key) => themeStorage.get(key) || null,
    setItem: (key, value) => themeStorage.set(key, value),
  };
  const context = {
    window, document, fetch, sessionStorage, localStorage, FileReader, Uint8Array, TextDecoder,
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
    btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
    Blob, URL, console, setTimeout, clearTimeout, setInterval, clearInterval,
    queueMicrotask, Date, Math, Set, Map, Promise, Error, JSON,
  };
  vm.runInNewContext(fs.readFileSync(require.resolve('./app.js'), 'utf8'), context, { filename: 'app.js' });
  const evaluate = (expression) => vm.runInNewContext(expression, context);
  const click = async (selector) => {
    const callback = element(selector).listeners.click;
    assert.ok(callback, `missing click handler: ${selector}`);
    return callback({ preventDefault() {} });
  };
  const requestFor = (path) => requests.findLast((item) => item.path === path);
  const requestForAction = (action) => requests.findLast((item) => item.path === '/api/history/backup-transfer' && JSON.parse(item.init.body).action === action);
  const addTransferFile = (id, bytes) => transferFiles.set(id, Buffer.from(bytes));
  return { element, window, click, requests, requestFor, requestForAction, addTransferFile, evaluate, themeStorage, document };
}

async function refreshHarnessAs(h, identity, historyItems = []) {
  const refresh = h.evaluate('refreshIdentity()');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/identity/status').resolve(response(identity));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/settings/get').resolve(response(JSON.stringify({
    savedMode: 'general', socks: null, activeMode: 'general', activeSocks: null,
    restartRequired: false, notifications: false,
    savedRelays: ['wss://relay.primal.net'], activeRelays: ['wss://relay.primal.net'],
  })));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response(JSON.stringify(historyItems)));
  await refresh;
}

function historySummary(peerId, messageCount = 1) {
  return { peerId, messageCount, lastMessage: 1234, verified: true };
}

async function waitForRequest(getRequest) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const found = getRequest();
    if (found) return found;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail('expected request was not issued');
}

async function attachChatInHarness(h, operationId) {
  const attaching = h.evaluate(`attachChat('${operationId}')`);
  const statusRequest = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/chat/status'));
  statusRequest.resolve(response(JSON.stringify({ phase: 'connected', messageCount: 0, messageEpoch: 1 })));
  await attaching;
  h.evaluate('stopPolling()');
}

function submitChat(h) {
  return h.element('#send-form').listeners.submit({ preventDefault() {} });
}

function inputChat(h, value) {
  h.element('#chat-text').value = value;
  h.element('#chat-text').listeners.input();
}

test('chat drafts stay with one operation through home and disconnect but not close or another operation', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  inputChat(h, 'A draft');

  await h.click('#brand-home');
  await h.click('#return-to-chat');
  assert.equal(h.element('#chat-text').value, 'A draft');

  h.evaluate("updateChatView({ phase: 'disconnected', messageCount: 0, messageEpoch: 1 })");
  assert.equal(h.element('#chat-text').value, 'A draft');

  const closing = h.click('#close-chat');
  h.requestFor('/api/chat/cancel').resolve(response('ok'));
  await closing;
  await attachChatInHarness(h, 'operation-B');
  assert.equal(h.element('#chat-text').value, '');
});

test('late send success, failure, or body from A cannot change B controls, status, focus, or draft', async () => {
  for (const lateResult of ['success', 'failure', 'body']) {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
    await attachChatInHarness(h, 'operation-A');
    inputChat(h, 'A message');
    const sendingA = submitChat(h);
    const requestA = await waitForRequest(() => h.requestFor('/api/chat/send'));

    let lateBody;
    let bodyStarted;
    if (lateResult === 'body') {
      lateBody = deferred();
      let bodyStartedResolve;
      bodyStarted = new Promise((resolve) => { bodyStartedResolve = resolve; });
      requestA.resolve({
        ok: false, status: 409,
        text: () => { bodyStartedResolve(); return lateBody.promise; },
      });
      await bodyStarted;
    }

    await attachChatInHarness(h, 'operation-B');
    h.element('#chat-status').textContent = 'B status';
    inputChat(h, 'B draft');
    const sendingB = submitChat(h);
    const requests = h.requests.filter((item) => item.path === '/api/chat/send');
    const requestB = requests[1];
    assert.equal(h.element('#send-form').querySelector('button').disabled, true);

    if (lateResult === 'success') requestA.resolve(response('ok'));
    else if (lateResult === 'failure') requestA.reject(new Error('late network failure'));

    if (lateResult === 'body') {
      lateBody.resolve('A 늦은 거절');
      await sendingA;
      assert.equal(h.element('#chat-text').value, 'B draft');
      assert.equal(h.element('#chat-status').textContent, 'B status');
      assert.equal(h.element('#chat-text').focused, undefined);
      assert.equal(h.element('#send-form').querySelector('button').disabled, true);
      requestB.resolve(response('ok'));
      await sendingB;
      assert.equal(h.element('#chat-text').value, '');
      continue;
    }

    await sendingA;

    assert.equal(h.element('#chat-text').value, 'B draft');
    assert.equal(h.element('#chat-status').textContent, 'B status');
    assert.equal(h.element('#chat-text').focused, undefined);
    assert.equal(h.element('#send-form').querySelector('button').disabled, true);

    requestB.resolve(response('ok'));
    await sendingB;
    assert.equal(h.element('#chat-text').value, '');
  }
});

test('a successful send does not clear text entered while that send was pending', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  inputChat(h, 'first message');
  const sending = submitChat(h);
  const request = await waitForRequest(() => h.requestFor('/api/chat/send'));
  inputChat(h, 'new draft');
  request.resolve(response('ok'));
  await sending;
  assert.equal(h.element('#chat-text').value, 'new draft');
});

test('a delayed close for A cannot clean up a newly attached B conversation', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  const closing = h.click('#close-chat');
  const cancelA = await waitForRequest(() => h.requestFor('/api/chat/cancel'));
  assert.equal(cancelA.init.body, 'operation-A');
  assert.equal(h.evaluate('operationId'), null);
  assert.equal(h.element('#identity-active').hidden, false);

  await attachChatInHarness(h, 'operation-B');
  const bSnapshot = h.evaluate('latestChatSnapshot');
  const bMessage = { textContent: 'B message' };
  h.element('#conversation').appendChild(bMessage);
  inputChat(h, 'B draft');
  const bPollGeneration = h.evaluate('pollGeneration');

  cancelA.resolve(response('cancelled A'));
  await closing;

  assert.equal(h.evaluate('operationId'), 'operation-B');
  assert.equal(h.evaluate('latestChatSnapshot'), bSnapshot);
  assert.equal(h.element('#chat-view').hidden, false);
  assert.equal(h.element('#identity-active').hidden, true);
  assert.deepEqual(h.element('#conversation').children, [bMessage]);
  assert.equal(h.element('#chat-text').value, 'B draft');
  assert.equal(h.evaluate('pollGeneration'), bPollGeneration);
  assert.equal(h.requests.filter((item) => item.path === '/api/history/list').length, 0);
});

test('send success while home is open does not focus the hidden conversation input', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  h.document.activeElement = h.element('#chat-text');
  inputChat(h, 'message from A');
  const sending = submitChat(h);
  const request = await waitForRequest(() => h.requestFor('/api/chat/send'));
  await h.click('#brand-home');
  request.resolve(response('sent'));
  await sending;

  assert.equal(h.element('#identity-active').hidden, false);
  assert.equal(h.element('#chat-view').hidden, true);
  assert.equal(h.element('#chat-text').value, '');
  assert.equal(h.document.activeElement, h.element('#chat-text'));
  assert.equal(h.element('#chat-text').focusCalls || 0, 0);
});

test('send success does not steal focus from another control in the same chat', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  h.document.activeElement = h.element('#chat-text');
  inputChat(h, 'message from A');
  const sending = submitChat(h);
  const request = await waitForRequest(() => h.requestFor('/api/chat/send'));
  const closeButton = h.element('#close-chat');
  h.document.activeElement = closeButton;
  request.resolve(response('sent'));
  await sending;

  assert.equal(h.element('#chat-view').hidden, false);
  assert.equal(h.document.activeElement, closeButton);
  assert.equal(h.element('#chat-text').focusCalls || 0, 0);
});

test('dashboard menu closes on outside click and Escape; management dialog reuses the selected pane and restores focus', async () => {
  const harness = createHarness();
  const menu = harness.element('#identity-menu');
  harness.element('#identity-active').hidden = false;
  menu.open = true;
  harness.document.listeners.click({ target: {} });
  assert.equal(menu.open, false);

  const inside = {};
  menu.containsNodes = [inside];
  menu.open = true;
  harness.document.listeners.click({ target: inside });
  assert.equal(menu.open, true);
  harness.document.listeners.keydown({ key: 'Escape' });
  assert.equal(menu.open, false);

  const settings = harness.element('#management-settings-pane');
  const identity = harness.element('#management-identity-pane');
  const history = harness.element('#management-history-pane');
  await harness.click('#menu-open-settings');
  assert.equal(menu.open, false);
  assert.equal(harness.element('#management-dialog').open, true);
  assert.equal(harness.element('#management-dialog-title').textContent, '연결 설정');
  assert.equal(settings.hidden, false);
  assert.equal(identity.hidden, true);
  assert.equal(history.hidden, true);
  assert.equal(harness.element('#management-dialog-title').focused, true);

  await harness.click('#menu-open-identity');
  assert.equal(settings.hidden, true);
  assert.equal(identity.hidden, false);
  assert.equal(history.hidden, true);
  await harness.click('#menu-open-history');
  assert.equal(settings.hidden, true);
  assert.equal(identity.hidden, true);
  assert.equal(history.hidden, false);
  await harness.click('#menu-open-identity');
  const replaceDialog = harness.element('#replace-identity-dialog');
  await harness.click('#replace-identity');
  assert.equal(replaceDialog.open, true);
  await harness.click('#cancel-identity-replacement');
  assert.equal(replaceDialog.open, false);
  assert.equal(harness.element('#management-dialog').open, true);

  const addedCodeView = harness.element('#added-code-view');
  addedCodeView.hidden = true;
  const addCode = harness.click('#add-code');
  harness.requestFor('/api/identity/add-code').resolve(response('issued-code'));
  await addCode;
  assert.equal(harness.element('#added-code').value, 'issued-code');
  assert.equal(addedCodeView.hidden, false);
  assert.equal(identity.hidden, false);
  assert.equal(harness.element('#management-dialog').open, true);

  await harness.click('#close-added-code');
  assert.equal(harness.element('#added-code').value, 'issued-code');
  assert.equal(addedCodeView.hidden, false);
  await harness.click('#close-management-dialog');
  assert.equal(harness.element('#management-dialog').open, true);
  assert.equal(harness.element('#added-code').value, 'issued-code');
  let prevented = false;
  harness.element('#management-dialog').listeners.cancel({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  harness.window.confirm = () => true;
  await harness.click('#close-management-dialog');
  assert.equal(harness.element('#management-dialog').open, false);
  assert.equal(harness.element('#added-code').value, '');
  assert.equal(addedCodeView.hidden, true);
  assert.equal(harness.element('#identity-menu-toggle').focused, true);

  const html = pageSource();
  const menuPanel = html.slice(html.indexOf('id="identity-menu"'), html.indexOf('id="management-dialog"'));
  assert.ok(menuPanel.indexOf('class="menu-group-label">관리') < menuPanel.indexOf('class="menu-group menu-account"'));
  assert.match(html, /\.identity-menu-panel\s*\{[^}]*width:\s*min\(240px/);
  assert.match(html, /\.menu-group-label\s*\{[^}]*text-align:\s*left/);
  assert.ok(menuPanel.indexOf('class="menu-group-label">화면 설정') < menuPanel.indexOf('id="theme-toggle"'));
  assert.ok(menuPanel.indexOf('id="theme-toggle"') < menuPanel.indexOf('class="menu-group-label">관리'));
  assert.match(html, /\.join-controls input, \.join-controls button\s*\{[^}]*height:\s*var\(--control-height\);[^}]*min-height:\s*var\(--control-height\);/);
  assert.match(html, /--control-height:\s*44px/);
  assert.match(html, /\.conversation-options\s*\{[^}]*grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\)/);
  assert.match(html, /@media\s*\(max-width:\s*680px\)\s*\{\s*\.conversation-options\s*\{\s*grid-template-columns:\s*minmax\(0, 1fr\)/);
  assert.match(html, /main:has\(\.identity-dashboard:not\(\[hidden\]\)\)\s*\{[^}]*justify-content:\s*flex-start;[^}]*padding:\s*clamp\(32px, 8vh, 72px\)/);
  assert.match(html, /\.identity-dashboard\s*\{[^}]*margin:\s*0;/);
  assert.match(html, /@media\s*\(max-width:\s*560px\)[\s\S]*?main:has\(\.identity-dashboard:not\(\[hidden\]\)\)\s*\{\s*padding-top:\s*var\(--space-8\)/);
  assert.match(html, /\.chat-header\s*\{[^}]*grid-row:\s*1/);
  assert.match(html, /\.chat-status-strip\s*\{[^}]*grid-row:\s*2/);
  assert.match(html, /\.chat-workflows\s*\{[^}]*grid-row:\s*3/);
  assert.match(html, /#chat-view\s+#conversation\s*\{[^}]*grid-row:\s*4/);
  assert.match(html, /#chat-view #send-form\s*\{[^}]*grid-row:\s*6/);
  assert.match(html, /#send-status\s*\{[^}]*grid-row:\s*5/);
  assert.match(html, /#chat-view\s*\{[^}]*grid-template-rows:\s*auto auto auto minmax\(0, 1fr\) auto auto/);
  assert.match(html, /<div id="conversation"[^>]*><\/div>\s*<p id="send-status"[^>]*><\/p>\s*<form id="send-form"/);
  assert.match(html, /main:has\(#chat-view:not\(\[hidden\]\)\)\s+#message\s*\{[^}]*flex:\s*0 0 52px;[^}]*width:\s*100%/);
  assert.match(html, /#connect-form\s+h2/);
  assert.match(html, /#connect-form\s*>\s*button,\s*#login-form\s+button\s*\{[^}]*width:\s*100%/);
  assert.match(html, /#created,\s*#invite-view\s*\{[^}]*640px/);
  assert.match(html, /\.management-pane\s*>\s*\.dashboard-card\s*\{[^}]*border:\s*0;[^}]*background:\s*transparent/);
  assert.match(html, /\.history-bundle-row\s*\{[^}]*grid-template-columns:\s*auto minmax\(0, 1fr\)/);
  assert.match(html, /\.history-item\s*\{[^}]*text-align:\s*left/);
  assert.match(html, /#chat-text\s*\{[^}]*min-height:\s*48px/);
  assert.equal((html.match(/#chat-text\s*\{/g) || []).length, 2, 'only base and mobile chat input sizing rules remain');
  const dashboard = html.slice(html.indexOf('<section id="identity-active"'), html.indexOf('<section id="invite-view"'));
  for (const copy of ['채팅 시작', '채팅방 생성', '초대 코드 생성', '채팅방 입장', '입장']) {
    assert.ok(dashboard.includes(copy), `dashboard copy missing: ${copy}`);
  }
  for (const removedCopy of ['새로운 대화를 만들거나 초대 코드로 참여하세요.', '새 대화 만들기', '초대 코드를 생성하고 상대방과 공유하세요.', '초대 코드로 참여', '상대방에게 받은 초대 코드를 입력하세요.', '>참여<']) {
    assert.equal(dashboard.includes(removedCopy), false, `old dashboard copy remains: ${removedCopy}`);
  }

  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
  assert.deepEqual([...new Set(duplicateIds)], []);
  for (const [, labelledId] of html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)) {
    assert.ok(ids.includes(labelledId), `label points to missing id: ${labelledId}`);
  }
  for (const requiredId of [
    'theme-toggle', 'identity-menu', 'logout', 'save-settings', 'add-code',
    'replace-identity', 'history-bundle-export', 'identity-active', 'create-invite',
    'join-form', 'join-code', 'connect-form', 'connect-heading', 'identity-entry', 'created', 'invite-view',
    'chat-view', 'history-detail', 'added-code-view',
  ]) {
    assert.ok(ids.includes(requiredId), `required feature id missing: ${requiredId}`);
  }
});

test('brand button returns to the dashboard and global status has consistent separation', async () => {
  const h = createHarness();
  const returnButton = h.element('#return-to-chat');
  assert.equal(returnButton.hidden, true);

  h.element('#identity-id').textContent = 'test-identity';
  h.element('#chat-view').hidden = false;
  h.element('#history-detail').hidden = false;
  h.element('#message').textContent = '이전 오류';
  h.evaluate("operationId = 'live-operation'; updateChatView({ phase: 'connected', messageEpoch: 1 })");
  const existingMessage = { textContent: '기존 메시지' };
  h.element('#conversation').appendChild(existingMessage);

  await h.click('#brand-home');

  assert.equal(h.element('#identity-active').hidden, false);
  assert.equal(h.element('#chat-view').hidden, true);
  assert.equal(h.element('#history-detail').hidden, true);
  assert.equal(h.element('#message').textContent, '');
  assert.equal(returnButton.hidden, false);

  await h.click('#return-to-chat');
  assert.equal(h.element('#chat-view').hidden, false);
  assert.equal(h.element('#identity-active').hidden, true);
  assert.equal(h.element('#conversation').children[0], existingMessage);
  assert.equal(h.evaluate('operationId'), 'live-operation');

  const closeTask = h.click('#close-chat');
  h.requestFor('/api/chat/cancel').resolve(response('ok'));
  await closeTask;
  assert.equal(returnButton.hidden, true);
  assert.equal(h.evaluate('operationId'), null);

  h.evaluate("operationId = 'logout-operation'; updateChatView({ phase: 'connected', messageEpoch: 2 }); show('active')");
  assert.equal(returnButton.hidden, false);
  await h.click('#logout');
  assert.equal(returnButton.hidden, true);
  assert.equal(h.evaluate('operationId'), null);

  const html = pageSource();
  assert.match(html, /<h1><button id="brand-home"[^>]*>Another Dimension<\/button><\/h1>/);
  assert.match(html, /main\s*>\s*#message\s*\{[^}]*margin-top:\s*var\(--space-4\)/);
  assert.match(html, /main\s*>\s*:not\(\[hidden\]\):has\(\+ #message:not\(:empty\)\)\s*\{[^}]*margin-bottom:\s*0/);
  assert.match(html, /main:has\(\.identity-dashboard:not\(\[hidden\]\)\) #message, main:has\(#chat-view:not\(\[hidden\]\)\) #message\s*\{[^}]*margin:\s*var\(--space-4\) 0 0/);
});

test('chat UI keeps the message DOM safe and follows new messages only when already near the bottom', () => {
  const harness = createHarness();
  const conversation = harness.element('#conversation');
  conversation.clientHeight = 200;
  conversation.scrollHeight = 1000;
  conversation.scrollTop = 800;
  harness.evaluate(`appendMessages([{ sender: '나', time: 1700000000, text: 'hello\\nhttps://example.test' }])`);
  assert.equal(conversation.scrollTop, 1000);
  const firstMessage = conversation.children[0];
  assert.match(firstMessage.className, /^entry mine group-start$/);
  assert.equal(firstMessage.children.length, 2);
  assert.match(firstMessage.children[0].dateTime, /^\d{4}-/);
  assert.match(firstMessage.children[0].textContent, /^\d{2}:\d{2}$/);
  assert.match(firstMessage.children[0].title, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);

  conversation.scrollHeight = 1200;
  conversation.scrollTop = 200;
  harness.evaluate(`appendMessages([{ sender: '상대', time: 1700000001, text: 'older message' }])`);
  assert.equal(conversation.scrollTop, 200);

  const html = pageSource();
  assert.match(html, /main:has\(#chat-view:\s*not\(\[hidden\]\)\)[^{]*\{[^}]*width:\s*min\(100%,\s*960px\)/);
  assert.match(html, /#chat-view\s+#conversation\s*\{[^}]*min-height:\s*0;[^}]*max-height:\s*none;[^}]*overflow-y:\s*auto/s);
  assert.match(html, /#chat-view\s+\.entry\.mine\s*\{[^}]*align-self:\s*flex-end;[^}]*margin-left:\s*auto/s);
  assert.match(html, /#send-form\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+88px/s);
  assert.match(html, /#chat-text\s*\{[^}]*max-height:\s*160px/s);
  for (const id of [
    'chat-view', 'chat-title', 'chat-status', 'delivery-status', 'storage-status',
    'verification', 'confirm-peer', 'identity-transition-panel', 'history-restore-panel',
    'history-restore-preview', 'history-restore-request', 'conversation', 'send-form',
    'send-status', 'chat-text', 'close-chat',
  ]) assert.match(html, new RegExp(`id="${id}"`));
});

test('chat input grows from 48px, caps internally, and resets after clearing', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const input = h.element('#chat-text');
  input.scrollHeight = 112;
  h.evaluate("chatDrafts.set(chatDraftKey('identity-A', 'operation-A'), 'restored draft')");
  await attachChatInHarness(h, 'operation-A');
  assert.equal(input.value, 'restored draft');
  assert.equal(input.style.height, '112px', 'restored drafts are measured during attachment');

  input.scrollHeight = 220;
  inputChat(h, 'a long draft');
  assert.equal(input.style.height, '160px');
  assert.equal(input.style.overflowY, 'auto');

  input.scrollHeight = 48;
  inputChat(h, 'short draft');
  const sending = submitChat(h);
  const request = await waitForRequest(() => h.requestFor('/api/chat/send'));
  request.resolve(response('ok'));
  await sending;
  assert.equal(input.value, '');
  assert.equal(input.style.height, '48px');
  assert.equal(input.style.overflowY, 'hidden');
});

test('chat keyboard sends on Enter but preserves Shift+Enter and IME composition', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  const input = h.element('#chat-text');
  const form = h.element('#send-form');
  let submitCalls = 0;
  form.requestSubmit = () => { submitCalls += 1; };
  inputChat(h, 'hello');

  const event = (overrides = {}) => ({
    key: 'Enter', shiftKey: false, isComposing: false, keyCode: 13,
    prevented: false, preventDefault() { this.prevented = true; }, ...overrides,
  });
  const enter = event();
  input.listeners.keydown(enter);
  assert.equal(enter.prevented, true);
  assert.equal(submitCalls, 1);

  for (const composingEnter of [event({ shiftKey: true }), event({ isComposing: true }), event({ keyCode: 229 })]) {
    input.listeners.keydown(composingEnter);
    assert.equal(composingEnter.prevented, false);
  }
  assert.equal(submitCalls, 1);
});

test('chat send button requires a connected nonempty unsent draft', () => {
  const h = createHarness();
  const button = h.element('#send-form').querySelector('button');
  const input = h.element('#chat-text');
  h.evaluate("operationId = 'operation-A'; updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1 })");
  assert.equal(button.disabled, true);
  inputChat(h, 'hello');
  assert.equal(button.disabled, false);
  h.evaluate("updateChatView({ phase: 'disconnected', messageCount: 0, messageEpoch: 1 })");
  assert.equal(button.disabled, true);
});

test('chat date separators and sender grouping survive polling batches and reset with message epoch', () => {
  const h = createHarness();
  const conversation = h.element('#conversation');
  const firstDay = new Date(2026, 0, 1, 23, 59, 0).getTime() / 1000;
  const secondDay = new Date(2026, 0, 2, 0, 1, 0).getTime() / 1000;
  h.evaluate(`updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1 })`);
  h.evaluate(`appendMessages([{ sender: '상대', time: ${firstDay}, text: 'first batch' }])`);
  h.evaluate(`appendMessages([
    { sender: '상대', text: 'timestamp unavailable' },
    { sender: '상대', time: ${secondDay}, text: 'next day after unknown time' },
    { sender: '신원 변경', time: ${secondDay + 1}, text: 'system event' },
    { sender: '상대', time: ${secondDay + 2}, text: 'after system' },
  ])`);

  assert.equal(conversation.children.length, 6);
  assert.equal(conversation.children[0].className, 'entry group-start');
  assert.equal(conversation.children[1].children.length, 1, 'missing timestamps are omitted');
  assert.equal(conversation.children[2].className, 'message-date-divider');
  assert.match(conversation.children[2].textContent, /2026년 1월 2일/);
  assert.equal(conversation.children[3].className, 'entry group-start');
  assert.equal(conversation.children[4].className, 'entry system group-start');
  assert.equal(conversation.children[5].className, 'entry group-start');
  assert.equal(h.evaluate('messageCursor'), 5, 'date separators do not count as messages');

  h.evaluate(`updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 2 })`);
  assert.equal(conversation.children.length, 0);
  assert.equal(h.evaluate('messageCursor'), 0);
  h.evaluate(`appendMessages([{ sender: '상대', time: ${secondDay}, text: 'new epoch' }])`);
  assert.equal(conversation.children.length, 1, 'the new epoch starts without stale date or sender state');
});

test('history detail separates browsing, backup and deletion without replacing feature controls', () => {
  const html = pageSource();
  const detailStart = html.indexOf('<section id="history-detail"');
  const detail = html.slice(detailStart, html.indexOf('<p id="message"', detailStart));
  const ids = [...html.matchAll(/\bid="([^\"]+)"/g)].map((match) => match[1]);
  const required = [
    'history-peer', 'contact-reconnect', 'history-back', 'contact-export', 'history-export',
    'history-backup-export', 'history-backup-export-password', 'history-backup-export-password-confirm',
    'history-backup-file', 'history-backup-import-password', 'history-backup-import',
    'history-reprotect-choose', 'history-reprotect-source', 'history-reprotect-previous-code',
    'history-reprotect-previous-password', 'history-reprotect-new-password',
    'history-reprotect-new-password-confirm', 'history-reprotect', 'history-reprotect-save',
    'message-filter', 'history-messages', 'history-page-prev', 'history-page-next',
    'history-page-reload', 'history-page-status', 'selection-count', 'delete-selected',
    'delete-from', 'delete-to', 'delete-range', 'keep-days', 'keep-recent', 'delete-conversation',
  ];
  for (const id of required) assert.equal(ids.filter((candidate) => candidate === id).length, 1, `${id} remains unique`);
  assert.ok(detail.indexOf('history-detail-header') < detail.indexOf('message-filter'));
  assert.ok(detail.indexOf('message-filter') < detail.indexOf('history-messages'));
  assert.ok(detail.indexOf('history-messages') < detail.indexOf('백업 및 복원'));
  assert.ok(detail.indexOf('백업 및 복원') < detail.indexOf('데이터 삭제 및 보관'));
  assert.match(detail, /현재 불러온 페이지의 메시지를 평문 텍스트 파일로 저장합니다\. 파일은 암호화되지 않습니다\./);
  assert.match(detail, /비밀번호는 선택 사항입니다/);
  assert.match(detail, /현재 페이지 검색/);
  assert.match(detail, /TXT 저장은 현재 페이지에만 적용됩니다/);
  assert.match(detail, /상대방 신원 정보 백업/);
  assert.match(detail, />보관 기간 외 삭제</);
  assert.equal((detail.match(/class="history-reprotect-steps"[\s\S]*?<\/div>/) || [''])[0].match(/<span>/g).length, 5);
  assert.match(detail, /id="keep-days"[^>]*value="3"/);
  assert.match(html, /#history-detail #history-messages\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(html, /#history-detail #history-messages\s*\{[^}]*max-height:\s*680px/s);
  assert.match(html, /@media\s*\(max-width:\s*680px\)[\s\S]*?\.history-tool-grid\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
  assert.match(html, /\.danger-button\s*\{[^}]*background:\s*var\(--danger\)/);
  assert.match(html, /<h2>접속 코드로 로그인<\/h2>\s*<form id="login-form">/);
  assert.doesNotMatch(html, /개인 접속 코드로 로그인하거나 새 코드를 생성하세요\./);
  assert.match(html, /다른 신원의 코드를 입력하면 해당 신원으로 로그인됩니다\./);
});

test('bundle export accepts 128 selections and rejects 129 before requesting a backup', async () => {
  const h = createHarness();
  const status = h.element('#management-history-status');
  h.element('#management-dialog').open = true;
  h.element('#management-history-pane').hidden = false;
  let count = 0;
  let confirmations = 0;
  h.element('#history-list').querySelectorAll = () =>
    Array.from({ length: count }, (_, index) => ({ dataset: { bundlePeerId: String(index) } }));
  h.window.confirm = () => { confirmations += 1; return false; };

  await h.click('#history-bundle-export');
  assert.equal(status.hidden, false);
  assert.match(status.textContent, /백업할 대화를 선택하세요/);
  assert.equal(h.element('#message').textContent, '');
  assert.equal(h.requests.some((request) => request.path === '/api/history/backup-transfer'), false);

  count = 128;
  await h.click('#history-bundle-export');
  assert.equal(confirmations, 1);

  count = 129;
  await h.click('#history-bundle-export');
  assert.equal(confirmations, 1);
  assert.match(status.textContent, /최대 128개/);
  assert.equal(h.element('#message').textContent, '');
  assert.equal(h.requests.some((request) => request.path === '/api/history/backup-transfer'), false);

  const html = pageSource();
  const historyPane = html.slice(html.indexOf('id="management-history-pane"'), html.indexOf('</dialog>', html.indexOf('id="management-history-pane"')));
  assert.match(historyPane, /id="management-history-status"[^>]*role="status"[^>]*aria-live="polite"/);
});

test('bundle export success and failure are announced inside the open history dialog', async () => {
  for (const [options, expected] of [
    [{}, /1개 대화의 암호화 백업을 저장했습니다/],
    [{ bundleExportReject: true }, /대화 백업을 만들거나 저장하지 못했습니다/],
  ]) {
    const h = createHarness(options);
    h.element('#management-dialog').open = true;
    h.element('#management-history-pane').hidden = false;
    h.element('#history-list').querySelectorAll = () => [{ dataset: { bundlePeerId: 'peer-one' } }];
    h.window.confirm = () => true;
    h.window.showSaveFilePicker = async () => ({
      createWritable: async () => ({ write: async () => {}, close: async () => {}, abort: async () => {} }),
    });

    await h.click('#history-bundle-export');

    assert.equal(h.element('#management-history-status').hidden, false);
    assert.match(h.element('#management-history-status').textContent, expected);
    assert.equal(h.element('#message').textContent, '');
    assert.ok(h.requests.some((request) => request.path === '/api/history/backup-transfer'));
  }
});

test('opening history refreshes records created after the last list load and preserves pending notices', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const initial = h.evaluate('refreshHistoryList()');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await initial;
  assert.match(h.element('#history-list').children[0].textContent, /저장된 대화가 없습니다/);

  // Model a conversation being written after the login-time empty list.
  h.evaluate("pendingManagementHistoryNotices.push({ identityId: 'identity-A', text: '복원이 완료됐습니다.', refreshList: false })");
  await h.click('#menu-open-history');
  const reopened = await waitForRequest(() => h.requests.filter(item => item.path === '/api/history/list').at(-1));
  assert.match(h.element('#management-history-status').textContent, /복원이 완료됐습니다/);
  reopened.resolve(response(JSON.stringify([historySummary('peer-created-during-chat')])));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(h.element('#history-list').children.length, 1);
  assert.equal(h.element('#history-list').children[0].children[1].dataset.peerId, 'peer-created-during-chat');
  assert.match(h.element('#management-history-status').textContent, /복원이 완료됐습니다/);
});

test('a history list response from the prior identity cannot replace the newly opened identity list', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await h.click('#menu-open-history');
  const requestA = await waitForRequest(() => h.requests.filter(item => item.path === '/api/history/list').at(-1));

  h.evaluate("identitySessionGeneration += 1; identityId.textContent = 'identity-B'; token = 'session-B'");
  await h.click('#menu-open-history');
  const requestB = await waitForRequest(() => h.requests.filter(item => item.path === '/api/history/list').at(-1));
  requestB.resolve(response(JSON.stringify([historySummary('peer-identity-B')])));
  await new Promise((resolve) => setImmediate(resolve));
  requestA.resolve(response(JSON.stringify([historySummary('peer-identity-A')])));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(h.element('#history-list').children.length, 1);
  assert.equal(h.element('#history-list').children[0].children[1].dataset.peerId, 'peer-identity-B');
});

test('opening a conversation reports HTTP and network errors inside the history dialog', async () => {
  for (const [status, reject, expected] of [
    [500, false, /대화 기록을 열지 못했습니다/],
    [409, false, /기록이 바뀌어 선택을 적용할 수 없습니다/],
    [0, true, /대화 기록을 열지 못했습니다/],
  ]) {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
    const listing = h.evaluate('refreshHistoryList()');
    await new Promise((resolve) => setImmediate(resolve));
    h.requestFor('/api/history/list').resolve(response(JSON.stringify([historySummary('peer-history-error')])));
    await listing;
    h.element('#management-dialog').open = true;
    h.element('#management-history-pane').hidden = false;

    const row = h.element('#history-list').children[0];
    const open = row.children[1].listeners.click();
    const request = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/history/messages'));
    if (reject) request.reject(new Error('connection lost'));
    else request.resolve(response('', status));
    await open;
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(h.element('#management-dialog').open, true);
    assert.equal(h.element('#management-history-status').hidden, false);
    assert.match(h.element('#management-history-status').textContent, expected);
    assert.equal(h.element('#message').textContent, '');
  }
});

test('detail page HTTP errors stay on the detail screen and stale management errors are discarded', async () => {
  const detail = createHarness();
  detail.evaluate("identityId.textContent = 'identity-A'; selectedHistoryPeer = 'peer-detail'; historyCursorStack = [null]");
  const loading = detail.evaluate('loadHistoryPage(null)');
  await new Promise((resolve) => setImmediate(resolve));
  detail.requestFor('/api/history/messages').resolve(response('', 500));
  await loading;
  assert.match(detail.element('#message').textContent, /대화 기록을 열지 못했습니다/);

  const stale = createHarness();
  stale.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const listing = stale.evaluate('refreshHistoryList()');
  await new Promise((resolve) => setImmediate(resolve));
  stale.requestFor('/api/history/list').resolve(response(JSON.stringify([historySummary('peer-stale-error')])));
  await listing;
  stale.element('#management-dialog').open = true;
  stale.element('#management-history-pane').hidden = false;
  stale.element('#history-list').children[0].children[1].listeners.click();
  const request = await waitForRequest(() => stale.requests.findLast((item) => item.path === '/api/history/messages'));
  stale.evaluate("identitySessionGeneration += 1; identityId.textContent = 'identity-B'; token = 'session-B'");
  request.resolve(response('', 500));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(stale.element('#management-history-status').textContent, '');
  assert.equal(stale.element('#message').textContent, '');
});

test('closing and reopening management invalidates an older conversation open', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const listing = h.evaluate('refreshHistoryList()');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response(JSON.stringify([historySummary('peer-old-open')])));
  await listing;
  h.element('#management-dialog').open = true;
  h.element('#management-history-pane').hidden = false;

  h.element('#history-list').children[0].children[1].listeners.click();
  const request = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/history/messages'));
  await h.click('#close-management-dialog');
  await h.click('#menu-open-history');
  request.resolve(response('', 500));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(h.element('#management-dialog').open, true);
  assert.equal(h.element('#management-history-pane').hidden, false);
  assert.equal(h.element('#management-history-status').textContent, '');
  assert.equal(h.element('#message').textContent, '');
});

test('the latest conversation selection wins when an older messages response arrives last', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const listing = h.evaluate('refreshHistoryList()');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response(JSON.stringify([
    historySummary('peer-A'), historySummary('peer-B'),
  ])));
  await listing;
  h.element('#management-dialog').open = true;
  h.element('#management-history-pane').hidden = false;
  const [rowA, rowB] = h.element('#history-list').children;

  rowA.children[1].listeners.click();
  const requestA = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/history/messages'));
  rowB.children[1].listeners.click();
  const requestB = await waitForRequest(() => h.requests.filter((item) => item.path === '/api/history/messages').at(-1));
  requestB.resolve(response(JSON.stringify({
    version: 'B-v1', hasMore: false, nextCursor: null,
    messages: [{ index: 1, time: 1, sender: '상대방', text: 'B message' }],
  })));
  await new Promise((resolve) => setImmediate(resolve));
  requestA.resolve(response('', 500));
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(h.evaluate('selectedHistoryPeer'), 'peer-B');
  assert.equal(h.element('#history-detail').hidden, false);
  assert.equal(h.evaluate('selectedHistoryMessages[0].text'), 'B message');
  assert.equal(h.element('#management-history-status').textContent, '');
});

test('late bundle export and contact import results do not overwrite a new pane or input', async () => {
  const bundle = createHarness({ manualBundleExport: true });
  bundle.element('#management-dialog').open = true;
  bundle.element('#management-history-pane').hidden = false;
  bundle.element('#history-list').querySelectorAll = () => [{ dataset: { bundlePeerId: 'peer-export' } }];
  bundle.window.confirm = () => true;
  bundle.window.showSaveFilePicker = async () => ({
    createWritable: async () => ({ write: async () => {}, close: async () => {}, abort: async () => {} }),
  });
  const exporting = bundle.click('#history-bundle-export');
  const exportRequest = await waitForRequest(() => bundle.requestForAction('bundle-export'));
  await bundle.click('#close-management-dialog');
  await bundle.click('#menu-open-settings');
  bundle.addTransferFile('late-export', 'backup');
  exportRequest.resolve(response(JSON.stringify({ transferId: 'late-export', size: 6 })));
  await exporting;
  assert.equal(bundle.element('#management-dialog-title').textContent, '연결 설정');
  assert.equal(bundle.element('#management-history-status').textContent, '');
  assert.equal(bundle.element('#message').textContent, '');
  await bundle.click('#menu-open-history');
  assert.match(bundle.element('#management-history-status').textContent, /암호화 백업을 저장했습니다/);

  const failedBundle = createHarness({ manualBundleExport: true });
  failedBundle.element('#management-dialog').open = true;
  failedBundle.element('#management-history-pane').hidden = false;
  failedBundle.element('#history-list').querySelectorAll = () => [{ dataset: { bundlePeerId: 'peer-export' } }];
  failedBundle.window.confirm = () => true;
  failedBundle.window.showSaveFilePicker = async () => ({
    createWritable: async () => ({ write: async () => {}, close: async () => {}, abort: async () => {} }),
  });
  const failedExporting = failedBundle.click('#history-bundle-export');
  const failedExportRequest = await waitForRequest(() => failedBundle.requestForAction('bundle-export'));
  await failedBundle.click('#close-management-dialog');
  failedExportRequest.reject(new Error('server unavailable'));
  await failedExporting;
  assert.equal(failedBundle.element('#message').textContent, '');
  await failedBundle.click('#menu-open-history');
  assert.match(failedBundle.element('#management-history-status').textContent, /대화 백업을 만들거나 저장하지 못했습니다/);

  const picker = createHarness();
  const pickerOpened = deferred();
  const pickerResult = deferred();
  picker.element('#management-dialog').open = true;
  picker.element('#management-history-pane').hidden = false;
  picker.element('#history-list').querySelectorAll = () => [{ dataset: { bundlePeerId: 'peer-export' } }];
  picker.window.confirm = () => true;
  picker.window.showSaveFilePicker = () => { pickerOpened.resolve(); return pickerResult.promise; };
  const pickerExport = picker.click('#history-bundle-export');
  await pickerOpened.promise;
  await picker.click('#close-management-dialog');
  pickerResult.resolve({ createWritable: async () => ({ write: async () => {}, close: async () => {}, abort: async () => {} }) });
  await pickerExport;
  assert.equal(picker.requestForAction('bundle-export'), undefined);
  assert.equal(picker.element('#message').textContent, '');

  const contact = createHarness();
  contact.element('#management-dialog').open = true;
  contact.element('#management-history-pane').hidden = false;
  const fileInput = contact.element('#contact-file');
  fileInput.value = 'first.adcontact';
  fileInput.files = [{ size: 1, arrayBuffer: async () => Uint8Array.of(1).buffer }];
  const importing = contact.click('#contact-import');
  const importRequest = await waitForRequest(() => contact.requests.findLast((item) => item.path === '/api/contacts/import-backup'));
  await contact.click('#menu-open-identity');
  fileInput.value = 'new-selection.adcontact';
  importRequest.resolve(response('ok'));
  await importing;
  assert.equal(contact.element('#management-dialog-title').textContent, '신원 관리');
  assert.equal(fileInput.value, 'new-selection.adcontact');
  assert.equal(contact.element('#management-history-status').textContent, '');
  assert.equal(contact.element('#message').textContent, '');
  await contact.click('#menu-open-history');
  assert.match(contact.element('#management-history-status').textContent, /상대방 신원 정보를 복원했습니다/);

  const switched = createHarness();
  switched.element('#management-dialog').open = true;
  switched.element('#management-history-pane').hidden = false;
  switched.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const switchedInput = switched.element('#contact-file');
  switchedInput.value = 'identity-A.adcontact';
  switchedInput.files = [{ size: 1, arrayBuffer: async () => Uint8Array.of(1).buffer }];
  const switchedImport = switched.click('#contact-import');
  const switchedRequest = await waitForRequest(() => switched.requests.findLast((item) => item.path === '/api/contacts/import-backup'));
  switched.evaluate("identitySessionGeneration += 1; identityId.textContent = 'identity-B'; token = 'session-B'");
  switchedRequest.resolve(response('ok'));
  await switchedImport;
  assert.equal(switched.element('#management-history-status').textContent, '');
  assert.equal(switched.element('#message').textContent, '');
  assert.equal(switchedInput.value, 'identity-A.adcontact');
  await switched.click('#close-management-dialog');
  await switched.click('#menu-open-history');
  assert.equal(switched.element('#management-history-status').textContent, '');
  switched.evaluate("identitySessionGeneration += 1; identityId.textContent = 'identity-A'; token = 'session-A-again'");
  await switched.click('#close-management-dialog');
  await switched.click('#menu-open-history');
  assert.match(switched.element('#management-history-status').textContent, /상대방 신원 정보를 복원했습니다/);

  const overlapping = createHarness();
  overlapping.element('#management-dialog').open = true;
  overlapping.element('#management-history-pane').hidden = false;
  const overlappingInput = overlapping.element('#contact-file');
  overlappingInput.value = 'older.adcontact';
  overlappingInput.files = [{ size: 1, arrayBuffer: async () => Uint8Array.of(1).buffer }];
  const olderImport = overlapping.click('#contact-import');
  const olderRequest = await waitForRequest(() => overlapping.requests.findLast((item) => item.path === '/api/contacts/import-backup'));
  overlappingInput.value = 'newer.adcontact';
  const newerImport = overlapping.click('#contact-import');
  const newerRequest = await waitForRequest(() => {
    const requests = overlapping.requests.filter((item) => item.path === '/api/contacts/import-backup');
    return requests.length > 1 ? requests.at(-1) : null;
  });
  olderRequest.resolve(response('ok'));
  await olderImport;
  assert.equal(overlappingInput.value, 'newer.adcontact');
  assert.equal(overlapping.element('#management-history-status').textContent, '');
  newerRequest.resolve(response('ok'));
  const refreshedList = await waitForRequest(() => overlapping.requests.filter((item) => item.path === '/api/history/list').at(-1));
  refreshedList.resolve(response('[]'));
  await newerImport;
  assert.equal(overlappingInput.value, '');
  assert.match(overlapping.element('#management-history-status').textContent, /상대방 신원 정보를 복원했습니다/);
});

test('whole-conversation deletion remains explicitly confirmed and locally scoped', async () => {
  const h = createHarness();
  let prompt = '';
  h.window.confirm = (value) => { prompt = value; return false; };
  h.evaluate("selectedHistoryPeer = 'peer-to-delete'");
  await h.click('#delete-conversation');
  assert.match(prompt, /이 대화의 모든 기록을 이 기기에서 삭제할까요\?/);
  assert.match(prompt, /상대방 기록과 백업은 삭제되지 않습니다/);
  assert.equal(h.requests.some((item) => item.path === '/api/history/delete-conversation'), false);
});

async function chooseSource(harness, sourceHandle) {
  const picker = deferred();
  harness.window.showOpenFilePicker = () => picker.promise;
  const task = harness.click('#history-reprotect-choose');
  picker.resolve([sourceHandle]);
  await task;
}

function sourceHandle(name, contents) {
  const entry = { name, file: file(name, contents) };
  entry.getFile = async () => entry.file;
  entry.isSameEntry = async (other) => other === entry;
  return entry;
}

function reprotectResponse(harness, encoded, transferId = `result-${harness.requests.length}`) {
  const bytes = Buffer.from(encoded, 'base64');
  harness.addTransferFile(transferId, bytes);
  return response(JSON.stringify({ transferId, size: bytes.length, messageCount: 1 }));
}

function enterSecrets(harness, suffix) {
  harness.element('#history-reprotect-previous-code').value = `code-${suffix}`;
  harness.element('#history-reprotect-previous-password').value = `old-${suffix}`;
  harness.element('#history-reprotect-new-password').value = `replacement-${suffix}-secret`;
  harness.element('#history-reprotect-new-password-confirm').value = `replacement-${suffix}-secret`;
}

test('actual UI: dark is the default and theme selection persists across reloads', async () => {
  const themeStorage = new Map();
  const first = createHarness({ themeStorage });
  assert.equal(first.document.documentElement.dataset.theme, 'dark');
  first.element('#bridge-code').value = 'local-connection-code';
  first.element('#identity-code').value = 'private-identity-code';
  first.element('#created-note').textContent = '코드 생성 상태';
  await first.click('#theme-toggle');
  assert.equal(first.document.documentElement.dataset.theme, 'light');
  assert.equal(first.element('#theme-toggle').textContent, '다크 모드');
  assert.equal(themeStorage.get('another-dimension-theme'), 'light');
  assert.equal(first.element('#bridge-code').value, 'local-connection-code');
  assert.equal(first.element('#identity-code').value, 'private-identity-code');
  assert.equal(first.element('#created-note').textContent, '코드 생성 상태');

  const reopened = createHarness({ themeStorage });
  assert.equal(reopened.document.documentElement.dataset.theme, 'light');
  assert.equal(reopened.element('#theme-toggle').textContent, '다크 모드');
  await reopened.click('#theme-toggle');
  assert.equal(reopened.document.documentElement.dataset.theme, 'dark');
  assert.equal(themeStorage.get('another-dimension-theme'), 'dark');
});

test('actual UI: request A then B, and B completes before A', async () => {
  const h = createHarness();
  const original = sourceHandle('source.adbak', 'encrypted-source');
  await chooseSource(h, original);
  enterSecrets(h, 'A');
  const taskA = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const requestA = h.requestForAction('reprotect');
  assert.equal(JSON.parse(requestA.init.body).previousCode, 'code-A');
  assert.deepEqual([
    h.element('#history-reprotect-previous-code').value,
    h.element('#history-reprotect-previous-password').value,
    h.element('#history-reprotect-new-password').value,
    h.element('#history-reprotect-new-password-confirm').value,
  ], ['', '', '', '']);

  enterSecrets(h, 'B');
  const taskB = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const requestB = h.requests.filter((item) => item.path === '/api/history/backup-transfer' && JSON.parse(item.init.body).action === 'reprotect')[1];
  requestB.resolve(reprotectResponse(h, 'QmFja3VwQg==', 'result-B'));
  await taskB;
  assert.equal(h.element('#history-reprotect-save').disabled, false);
  assert.match(h.element('#message').textContent, /새 백업을 만들었습니다/);

  requestA.resolve(reprotectResponse(h, 'QmFja3VwQQ==', 'result-A'));
  await taskA;
  assert.equal(h.element('#history-reprotect-save').disabled, false);

  const output = createOutputHandle();
  let pickerOptions;
  h.window.showSaveFilePicker = async (options) => { pickerOptions = options; return output; };
  const saveTask = h.click('#history-reprotect-save');
  await new Promise((resolve) => setImmediate(resolve));
  const verifyRequest = h.requestForAction('verify');
  assert.equal(JSON.parse(verifyRequest.init.body).password, 'replacement-B-secret');
  await saveTask;
  assert.equal(pickerOptions.suggestedName, 'source.new-identity.adbak');
  assert.equal(output.written, 'BackupB');
  assert.equal(output.closed, true);
  assert.equal(h.element('#history-reprotect-source').textContent, '선택한 파일 없음');
  assert.equal(h.element('#history-reprotect-save').disabled, true);
  assert.equal(original.file.dataUrl, file('source.adbak', 'encrypted-source').dataUrl);
});

test('backup restore asks before applying authenticated linked identity data', async () => {
  const h = createHarness();
  h.element('#history-backup-file').files = [file('linked.adbak', 'ADBACK5\0payload')];
  h.element('#history-backup-import-password').value = 'long-enough-password';
  let prompt = '';
  h.window.confirm = (message) => { prompt = message; return false; };
  await h.click('#history-backup-import');
  assert.match(prompt, /이전 신원 연결 정보/);
  assert.equal(h.requests.some((item) => item.path === '/api/history/backup-transfer' && JSON.parse(item.init.body).action === 'import'), false);
});

test('backup import result stays visible without hover or focus', () => {
  const html = pageSource();
  assert.match(html, /<div id="history-backup-import-result" class="history-import-result" role="status" aria-live="polite" hidden><\/div>/);
  assert.match(html, /\.history-import-result\s*\{[^}]*display:\s*block/);
  assert.match(html, /\.history-import-result\[hidden\]\s*\{\s*display:\s*none\s*!important;/);
  assert.doesNotMatch(html, /\.history-import-action:(?:hover|focus-within).*history-import-result/);
  assert.doesNotMatch(html, /\.history-import-result:not\(\[hidden\]\)\s*\{\s*display:\s*none/);
});

test('backup import keeps a general server failure detail in the result region', async () => {
  const detail = 'backup authentication failed: invalid password';
  const h = createHarness({ importFailure: detail });
  h.evaluate("selectedHistoryPeer = '89'.repeat(32)");
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  await task;
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'failure');
  assert.match(h.element('#history-backup-import-result').textContent, /백업 가져오기 실패/);
  assert.ok(h.element('#history-backup-import-result').textContent.includes(detail));
  assert.doesNotMatch(h.element('#history-backup-import-result').textContent, /대화 898989898989/);
});

test('legacy streaming backup formats warn about their integrity and privacy limits', async () => {
  for (const magic of ['ADBACK6\0', 'ADPACK2\0']) {
    const h = createHarness();
    h.element('#history-backup-file').files = [file('legacy.adbak', `${magic}payload`)];
    let warning = '';
    h.window.confirm = (text) => { warning = text; return false; };
    await h.click('#history-backup-import');
    assert.match(warning, /이전 형식/);
    if (magic === 'ADBACK6\0') assert.match(warning, /상대 공개 ID가 평문/);
    else assert.match(warning, /묶음 인증이 없습니다/);
    assert.equal(h.requests.some((item) => item.path === '/api/history/backup-transfer'
      && JSON.parse(item.init.body).action === 'upload-start'), false);
  }
});

test('backup import presents the server-reported partial bundle count', async () => {
  const detail = 'backup bundle failed after applying 1 conversation(s): backup bundle authentication failed';
  const h = createHarness({ importFailure: detail });
  const original = file('bundle.adpak', 'ADPACK3\0payload');
  h.element('#history-backup-file').files = [original];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  const listRequest = h.requestFor('/api/history/list');
  assert.ok(listRequest, 'partial application refreshes the conversation list');
  listRequest.resolve(response(JSON.stringify([{
    peerId: 'cd'.repeat(32), messageCount: 3, lastMessage: 1234, verified: true,
  }])));
  await task;
  assert.equal(h.element('#message').textContent, `${detail} 적용된 대화 ID는 오류 응답에 없어 특정할 수 없습니다. 기록 목록을 새로고침해 적용된 대화를 확인하고, 원본 백업 파일은 보관하세요. 미적용 대화만 선택해 재시도하는 기능은 없습니다.`);
  assert.match(h.element('#history-backup-import-result').textContent, /^백업 가져오기 실패/);
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'failure');
  assert.equal(h.element('#history-backup-import-result').hidden, false);
  assert.ok(h.element('#history-backup-import-result').textContent.includes(detail));
  assert.match(h.element('#history-backup-import-result').textContent, /기록 목록을 새로고침해 적용된 대화를 확인/);
  assert.match(h.element('#history-backup-import-result').textContent, /원본 백업 파일은 보관/);
  assert.match(h.element('#history-backup-import-result').textContent, /적용된 대화 ID는 오류 응답에 없어 특정할 수 없습니다/);
  assert.equal(h.element('#history-list').children.length, 1);
  assert.equal(h.element('#history-list').children[0].children[1].children[0].textContent, '대화 cdcdcdcdcdcd');
  assert.equal(h.element('#history-backup-file').files[0], original);
});

test('partial import error remains visible when the follow-up list request or rendering fails', async (t) => {
  for (const mode of ['list request failure', 'list rendering failure']) {
    await t.test(mode, async () => {
      const detail = 'backup bundle failed after applying 2 conversation(s): disk write failed';
      const h = createHarness({ importFailure: detail });
      h.element('#history-backup-file').files = [file('bundle.adpak', 'ADPACK3\0payload')];
      h.window.confirm = () => true;
      if (mode === 'list rendering failure') {
        h.element('#history-list').append = () => { throw new Error('render failed'); };
      }
      const task = h.click('#history-backup-import');
      await new Promise((resolve) => setImmediate(resolve));
      h.requestFor('/api/history/list').resolve(mode === 'list request failure'
        ? response('unavailable', 500)
        : response(JSON.stringify([{ peerId: 'ef'.repeat(32), messageCount: 4, verified: false }])));
      await task;
      assert.match(h.element('#message').textContent, /backup bundle failed after applying 2 conversation\(s\): disk write failed/);
      assert.match(h.element('#message').textContent, /기록 목록을 새로고침해 적용된 대화를 확인/);
      assert.equal(h.element('#history-backup-import-result').dataset.result, 'failure');
      assert.ok(h.element('#history-backup-import-result').textContent.includes(detail));
      assert.match(h.element('#history-backup-import-result').textContent, /기록 목록을 새로고침해 적용된 대화를 확인/);
      assert.equal(h.element('#history-backup-file').files[0].name, 'bundle.adpak');
    });
  }
});

test('completed import with upload cleanup failure refreshes the list and explains manual cleanup', async () => {
  const detail = 'backup import completed but temporary upload cleanup failed (permission denied)';
  const h = createHarness({ importFailure: detail });
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const original = h.element('#history-backup-file').files[0];
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  const listRequest = h.requestFor('/api/history/list');
  assert.ok(listRequest, 'completed import still refreshes conversation history');
  listRequest.resolve(response(JSON.stringify([{ peerId: '12'.repeat(32), messageCount: 6, verified: true }])));
  await task;
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'cleanup-warning');
  assert.match(h.element('#history-backup-import-result').textContent, /^가져오기 완료 · 임시 파일 정리 실패/);
  assert.ok(h.element('#history-backup-import-result').textContent.includes(detail));
  assert.match(h.element('#history-backup-import-result').textContent, /기록 목록에서 가져온 대화를 확인하세요/);
  assert.match(h.element('#history-backup-import-result').textContent, /적용된 대화 ID는 응답에 없어 특정할 수 없습니다/);
  assert.match(h.element('#history-backup-import-result').textContent, /README의 수동 정리 안내/);
  assert.match(h.element('#message').textContent, /backup import completed but temporary upload cleanup failed/);
  assert.match(h.element('#message').textContent, /기록 목록에서 가져온 대화를 확인하세요/);
  assert.match(h.element('#message').textContent, /앱을 모두 종료한 뒤 README의 수동 정리 안내/);
  assert.equal(h.element('#history-list').children[0].children[1].children[0].textContent, '대화 121212121212');
  assert.equal(h.element('#history-backup-file').files[0], original);
});

test('backup import distinguishes an unconfirmed server result from pre-request upload failure', async (t) => {
  for (const outcome of ['fetch rejected after import request', 'response body unreadable']) {
    await t.test(outcome, async () => {
      const h = createHarness(outcome === 'fetch rejected after import request'
        ? { importFetchReject: true }
        : { importTextReject: true });
      h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK4\0payload')];
      const task = h.click('#history-backup-import');
      const importRequest = await waitForRequest(() => h.requestForAction('import'));
      assert.ok(importRequest);
      const listRequest = await waitForRequest(() => h.requestFor('/api/history/list'));
      listRequest.resolve(response('[]'));
      await task;
      assert.equal(h.element('#history-backup-import-result').dataset.result, 'unknown');
      assert.match(h.element('#history-backup-import-result').textContent, /가져오기 결과 확인 필요/);
      assert.match(h.element('#history-backup-import-result').textContent, /가져오기 요청을 보낸 뒤 결과와 적용 대상 대화를 확인하지 못했습니다/);
      assert.match(h.element('#history-backup-import-result').textContent, /기록 목록을 새로고침해 적용 여부를 확인/);
      assert.match(h.element('#history-backup-import-result').textContent, /원본 백업 파일은 보관/);
      assert.match(h.element('#message').textContent, /가져오기 요청을 보낸 뒤 결과와 적용 대상 대화를 확인하지 못했습니다/);
      assert.match(h.element('#message').textContent, /기록 목록을 새로고침해 적용 여부를 확인/);
      assert.match(h.element('#message').textContent, /원본 백업 파일은 보관/);
      assert.doesNotMatch(h.element('#message').textContent, /기존 기록과 선택한 원본 파일은 보존됩니다/);
      assert.equal(h.element('#history-backup-file').files[0].name, 'backup.adbak');
    });
  }

  await t.test('upload fails before import was sent', async () => {
    const h = createHarness({ uploadChunkReject: true });
    h.element('#history-backup-file').files = [file('large.adbak', `ADBACK4\0${'x'.repeat(300000)}`)];
    const task = h.click('#history-backup-import');
    await task;
    assert.equal(h.requestForAction('import'), undefined);
    assert.equal(h.element('#history-backup-import-result').dataset.result, 'failure');
    assert.match(h.element('#history-backup-import-result').textContent, /가져오기 요청 전에 백업 파일을 읽거나 업로드하지 못했습니다/);
    assert.match(h.element('#message').textContent, /가져오기 요청 전에 백업 파일을 읽거나 업로드하지 못했습니다/);
    assert.match(h.element('#message').textContent, /기록 가져오기는 시작되지 않았으며/);
    assert.doesNotMatch(h.element('#message').textContent, /기존 기록과 선택한 원본 파일은 보존됩니다/);
  });
});

test('a partial import list response from the previous identity cannot replace the new identity list', async () => {
  const detail = 'backup bundle failed after applying 1 conversation(s): linked identity store failed';
  const h = createHarness({ importFailure: detail });
  h.element('#identity-id').textContent = 'identity-a';
  h.element('#history-backup-file').files = [file('bundle.adpak', 'ADPACK3\0payload')];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  const listRequest = h.requestFor('/api/history/list');
  assert.ok(listRequest);
  h.element('#identity-id').textContent = 'identity-b';
  h.element('#message').textContent = '신원 B의 화면 상태';
  h.element('#history-backup-import-result').hidden = true;
  h.element('#history-backup-import-result').textContent = '';
  const newIdentityRow = { textContent: '신원 B의 대화 목록' };
  h.element('#history-list').replaceChildren(newIdentityRow);
  listRequest.resolve(response(JSON.stringify([{ peerId: '34'.repeat(32), messageCount: 1, verified: true }])));
  await task;
  assert.equal(h.element('#message').textContent, '신원 B의 화면 상태');
  assert.deepEqual(h.element('#history-list').children, [newIdentityRow]);
  assert.equal(h.element('#history-backup-import-result').hidden, true);
});

test('successful import list refresh from A cannot update B or a later A session', async () => {
  const h = createHarness({ manualImport: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.element('#history-backup-file').files = [file('bundle.adpak', 'ADPACK3\0payload')];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  const importRequest = await waitForRequest(() => h.requestForAction('import'));
  importRequest.resolve(response(JSON.stringify({ conversations: [] })));
  const delayedAList = await waitForRequest(() => h.requestFor('/api/history/list'));
  assert.equal(h.element('#history-backup-import-result').hidden, true);

  await refreshHarnessAs(h, 'identity-B', [historySummary('b1'.repeat(32), 2)]);
  assert.match(h.element('#history-list').children[0].children[1].children[0].textContent, /^대화 b1/);
  await refreshHarnessAs(h, 'identity-A', [historySummary('a2'.repeat(32), 3)]);
  h.element('#message').textContent = '새 A 세션의 안내';
  h.element('#history-backup-import-result').textContent = '새 A 세션의 가져오기 상태';
  h.element('#history-backup-import-result').hidden = false;
  delayedAList.resolve(response(JSON.stringify([historySummary('a1'.repeat(32), 99)])));
  await task;

  assert.equal(h.element('#identity-id').textContent, 'identity-A');
  assert.equal(h.element('#message').textContent, '새 A 세션의 안내');
  assert.equal(h.element('#history-backup-import-result').textContent, '새 A 세션의 가져오기 상태');
  assert.match(h.element('#history-list').children[0].children[1].children[0].textContent, /^대화 a2/);
});

test('logout and relogin to the same identity invalidate an older import response', async () => {
  const h = createHarness({ manualImport: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.element('#history-backup-file').files = [file('single.adbak', 'ADBACK4\0payload')];
  h.element('#history-backup-file').value = 'C:\\fakepath\\single.adbak';
  h.element('#history-backup-import-password').value = 'older-password-long';
  const oldImport = h.click('#history-backup-import');
  const delayedImport = await waitForRequest(() => h.requestForAction('import'));

  await h.click('#logout');
  assert.equal(h.element('#history-backup-import-result').hidden, true);
  assert.equal(h.element('#history-backup-import-result').textContent, '');
  assert.equal(h.element('#history-backup-import-result').dataset.result, undefined);
  assert.equal(h.element('#history-backup-file').value, '');
  assert.deepEqual(h.element('#history-backup-file').files, []);
  assert.equal(h.element('#history-backup-import-password').value, '');
  await refreshHarnessAs(h, 'identity-A', [historySummary('a3'.repeat(32), 4)]);
  h.element('#message').textContent = '재로그인한 A의 안내';
  h.element('#history-backup-import-result').textContent = '재로그인한 A의 상태';
  h.element('#history-backup-import-result').hidden = false;
  h.element('#history-backup-file').value = 'C:\\fakepath\\new-session.adbak';
  h.element('#history-backup-file').files = [file('new-session.adbak', 'ADBACK4\0new')];
  h.element('#history-backup-import-password').value = 'new-session-password';
  delayedImport.resolve(response(JSON.stringify({ conversations: [] })));
  await oldImport;

  assert.equal(h.element('#message').textContent, '재로그인한 A의 안내');
  assert.equal(h.element('#history-backup-import-result').textContent, '재로그인한 A의 상태');
  assert.equal(h.element('#history-backup-file').value, 'C:\\fakepath\\new-session.adbak');
  assert.equal(h.element('#history-backup-import-password').value, 'new-session-password');
  assert.match(h.element('#history-list').children[0].children[1].children[0].textContent, /^대화 a3/);
});

test('switching identities clears the prior backup import result, selected file, and password', async () => {
  const h = createHarness({ importFailure: 'backup authentication failed: invalid password' });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  const original = file('private-a.adbak', 'ADBACK7\0payload');
  h.element('#history-backup-file').files = [original];
  h.element('#history-backup-file').value = 'C:\\fakepath\\private-a.adbak';
  h.element('#history-backup-import-password').value = 'password-for-a-session';
  h.window.confirm = () => true;
  await h.click('#history-backup-import');
  const result = h.element('#history-backup-import-result');
  assert.equal(result.dataset.result, 'failure');
  assert.ok(result.textContent.includes('invalid password'));

  h.element('#history-backup-file').files = [original];
  h.element('#history-backup-file').value = 'C:\\fakepath\\private-a.adbak';
  h.element('#history-backup-import-password').value = 'password-for-a-session';
  await refreshHarnessAs(h, 'identity-B', [historySummary('b4'.repeat(32), 2)]);

  assert.equal(result.hidden, true);
  assert.equal(result.textContent, '');
  assert.equal(result.dataset.result, undefined);
  assert.equal(h.element('#history-backup-file').value, '');
  assert.deepEqual(h.element('#history-backup-file').files, []);
  assert.equal(h.element('#history-backup-import-password').value, '');
});

test('a pending import response from A cannot change B backup state', async () => {
  const h = createHarness({ manualImport: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.element('#history-backup-file').files = [file('a.adpak', 'ADPACK3\0payload')];
  h.element('#history-backup-import-password').value = 'password-for-identity-a';
  h.window.confirm = () => true;
  const importA = h.click('#history-backup-import');
  const delayedA = await waitForRequest(() => h.requestForAction('import'));

  await refreshHarnessAs(h, 'identity-B', [historySummary('b5'.repeat(32), 1)]);
  h.element('#history-backup-import-result').dataset.result = 'failure';
  h.element('#history-backup-import-result').textContent = 'B의 새 가져오기 결과';
  h.element('#history-backup-import-result').hidden = false;
  h.element('#history-backup-file').value = 'C:\\fakepath\\b.adbak';
  h.element('#history-backup-file').files = [file('b.adbak', 'ADBACK7\0payload')];
  h.element('#history-backup-import-password').value = 'password-for-identity-b';

  delayedA.resolve(response(JSON.stringify({ conversations: [] })));
  await importA;

  assert.equal(h.element('#identity-id').textContent, 'identity-B');
  assert.equal(h.element('#history-backup-import-result').textContent, 'B의 새 가져오기 결과');
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'failure');
  assert.equal(h.element('#history-backup-file').value, 'C:\\fakepath\\b.adbak');
  assert.equal(h.element('#history-backup-file').files[0].name, 'b.adbak');
  assert.equal(h.element('#history-backup-import-password').value, 'password-for-identity-b');
});

test('same-identity history navigation does not clear the backup import result', async () => {
  const h = createHarness();
  const result = h.element('#history-backup-import-result');
  result.dataset.result = 'success';
  result.textContent = '백업 가져오기 성공. 2개 대화를 기록에 병합했습니다.';
  result.hidden = false;
  h.element('#history-backup-file').value = 'C:\\fakepath\\backup.adpak';
  h.element('#history-backup-file').files = [file('backup.adpak', 'ADPACK3\0payload')];
  h.element('#history-backup-import-password').value = 'same-identity-password';

  const open = h.evaluate("openHistory('ab'.repeat(32))");
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({ messages: [], version: 1, nextCursor: null })));
  assert.equal(await open, true);
  assert.equal(result.hidden, false);
  assert.equal(result.textContent, '백업 가져오기 성공. 2개 대화를 기록에 병합했습니다.');
  assert.equal(result.dataset.result, 'success');
});

test('local bridge disconnect clears backup import credentials and displayed outcome', async () => {
  const h = createHarness();
  const result = h.element('#history-backup-import-result');
  result.dataset.result = 'unknown';
  result.textContent = '가져오기 결과 확인 필요';
  result.hidden = false;
  h.element('#history-backup-file').value = 'C:\\fakepath\\backup.adpak';
  h.element('#history-backup-file').files = [file('backup.adpak', 'ADPACK3\0payload')];
  h.element('#history-backup-import-password').value = 'bridge-password';

  const disconnect = h.click('#disconnect');
  assert.equal(result.hidden, true);
  assert.equal(result.textContent, '');
  assert.equal(result.dataset.result, undefined);
  assert.equal(h.element('#history-backup-file').value, '');
  assert.deepEqual(h.element('#history-backup-file').files, []);
  assert.equal(h.element('#history-backup-import-password').value, '');
  h.requestFor('/api/disconnect').resolve(response('ok'));
  await disconnect;
});

test('a new bridge session clears backup import state before loading its identity', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-old'");
  const result = h.element('#history-backup-import-result');
  result.dataset.result = 'unknown';
  result.textContent = '가져오기 결과 확인 필요';
  result.hidden = false;
  h.element('#history-backup-file').value = 'C:\\fakepath\\backup.adpak';
  h.element('#history-backup-file').files = [file('backup.adpak', 'ADPACK3\0payload')];
  h.element('#history-backup-import-password').value = 'old-bridge-password';

  h.element('#bridge-code').value = 'temporary-test-bridge-code';
  const connect = h.element('#connect-form').listeners.submit({ preventDefault() {} });
  h.requestFor('/api/connect').resolve(response('bridge-session-new'));
  await waitForRequest(() => h.requestFor('/api/identity/status'));

  assert.equal(result.hidden, true);
  assert.equal(result.textContent, '');
  assert.equal(result.dataset.result, undefined);
  assert.equal(h.element('#history-backup-file').value, '');
  assert.deepEqual(h.element('#history-backup-file').files, []);
  assert.equal(h.element('#history-backup-import-password').value, '');

  h.requestFor('/api/identity/status').resolve(response('identity-B'));
  await waitForRequest(() => h.requestFor('/api/settings/get'));
  h.requestFor('/api/settings/get').resolve(response(JSON.stringify({
    savedMode: 'general', socks: null, activeMode: 'general', activeSocks: null,
    restartRequired: false, notifications: false,
    savedRelays: [], activeRelays: [],
  })));
  await waitForRequest(() => h.requestFor('/api/history/list'));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await connect;
  assert.equal(h.element('#identity-id').textContent, 'identity-B');
});

test('a superseded import cannot clear the newer import file or password', async () => {
  const h = createHarness({ manualImport: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.element('#history-backup-file').files = [file('older.adbak', 'ADBACK4\0older')];
  h.element('#history-backup-import-password').value = 'older-password-long';
  const olderTask = h.click('#history-backup-import');
  const olderRequest = await waitForRequest(() => h.requestForAction('import'));

  const newerFile = file('newer.adpak', 'ADPACK3\0newer');
  h.element('#history-backup-file').files = [newerFile];
  h.element('#history-backup-import-password').value = 'newer-password-long';
  h.window.confirm = () => true;
  const newerTask = h.click('#history-backup-import');
  const newerRequest = await waitForRequest(() => {
    const current = h.requestForAction('import');
    return current !== olderRequest ? current : null;
  });
  assert.notEqual(newerRequest, olderRequest);
  newerRequest.resolve(response(JSON.stringify({ conversations: [] })));
  (await waitForRequest(() => h.requestFor('/api/history/list'))).resolve(response('[]'));
  await newerTask;

  h.element('#history-backup-file').files = [file('next.adbak', 'ADBACK4\0next')];
  h.element('#history-backup-import-password').value = 'password-for-the-next-import';
  olderRequest.reject(new Error('older import response lost'));
  await olderTask;

  assert.equal(h.element('#history-backup-file').files[0].name, 'next.adbak');
  assert.equal(h.element('#history-backup-import-password').value, 'password-for-the-next-import');
  assert.match(h.element('#history-backup-import-result').textContent, /^백업 가져오기 성공/);
});

test('superseded upload cleanup uses the session that created its transfer', async () => {
  const h = createHarness({ manualUploadChunks: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.element('#history-backup-file').files = [file('large.adbak', `ADBACK4\0${'x'.repeat(300000)}`)];
  h.element('#history-backup-import-password').value = 'old-session-password';
  const task = h.click('#history-backup-import');
  const chunk = await waitForRequest(() => h.requestForAction('upload-chunk'));

  h.evaluate("token = 'bridge-session-B'; identitySessionGeneration += 1");
  h.element('#history-backup-import-password').value = 'new-session-password';
  chunk.resolve(response(JSON.stringify({ offset: 256 * 1024 })));
  await task;
  const cleanup = h.requestForAction('cleanup');
  assert.equal(cleanup.init.headers.Authorization, 'Bearer bridge-session-A');
  assert.equal(h.element('#history-backup-import-password').value, 'new-session-password');
  assert.equal(h.requestForAction('import'), undefined);
});

test('backup import exposes success on the import control after a successful response', async () => {
  const h = createHarness({ importResult: JSON.stringify({ conversations: [
    { peerId: 'ab'.repeat(32), messageCount: 2, linkedIdentityRestored: false },
    { peerId: 'cd'.repeat(32), messageCount: 3, linkedIdentityRestored: false },
  ] }) });
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK4\0payload')];
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await task;
  assert.match(h.element('#history-backup-import-result').textContent, /백업 가져오기 성공/);
  assert.match(h.element('#history-backup-import-result').textContent, /대화 묶음 전체 백업 2개를 기존 기록과 병합했습니다/);
  assert.match(h.element('#history-backup-import-result').textContent, /특정 대화가 아닌 묶음 전체에 대한 결과/);
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'success');
  assert.equal(h.element('#history-backup-import-result').hidden, false);
});

test('single-backup import success reports list refresh failure without changing import outcome', async () => {
  const peerId = '34'.repeat(32);
  const h = createHarness({ importResult: JSON.stringify({ peerId, linkedIdentityRestored: false }) });
  h.element('#history-backup-file').files = [file('single.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('temporarily unavailable', 500));
  await task;

  const result = h.element('#history-backup-import-result');
  assert.equal(result.dataset.result, 'success');
  assert.match(result.textContent, /백업 가져오기 성공/);
  assert.match(result.textContent, /가져온 대상: 대화 343434343434/);
  assert.match(result.textContent, /기록은 가져왔지만 대화 목록을 갱신하지 못했습니다/);
  assert.match(result.textContent, /기록 목록을 다시 불러와 확인/);
  assert.doesNotMatch(result.textContent, /백업 가져오기 실패|가져오기 결과 확인 필요/);
});

test('bundle import success reports failed or invalid JSON list refresh as a separate problem', async (t) => {
  for (const mode of ['request failure', 'invalid JSON']) {
    await t.test(mode, async () => {
      const h = createHarness({ importResult: JSON.stringify({ conversations: [
        { peerId: '56'.repeat(32), messageCount: 2, linkedIdentityRestored: false },
        { peerId: '78'.repeat(32), messageCount: 3, linkedIdentityRestored: false },
      ] }) });
      h.element('#history-backup-file').files = [file('bundle.adpak', 'ADPACK3\0payload')];
      h.window.confirm = () => true;
      const task = h.click('#history-backup-import');
      await new Promise((resolve) => setImmediate(resolve));
      const listing = h.requestFor('/api/history/list');
      if (mode === 'request failure') listing.reject(new Error('connection lost'));
      else listing.resolve(response('{ invalid json'));
      await task;

      const result = h.element('#history-backup-import-result');
      assert.equal(result.dataset.result, 'success');
      assert.match(result.textContent, /대화 묶음 전체 백업 2개를 기존 기록과 병합했습니다/);
      assert.match(result.textContent, /특정 대화가 아닌 묶음 전체에 대한 결과/);
      assert.match(result.textContent, /기록은 가져왔지만 대화 목록을 갱신하지 못했습니다/);
      assert.match(result.textContent, /기록 목록을 다시 불러와 확인/);
      assert.doesNotMatch(result.textContent, /백업 가져오기 실패|가져오기 결과 확인 필요/);
    });
  }
});

test('a newer import prevents an older list refresh failure from replacing its state', async () => {
  const h = createHarness({ manualImport: true });
  h.evaluate("identityId.textContent = 'identity-A'; token = 'bridge-session-A'");
  h.window.confirm = () => true;
  h.element('#history-backup-file').files = [file('older.adbak', 'ADBACK7\0older')];
  const olderTask = h.click('#history-backup-import');
  const olderRequest = await waitForRequest(() => h.requestForAction('import'));
  olderRequest.resolve(response(JSON.stringify({ peerId: 'ab'.repeat(32), linkedIdentityRestored: false })));
  await new Promise((resolve) => setImmediate(resolve));
  const olderListRequest = h.requestFor('/api/history/list');
  assert.ok(olderListRequest);

  const newerFile = file('newer.adpak', 'ADPACK3\0newer');
  h.element('#history-backup-file').files = [newerFile];
  h.element('#history-backup-import-password').value = 'new-import-password';
  const newerTask = h.click('#history-backup-import');
  const newerRequest = await waitForRequest(() => {
    const current = h.requestForAction('import');
    return current !== olderRequest ? current : null;
  });
  olderListRequest.resolve(response('list failed', 500));
  await olderTask;
  assert.equal(h.element('#history-backup-import-result').hidden, true);
  assert.equal(h.element('#history-backup-import-result').textContent, '');
  assert.equal(h.element('#history-backup-file').files[0].name, 'newer.adpak');
  assert.equal(h.element('#history-backup-import-password').value, 'new-import-password');

  newerRequest.resolve(response(JSON.stringify({ conversations: [
    { peerId: 'cd'.repeat(32), messageCount: 1, linkedIdentityRestored: false },
  ] })));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await newerTask;
  assert.equal(h.element('#history-backup-import-result').dataset.result, 'success');
  assert.match(h.element('#history-backup-import-result').textContent, /대화 묶음 전체 백업 1개/);
});

test('single-backup import leaves its success result visible in the management dialog', async () => {
  const h = createHarness({ importResult: JSON.stringify({ peerId: 'ab'.repeat(32), linkedIdentityRestored: false }) });
  h.element('#management-dialog').open = true;
  h.element('#history-detail').hidden = true;
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const task = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await task;
  assert.equal(h.element('#management-dialog').open, true);
  assert.equal(h.element('#history-detail').hidden, true);
  assert.match(h.element('#history-backup-import-result').textContent, /기존 기록과 병합했습니다/);
  assert.match(h.element('#history-backup-import-result').textContent, /가져온 대상: 대화 abababababab/);
});

test('single-backup result keeps its server target after opening another conversation', async () => {
  const peerA = 'ab'.repeat(32);
  const peerB = 'cd'.repeat(32);
  const h = createHarness({ importResult: JSON.stringify({ peerId: peerA, linkedIdentityRestored: false }) });
  const openA = h.evaluate(`openHistory('${peerA}')`);
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({ messages: [], version: 1, nextCursor: null })));
  await openA;
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const importing = h.click('#history-backup-import');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await importing;

  const openB = h.evaluate(`openHistory('${peerB}')`);
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({ messages: [], version: 1, nextCursor: null })));
  await openB;
  const text = h.element('#history-backup-import-result').textContent;
  assert.match(text, /가져온 대상: 대화 abababababab/);
  assert.doesNotMatch(text, /가져온 대상: 대화 cdcdcdcdcdcd/);
});

test('late single-backup success after navigating A to B reports the server target, not B', async () => {
  const peerA = 'ef'.repeat(32);
  const peerB = '12'.repeat(32);
  const h = createHarness({ manualImport: true });
  const openA = h.evaluate(`openHistory('${peerA}')`);
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({ messages: [], version: 1, nextCursor: null })));
  await openA;
  h.element('#history-backup-file').files = [file('backup.adbak', 'ADBACK7\0payload')];
  h.window.confirm = () => true;
  const importing = h.click('#history-backup-import');
  const importRequest = await waitForRequest(() => h.requestForAction('import'));

  const openB = h.evaluate(`openHistory('${peerB}')`);
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({ messages: [], version: 1, nextCursor: null })));
  await openB;

  importRequest.resolve(response(JSON.stringify({ peerId: peerA, linkedIdentityRestored: false })));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await importing;
  const text = h.element('#history-backup-import-result').textContent;
  assert.match(text, /가져온 대상: 대화 efefefefefef/);
  assert.doesNotMatch(text, /가져온 대상: 대화 121212121212/);
});

function createOutputHandle() {
  const output = { written: '', closed: false, aborted: false };
  output.isSameEntry = async () => false;
  output.createWritable = async () => ({
    write: async (bytes) => { output.written = Buffer.from(bytes).toString(); },
    close: async () => { output.closed = true; },
    abort: async () => { output.aborted = true; },
  });
  output.getFile = async () => file('output.adbak', output.written);
  return output;
}

test('actual UI: file chooser and cancellation invalidate an earlier request', async (t) => {
  for (const cancel of [false, true]) {
    await t.test(cancel ? 'cancelled picker' : 'new file selected', async () => {
      const h = createHarness();
      const oldSource = sourceHandle('old.adbak', 'old encrypted');
      await chooseSource(h, oldSource);
      enterSecrets(h, 'pending');
      const pendingTask = h.click('#history-reprotect');
      await new Promise((resolve) => setImmediate(resolve));
        const oldRequest = h.requestForAction('reprotect');

      const picker = deferred();
      h.window.showOpenFilePicker = () => picker.promise;
      const chooseTask = h.click('#history-reprotect-choose');
      if (cancel) {
        const error = new Error('cancelled');
        error.name = 'AbortError';
        picker.reject(error);
      } else {
        picker.resolve([sourceHandle('new.adbak', 'new encrypted')]);
      }
      await chooseTask;
      const statusAfterPicker = h.element('#message').textContent;
      h.element('#history-reprotect-previous-code').value = 'new-session-input';
      oldRequest.resolve(reprotectResponse(h, 'U1RBTEU=', 'stale-output'));
      await pendingTask;

      assert.equal(h.element('#history-reprotect-previous-code').value, 'new-session-input');
      assert.equal(h.element('#history-reprotect-save').disabled, true);
      assert.equal(h.element('#message').textContent, statusAfterPicker);
      assert.equal(h.element('#history-reprotect-source').textContent,
        cancel ? 'old.adbak (13 bytes)' : 'new.adbak (13 bytes)');
      assert.doesNotMatch(h.element('#message').textContent, /새 백업을 만들었습니다/);
    });
  }
});

test('actual UI: logout clears state and invalidates picker and request completions', async (t) => {
  for (const pendingKind of ['picker', 'request']) {
    await t.test(pendingKind, async () => {
      const h = createHarness();
      const original = sourceHandle('old.adbak', 'old encrypted');
      await chooseSource(h, original);
      let pendingTask;
      let oldRequest;
      let picker;
      if (pendingKind === 'picker') {
        picker = deferred();
        h.window.showOpenFilePicker = () => picker.promise;
        pendingTask = h.click('#history-reprotect-choose');
      } else {
        enterSecrets(h, 'logout');
        pendingTask = h.click('#history-reprotect');
        await new Promise((resolve) => setImmediate(resolve));
        oldRequest = h.requestForAction('reprotect');
      }
      await h.click('#logout');
      assert.equal(h.element('#history-reprotect-source').textContent, '선택한 파일 없음');
      assert.equal(h.element('#history-reprotect-save').disabled, true);
      const logoutStatus = h.element('#message').textContent;
      if (picker) picker.resolve([sourceHandle('late.adbak', 'late encrypted')]);
      if (oldRequest) oldRequest.resolve(reprotectResponse(h, 'T0xE', 'logout-output'));
      await pendingTask;
      h.element('#history-reprotect-previous-code').value = 'new-session-code';
      assert.equal(h.element('#history-reprotect-previous-code').value, 'new-session-code');
      assert.equal(h.element('#history-reprotect-source').textContent, '선택한 파일 없음');
      assert.equal(h.element('#history-reprotect-save').disabled, true);
      assert.equal(h.element('#message').textContent, logoutStatus);
    });
  }
});

test('actual UI: save snapshots its source, output and password; stale writes abort', async (t) => {
  for (const invalidator of ['new task', 'logout']) {
    await t.test(invalidator, async () => {
      const h = createHarness();
      const original = sourceHandle('original.adbak', 'original bytes');
      await chooseSource(h, original);
      enterSecrets(h, 'save');
      const reprotectTask = h.click('#history-reprotect');
      await new Promise((resolve) => setImmediate(resolve));
      const reprotect = h.requestForAction('reprotect');
      reprotect.resolve(reprotectResponse(h, 'U0FWRQ==', 'save-output'));
      await reprotectTask;

      const write = deferred();
      const output = createOutputHandle();
      output.createWritable = async () => ({
        write: async (bytes) => { output.written = Buffer.from(bytes).toString(); await write.promise; },
        close: async () => { output.closed = true; },
        abort: async () => { output.aborted = true; },
      });
      h.window.showSaveFilePicker = async () => output;
      const saveTask = h.click('#history-reprotect-save');
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(output.written, 'SAVE');
      if (invalidator === 'new task') {
        h.element('#history-reprotect-previous-code').value = 'next-code';
        h.click('#history-reprotect');
        assert.equal(h.element('#history-reprotect-previous-code').value, '');
        assert.equal(h.element('#history-reprotect-save').disabled, true);
      } else {
        await h.click('#logout');
        assert.equal(h.element('#history-reprotect-previous-code').value, '');
        assert.equal(h.element('#history-reprotect-save').disabled, true);
      }
      write.resolve();
      await saveTask;
      assert.equal(output.aborted, true);
      assert.equal(output.closed, false);
      assert.equal(original.file.dataUrl, file('original.adbak', 'original bytes').dataUrl);
      assert.equal(h.requests.filter((item) => item.path === '/api/history/backup-transfer' && JSON.parse(item.init.body).action === 'verify').length, 0);
      if (invalidator === 'new task') {
        assert.equal(h.element('#history-reprotect-previous-code').value, '');
        assert.equal(h.element('#history-reprotect-save').disabled, true);
      } else {
        assert.equal(h.element('#history-reprotect-source').textContent, '선택한 파일 없음');
      }
    });
  }
});

test('actual UI: same-entry save target is rejected before opening a writer', async () => {
  const h = createHarness();
  const original = sourceHandle('original.adbak', 'original bytes');
  await chooseSource(h, original);
  enterSecrets(h, 'source');
  const task = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestForAction('reprotect').resolve(reprotectResponse(h, 'T1VUUFVU', 'same-entry-output'));
  await task;
  let writerOpened = false;
  original.createWritable = async () => { writerOpened = true; };
  h.window.showSaveFilePicker = async () => original;
  await h.click('#history-reprotect-save');
  assert.equal(writerOpened, false);
  assert.equal(original.file.dataUrl, file('original.adbak', 'original bytes').dataUrl);
  assert.match(h.element('#message').textContent, /원본 백업과 다른 새 파일/);
});

test('actual UI: failed new request invalidates the prior saved candidate', async () => {
  const h = createHarness();
  await chooseSource(h, sourceHandle('source.adbak', 'encrypted source'));
  enterSecrets(h, 'valid');
  const validTask = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestForAction('reprotect').resolve(reprotectResponse(h, 'VkFMSUQ=', 'valid-output'));
  await validTask;
  assert.equal(h.element('#history-reprotect-save').disabled, false);

  enterSecrets(h, 'invalid');
  const failedTask = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const failedRequest = h.requests.filter((item) => item.path === '/api/history/backup-transfer' && JSON.parse(item.init.body).action === 'reprotect')[1];
  assert.deepEqual([
    h.element('#history-reprotect-previous-code').value,
    h.element('#history-reprotect-previous-password').value,
    h.element('#history-reprotect-new-password').value,
    h.element('#history-reprotect-new-password-confirm').value,
  ], ['', '', '', '']);
  failedRequest.resolve(response('invalid', 400));
  await failedTask;
  assert.equal(h.element('#history-reprotect-save').disabled, true);
  assert.match(h.element('#message').textContent, /확인하지 못했습니다/);
  let pickerOpened = false;
  h.window.showSaveFilePicker = async () => { pickerOpened = true; return createOutputHandle(); };
  await h.click('#history-reprotect-save');
  assert.equal(pickerOpened, false);
});

test('actual UI: identity-link failure body reaches the user status unchanged', async () => {
  const h = createHarness();
  h.evaluate("operationId = 'operation-for-test'");
  h.element('#identity-transition-choice').value = 'ab'.repeat(32);
  const task = h.click('#identity-transition-accept');
  await new Promise((resolve) => setImmediate(resolve));
  const recoveryPath = '/temporary-test-history/.deleted-encrypted-history.tmp';
  const detail = `prior conversation cleanup failed; recoverable file: ${recoveryPath}; restoring destination also failed`;
  h.requestFor('/api/chat/link-identity').resolve(response(detail, 500));
  await task;
  assert.equal(h.element('#message').textContent, detail);
});

test('actual UI: restore progress, cancel, and unsigned legacy preview reach the connected screen', async () => {
  const h = createHarness();
  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer',
    historyRestoreStatus: '복원 제안을 거부했습니다. 로컬 기록은 변경되지 않았습니다.',
    historyRestoreState: 'awaiting-merge-consent',
    historyRestoreOfferCount: 1, historyRestoreLegacyCount: 1,
    historyRestoreOffer: [{ time: 1, sender: '상대방', text: 'legacy item', signed: false }],
    historyRestoreInProgress: false, identityTransition: []
  })`);
  assert.match(h.element('#history-restore-status').textContent, /로컬 기록은 변경되지 않았습니다/);
  assert.match(h.element('#history-restore-preview').children[0].children[0].textContent, /기존 서명 없음/);
  assert.equal(h.element('#history-restore-accept').disabled, false);

  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer',
    historyRestoreStatus: '받는 중', historyRestoreOfferCount: 0,
    historyRestoreState: 'receiving',
    historyRestoreOffer: [], historyRestoreInProgress: true,
    historyRestoreReceived: 4096, historyRestoreTotal: 4097, identityTransition: []
  })`);
  assert.match(h.element('#history-restore-status').textContent, /4096 \/ 4097/);
  assert.equal(h.element('#history-restore-decline').disabled, false);
  assert.equal(h.element('#history-restore-decline').textContent, '전송 취소');
  h.evaluate("operationId = 'restore-request-test'");
  const cancel = h.click('#history-restore-decline');
  await new Promise((resolve) => setImmediate(resolve));
  const request = h.requestFor('/api/chat/resolve-history-restore');
  assert.equal(JSON.parse(request.init.body).accept, false);
  request.resolve(response('ok'));
  await cancel;
  assert.match(h.element('#message').textContent, /전송을 취소했습니다/);
});

test('actual UI: transfer consent uses the estimate while final merge consent requires verified records', async () => {
  const h = createHarness();
  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-transfer-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 120000, historyRestoreEstimateBytes: 80000000,
    historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: 'estimate only'
  })`);
  assert.equal(h.element('#history-restore-accept').textContent, '전송 동의');
  assert.equal(h.element('#history-restore-accept').disabled, false);

  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-transfer-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 0, historyRestoreEstimateBytes: 0,
    historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: '0개 예상'
  })`);
  assert.equal(h.element('#history-restore-accept').disabled, false);
  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-merge-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 120000, historyRestoreOfferCount: 120000,
    historyRestoreOffer: [], historyRestoreStatus: 'preview'
  })`);
  assert.equal(h.element('#history-restore-accept').textContent, '제안된 기록 병합');
  assert.equal(h.element('#history-restore-accept').disabled, false);

  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-merge-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 0, historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: '상대가 보낸 기록이 없습니다.'
  })`);
  assert.equal(h.element('#history-restore-accept').disabled, true);
  assert.equal(h.element('#history-restore-decline').disabled, false);

  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-transfer-consent', historyRestoreInProgress: true,
    historyRestoreTotal: 1, historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: 'receiving'
  })`);
  assert.equal(h.element('#history-restore-accept').disabled, true);

  h.evaluate(`updateChatView({
    phase: 'disconnected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-transfer-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 1, historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: 'estimate only'
  })`);
  assert.equal(h.element('#history-restore-accept').disabled, true);
});

test('actual UI: history detail loads bounded pages and searches only the current page', async () => {
  const h = createHarness();
  const opening = h.evaluate("openHistory('peer-for-pagination')");
  await new Promise((resolve) => setImmediate(resolve));
  const firstRequest = h.requestFor('/api/history/messages');
  assert.deepEqual(JSON.parse(firstRequest.init.body), {
    peerId: 'peer-for-pagination', cursor: null, limit: 50,
  });
  const firstMessages = Array.from({ length: 50 }, (_, index) => ({
    index, time: index, sender: '상대방', text: `page one ${index}`,
  }));
  firstRequest.resolve(response(JSON.stringify({
    version: 'file-version-1',
    hasMore: true,
    nextCursor: { version: 'file-version-1', offset: 500, index: 50 },
    messages: firstMessages,
  })));
  await opening;
  assert.equal(h.evaluate('selectedHistoryMessages.length'), 50);
  assert.equal(h.element('#history-page-next').disabled, false);
  assert.match(h.element('#history-page-status').textContent, /현재 페이지/);

  const next = h.click('#history-page-next');
  await new Promise((resolve) => setImmediate(resolve));
  const secondRequest = h.requestFor('/api/history/messages');
  assert.deepEqual(JSON.parse(secondRequest.init.body), {
    peerId: 'peer-for-pagination',
    cursor: { version: 'file-version-1', offset: 500, index: 50 },
    limit: 50,
  });
  secondRequest.resolve(response(JSON.stringify({
    version: 'file-version-1', hasMore: false, nextCursor: null,
    messages: [{ index: 50, time: 50, sender: '상대방', text: 'page two' }],
  })));
  await next;
  assert.equal(h.evaluate('selectedHistoryMessages.length'), 1);
  assert.equal(h.element('#history-page-next').disabled, true);
});

test('actual UI: stale history selection reports the reload requirement', async () => {
  const h = createHarness();
  h.window.confirm = () => true;
  h.evaluate("identityId.textContent = 'identity-A'; selectedHistoryPeer = 'peer'; historyPageVersion = 'old-version'; selectedHistoryIndices.add(4)");
  const deletion = h.click('#delete-selected');
  await new Promise((resolve) => setImmediate(resolve));
  const request = h.requestFor('/api/history/delete-messages');
  const payload = JSON.parse(request.init.body);
  assert.equal(payload.version, 'old-version');
  request.resolve(response(JSON.stringify({ operationId: payload.operationId }), 202));
  await deletion;
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/delete-status').resolve(response(JSON.stringify({
    state: 'failed', error: 'history changed; reload before applying selection',
  })));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.element('#message').textContent, 'history changed; reload before applying selection');
});

test('actual UI: successful deletion reloads the detail page and clears stale selection', async () => {
  const h = createHarness();
  h.window.confirm = () => true;
  h.evaluate("identityId.textContent = 'identity-A'; selectedHistoryPeer = 'peer'; historyPageVersion = 'v1'; selectedHistoryIndices.add(4)");
  const deletion = h.click('#delete-selected');
  await new Promise((resolve) => setImmediate(resolve));
  const deleteRequest = h.requestFor('/api/history/delete-messages');
  const requestBody = JSON.parse(deleteRequest.init.body);
  assert.equal(requestBody.peerId, 'peer');
  assert.equal(typeof requestBody.operationId, 'string');
  deleteRequest.resolve(response(JSON.stringify({ operationId: requestBody.operationId }), 202));
  await deletion;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.element('#delete-selected').disabled, true);
  assert.equal(h.element('#message').textContent, '기록 삭제를 진행 중입니다. 완료 상태를 확인하고 있습니다.');
  h.requestFor('/api/history/delete-status').resolve(response(JSON.stringify({
    state: 'completed', peerId: 'peer', messageCount: 1, error: null,
  })));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/messages').resolve(response(JSON.stringify({
    version: 'v2', hasMore: false, nextCursor: null,
    messages: [{ index: 0, time: 1, sender: '나', text: 'remaining' }],
  })));
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/history/list').resolve(response('[]'));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.evaluate('selectedHistoryIndices.size'), 0);
  assert.equal(h.evaluate('selectedHistoryMessages.length'), 1);
  assert.equal(h.element('#message').textContent, '기록 삭제를 완료했습니다.');
  assert.equal(h.element('#delete-selected').disabled, false);
});

test('actual UI: deletion result stays owner-scoped and can be checked again after identity switch', async () => {
  const h = createHarness();
  h.window.confirm = () => true;
  h.evaluate("identityId.textContent = 'identity-A'; selectedHistoryPeer = 'peer'; historyPageVersion = 'v1'; selectedHistoryIndices.add(1)");
  const deletion = h.click('#delete-selected');
  await new Promise((resolve) => setImmediate(resolve));
  const request = h.requestFor('/api/history/delete-messages');
  const payload = JSON.parse(request.init.body);
  request.resolve(response(JSON.stringify({ operationId: payload.operationId }), 202));
  await deletion;
  await new Promise((resolve) => setImmediate(resolve));
  const firstStatus = h.requestFor('/api/history/delete-status');
  h.evaluate("identityId.textContent = 'identity-B'");
  firstStatus.resolve(response(JSON.stringify({ state: 'failed', error: 'private A result' })));
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(h.evaluate(`sessionStorage.getItem('local-history-delete-jobs')`), /identity-A/);
  h.evaluate("resumeHistoryDeletions('identity-B')");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.requests.filter((item) => item.path === '/api/history/delete-status').length, 1);
  h.evaluate("identityId.textContent = 'identity-A'; resumeHistoryDeletions('identity-A')");
  await new Promise((resolve) => setImmediate(resolve));
  const resumed = h.requests.filter((item) => item.path === '/api/history/delete-status').at(-1);
  resumed.resolve(response(JSON.stringify({ state: 'failed', error: 'retryable A error' })));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.element('#message').textContent, 'retryable A error');
  assert.equal(h.evaluate("sessionStorage.getItem('local-history-delete-jobs')"), null);
});

test('actual UI: restore jobs reopen only for the identity that created them', async (t) => {
  const restoreJob = JSON.stringify({ operationId: 'private-operation', identityId: 'identity-A' });
  const settings = JSON.stringify({
    savedMode: 'general', socks: null, activeMode: 'general', activeSocks: null,
    restartRequired: false, notifications: false,
    savedRelays: ['wss://relay.primal.net'], activeRelays: ['wss://relay.primal.net'],
    activeRelay: 'wss://relay.primal.net',
  });
  await t.test('A to B to A keeps A reference private and reopens it for A', async () => {
    const h = createHarness();
    h.evaluate(`sessionStorage.setItem('local-history-restore-job', ${JSON.stringify(restoreJob)})`);
    const refreshAs = async (identity, statusBody = null) => {
      const refresh = h.evaluate('refreshIdentity()');
      await new Promise((resolve) => setImmediate(resolve));
      h.requests.filter((item) => item.path === '/api/identity/status').at(-1).resolve(response(identity));
      await new Promise((resolve) => setImmediate(resolve));
      h.requests.filter((item) => item.path === '/api/settings/get').at(-1).resolve(response(settings));
      await new Promise((resolve) => setImmediate(resolve));
      h.requests.filter((item) => item.path === '/api/history/list').at(-1).resolve(response('[]'));
      if (statusBody) {
        await new Promise((resolve) => setImmediate(resolve));
        h.requests.filter((item) => item.path === '/api/chat/status').at(-1).resolve(response(statusBody));
      }
      await refresh;
    };
    await refreshAs('identity-B');
    assert.equal(h.requests.some((item) => item.path === '/api/chat/status'), false);
    assert.deepEqual(JSON.parse(h.evaluate("sessionStorage.getItem('local-history-restore-job')")), {
      jobs: { 'identity-A': 'private-operation' },
    });
    const completed = JSON.stringify({
      phase: 'closed', messageEpoch: 0, messages: [], messageCount: 0,
      historyRestoreState: 'completed', historyRestoreInProgress: false,
      historyRestoreStatus: 'merge done', historyRestoreOfferCount: 0,
      historyRestoreLegacyCount: 0, historyRestoreReceived: 0,
      historyRestoreTotal: 0, historyRestoreOffer: [], identityTransition: [],
    });
    await refreshAs('identity-A', completed);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/status').at(-1).init.body, 'private-operation');
    assert.equal(h.element('#history-restore-status').textContent, 'merge done');
    assert.equal(h.evaluate("sessionStorage.getItem('local-history-restore-job')"), null);
  });

  await t.test('temporary query failures keep the reference, missing jobs clear it, and unknown legacy owner is never opened', async () => {
    const h = createHarness();
    h.evaluate(`sessionStorage.setItem('local-history-restore-job', ${JSON.stringify(restoreJob)})`);
    h.evaluate("identityId.textContent = 'identity-A'; operationId = 'private-operation'");
    const temporaryPoll = h.evaluate('pollChat()');
    h.requestFor('/api/chat/status').resolve(response('', 503));
    await temporaryPoll;
    assert.deepEqual(JSON.parse(h.evaluate("sessionStorage.getItem('local-history-restore-job')")), {
      operationId: 'private-operation', identityId: 'identity-A',
    });

    const missingPoll = h.evaluate('pollChat()');
    h.requestFor('/api/chat/status').resolve(response('', 404));
    await missingPoll;
    assert.equal(h.evaluate("sessionStorage.getItem('local-history-restore-job')"), null);
    assert.match(h.element('#chat-status').textContent, /찾을 수 없습니다/);

    const unknown = createHarness();
    unknown.evaluate("sessionStorage.setItem('local-history-restore-job', JSON.stringify({operationId:'unsafe-operation'}))");
    const refresh = unknown.evaluate('refreshIdentity()');
    await new Promise((resolve) => setImmediate(resolve));
    unknown.requestFor('/api/identity/status').resolve(response('identity-A'));
    await new Promise((resolve) => setImmediate(resolve));
    unknown.requestFor('/api/settings/get').resolve(response(settings));
    await new Promise((resolve) => setImmediate(resolve));
    unknown.requestFor('/api/history/list').resolve(response('[]'));
    await refresh;
    assert.equal(unknown.requests.some((item) => item.path === '/api/chat/status'), false);
  });
});

test('actual UI: send rejected during restore merge preserves input and explains retry timing', async () => {
  const h = createHarness();
  h.evaluate("operationId = 'merge-operation'; lastPhase = 'connected'; chatText.value = 'keep this message'");
  const submit = h.element('#send-form').listeners.submit;
  const pending = submit({ preventDefault() {} });
  h.requestFor('/api/chat/send').resolve(response('기록 병합 중이라 메시지를 전송하지 않았습니다. 병합 완료 후 다시 보내세요.', 409));
  await pending;
  assert.equal(h.element('#chat-text').value, 'keep this message');
  assert.equal(h.element('#send-status').textContent, '기록 병합 중이라 메시지를 전송하지 않았습니다. 병합 완료 후 다시 보내세요.');
  assert.equal(h.element('#send-status').hidden, false);
  assert.equal(h.element('#chat-status').textContent, '');
});

test('send request errors stay separate from connection polling and clear on retry or operation switch', async () => {
  for (const failure of ['409', 'unknown']) {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
    await attachChatInHarness(h, 'operation-A');
    inputChat(h, 'keep my draft');
    const submitting = submitChat(h);
    const request = await waitForRequest(() => h.requestFor('/api/chat/send'));
    if (failure === '409') {
      request.resolve(response('병합 중이라 보낼 수 없습니다.', 409));
    } else {
      request.reject(new Error('response unavailable'));
    }
    await submitting;

    const errorText = h.element('#send-status').textContent;
    assert.ok(errorText);
    if (failure === '409') assert.equal(errorText, '병합 중이라 보낼 수 없습니다.');
    else assert.match(errorText, /결과를 확인하지 못했습니다.*중복될 수 있습니다/);
    assert.equal(h.element('#send-status').hidden, false);
    assert.equal(h.element('#chat-text').value, 'keep my draft');

    h.evaluate(`updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1 })`);
    assert.equal(h.element('#chat-status').textContent, '대화 연결이 활성화되었습니다.');
    assert.equal(h.element('#send-status').textContent, errorText);

    inputChat(h, 'retry text');
    const retry = submitChat(h);
    const retryRequest = await waitForRequest(() => h.requests.filter((item) => item.path === '/api/chat/send').at(-1));
    assert.equal(h.element('#send-status').hidden, true);
    assert.equal(h.element('#send-status').textContent, '');
    retryRequest.resolve(response('ok'));
    await retry;
    assert.equal(h.element('#chat-text').value, '');

    h.element('#send-status').textContent = 'old task error';
    h.element('#send-status').hidden = false;
    await attachChatInHarness(h, 'operation-B');
    assert.equal(h.element('#send-status').textContent, '');
    assert.equal(h.element('#send-status').hidden, true);
  }
});

test('send error, aggregate relay acknowledgement, and local storage error remain independent', () => {
  const h = createHarness();
  h.element('#send-status').textContent = '전송 결과를 확인하지 못했습니다.';
  h.element('#send-status').hidden = false;
  h.evaluate(`updateChatView({
    phase: 'connected', messageCount: 0, messageEpoch: 1,
    pendingSends: 2, relayAck: 'accepted', storageError: '기록 파일 쓰기 실패',
  })`);

  assert.equal(h.element('#chat-status').textContent, '대화 연결이 활성화되었습니다.');
  assert.equal(h.element('#send-status').textContent, '전송 결과를 확인하지 못했습니다.');
  assert.match(h.element('#delivery-status').textContent, /relay 접수 확인 대기 중 \(2건\)/);
  assert.match(h.element('#delivery-status').textContent, /상대방의 수신이나 저장은 확인되지 않습니다/);
  assert.match(h.element('#storage-status').textContent, /^이 기기의 기록 처리·저장 상태: 기록 파일 쓰기 실패$/);
  assert.equal(h.element('#delivery-status').hidden, false);
  assert.equal(h.element('#storage-status').hidden, false);
});

test('attaching a new chat clears only the previous relay and storage status before polling', async () => {
  const h = createHarness();
  h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  await attachChatInHarness(h, 'operation-A');
  h.evaluate(`updateChatView({
    phase: 'connected', messageCount: 0, messageEpoch: 1,
    pendingSends: 2, relayAck: 'pending', storageError: 'A 기록 파일 쓰기 실패',
  })`);
  const priorDelivery = h.element('#delivery-status').textContent;
  const priorStorage = h.element('#storage-status').textContent;
  assert.notEqual(priorDelivery, '');
  assert.notEqual(priorStorage, '');

  await h.click('#brand-home');
  await h.click('#return-to-chat');
  assert.equal(h.element('#delivery-status').textContent, priorDelivery);
  assert.equal(h.element('#storage-status').textContent, priorStorage);

  const closing = h.click('#close-chat');
  h.requestFor('/api/chat/cancel').resolve(response('ok'));
  await closing;
  assert.equal(h.evaluate('operationId'), null);

  const attaching = h.evaluate("attachChat('operation-B')");
  const pendingStatus = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/chat/status'));
  assert.equal(h.element('#delivery-status').textContent, '');
  assert.equal(h.element('#delivery-status').hidden, true);
  assert.equal(h.element('#storage-status').textContent, '');
  assert.equal(h.element('#storage-status').hidden, true);
  pendingStatus.resolve(response('unavailable', 503));
  await attaching;
  assert.equal(h.element('#delivery-status').textContent, '');
  assert.equal(h.element('#delivery-status').hidden, true);
  assert.equal(h.element('#storage-status').textContent, '');
  assert.equal(h.element('#storage-status').hidden, true);

  const next = createHarness();
  next.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
  const attachingNext = next.evaluate("attachChat('operation-B')");
  const nextStatus = await waitForRequest(() => next.requests.findLast((item) => item.path === '/api/chat/status'));
  nextStatus.resolve(response(JSON.stringify({
    phase: 'connected', messageCount: 0, messageEpoch: 1,
    pendingSends: 1, relayAck: 'pending', storageError: 'B 기록 파일 쓰기 실패',
  })));
  await attachingNext;
  assert.match(next.element('#delivery-status').textContent, /relay 접수 확인 대기 중 \(1건\)/);
  assert.match(next.element('#storage-status').textContent, /B 기록 파일 쓰기 실패/);
  assert.equal(next.element('#delivery-status').hidden, false);
  assert.equal(next.element('#storage-status').hidden, false);
});

test('invite room creation keeps the code until an operation id is received and ignores duplicate clicks', async () => {
  const h = createHarness();
  const invite = 'ADI3-SYNTHETIC-CODE';
  h.evaluate(`identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = ${JSON.stringify(invite)}; inviteCode.value = currentInvite; show('invite')`);
  const creating = h.click('#start-room');
  await new Promise((resolve) => setImmediate(resolve));
  const createRequest = h.requestFor('/api/chat/create');
  assert.equal(createRequest.init.body, invite);
  assert.equal(createRequest.init.headers.Authorization, 'Bearer session-A');
  assert.equal(h.evaluate('currentInvite'), invite);
  assert.equal(h.element('#invite-code').value, invite);
  assert.equal(h.element('#start-room').disabled, true);
  await h.click('#start-room');
  assert.equal(h.requests.filter((item) => item.path === '/api/chat/create').length, 1);

  createRequest.resolve(response('operation-created'));
  const statusRequest = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/chat/status'));
  assert.equal(h.evaluate('currentInvite'), '');
  assert.equal(h.element('#invite-code').value, '');
  statusRequest.resolve(response(JSON.stringify({ phase: 'connecting', messageCount: 0, messageEpoch: 1 })));
  await creating;
  h.evaluate('stopPolling()');
  assert.equal(h.evaluate('operationId'), 'operation-created');
  assert.equal(h.element('#chat-view').hidden, false);
  assert.equal(h.element('#invite-view').hidden, true);
});

test('room creation explicit failures preserve the invite and response loss is reported as unknown', async (t) => {
  const failures = [
    [400, /유효하지 않은 형식/],
    [412, /로그인이 필요/],
    [409, /연결 작업이 생성되지 않았습니다.*재시작 후 복원되지 않습니다.*새 초대 코드를 생성해 상대에게 다시 전달/],
    [500, /연결 작업 생성 여부.*안전성은.*확인할 수 없습니다/],
  ];
  for (const [status, messagePattern] of failures) {
    await t.test(`HTTP ${status}`, async () => {
      const h = createHarness();
      const invite = 'ADI3-PRESERVED-CODE';
      h.evaluate(`identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = ${JSON.stringify(invite)}; inviteCode.value = currentInvite; show('invite')`);
      const creating = h.click('#start-room');
      await new Promise((resolve) => setImmediate(resolve));
      h.requestFor('/api/chat/create').resolve(response('rejected', status));
      await creating;
      assert.equal(h.element('#invite-view').hidden, false);
      assert.equal(h.evaluate('currentInvite'), invite);
      assert.equal(h.element('#invite-code').value, invite);
      assert.match(h.element('#message').textContent, messagePattern);
      assert.equal(h.element('#start-room').disabled, false);
      assert.equal(h.evaluate('operationId'), null);
      if (status === 409) {
        assert.doesNotMatch(h.element('#message').textContent, /같은 초대 코드.*다시 시도/);
      }
    });
  }

  for (const lostResponse of ['fetch rejection', 'unreadable operation id', 'empty operation id']) {
    await t.test(lostResponse, async () => {
      const h = createHarness();
      const invite = 'ADI3-UNCERTAIN-CODE';
      h.evaluate(`identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = ${JSON.stringify(invite)}; inviteCode.value = currentInvite; show('invite')`);
      const creating = h.click('#start-room');
      await new Promise((resolve) => setImmediate(resolve));
      const createRequest = h.requestFor('/api/chat/create');
      if (lostResponse === 'fetch rejection') createRequest.reject(new Error('connection lost'));
      else if (lostResponse === 'unreadable operation id') {
        createRequest.resolve({ ok: true, status: 200, text: async () => { throw new Error('body lost'); } });
      } else createRequest.resolve(response('   '));
      await creating;
      assert.equal(h.element('#invite-view').hidden, false);
      assert.equal(h.evaluate('currentInvite'), invite);
      assert.equal(h.element('#invite-code').value, invite);
      assert.match(h.element('#message').textContent, /방 생성 결과를 확인하지 못했습니다.*시작했을 수 있고/);
      assert.match(h.element('#message').textContent, /화면에서는 그 작업의 진행 여부를 조회할 수 없습니다/);
      assert.match(h.element('#message').textContent, /프로그램을 종료한 뒤 다시 실행/);
      assert.match(h.element('#message').textContent, /이미 relay에 전달된 내용이 있는지는 확인할 수 없습니다/);
      assert.equal(h.evaluate('operationId'), null);
    });
  }
});

test('late room creation results cannot replace a newer invite or another identity screen', async (t) => {
  await t.test('empty success from a stale request does not change the newer invite UI', async () => {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = 'ADI3-OLD'; inviteCode.value = currentInvite; show('invite')");
    const oldRoom = h.click('#start-room');
    await new Promise((resolve) => setImmediate(resolve));
    const oldRequest = h.requestFor('/api/chat/create');

    await h.click('#brand-home');
    const newInvite = h.click('#create-invite');
    await new Promise((resolve) => setImmediate(resolve));
    h.requestFor('/api/invite/create').resolve(response('ADI3-NEW'));
    await newInvite;
    h.element('#start-room').focus();
    h.element('#message').textContent = '새 초대 화면의 상태';
    const focusCalls = h.element('#start-room').focusCalls;

    oldRequest.resolve(response('   '));
    await oldRoom;
    assert.equal(h.element('#invite-view').hidden, false);
    assert.equal(h.evaluate('currentInvite'), 'ADI3-NEW');
    assert.equal(h.element('#invite-code').value, 'ADI3-NEW');
    assert.equal(h.element('#message').textContent, '새 초대 화면의 상태');
    assert.equal(h.element('#start-room').disabled, false);
    assert.equal(h.document.activeElement, h.element('#start-room'));
    assert.equal(h.element('#start-room').focusCalls, focusCalls);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/cancel').length, 0);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/status').length, 0);
  });

  await t.test('leaving the invite view best-effort cancels an operation whose id arrives later', async () => {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = 'ADI3-OLD'; inviteCode.value = currentInvite; show('invite')");
    const oldRoom = h.click('#start-room');
    await new Promise((resolve) => setImmediate(resolve));
    const oldRequest = h.requestFor('/api/chat/create');
    await h.click('#discard-invite');
    assert.equal(h.element('#invite-view').hidden, true);

    oldRequest.resolve(response('abandoned-operation'));
    await oldRoom;
    const cancelRequest = h.requests.find((item) => item.path === '/api/chat/cancel');
    assert.ok(cancelRequest);
    assert.equal(cancelRequest.init.body, 'abandoned-operation');
    assert.equal(cancelRequest.init.headers.Authorization, 'Bearer session-A');
    assert.equal(h.evaluate('operationId'), null);
    assert.equal(h.requests.some((item) => item.path === '/api/chat/status'), false);
  });

  await t.test('new invite wins over older room response', async () => {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = 'ADI3-OLD'; inviteCode.value = currentInvite; show('invite')");
    const oldRoom = h.click('#start-room');
    await new Promise((resolve) => setImmediate(resolve));
    const oldRequest = h.requestFor('/api/chat/create');

    await h.click('#brand-home');
    const newInvite = h.click('#create-invite');
    await new Promise((resolve) => setImmediate(resolve));
    const inviteRequest = h.requestFor('/api/invite/create');
    inviteRequest.resolve(response('ADI3-NEW'));
    await newInvite;
    oldRequest.resolve(response('old-operation'));
    await oldRoom;
    const staleCancel = h.requests.find((item) => item.path === '/api/chat/cancel');
    assert.ok(staleCancel, 'stale operation is best-effort cancelled while the original session still owns it');
    assert.equal(staleCancel.init.body, 'old-operation');
    assert.equal(staleCancel.init.headers.Authorization, 'Bearer session-A');

    assert.equal(h.evaluate('currentInvite'), 'ADI3-NEW');
    assert.equal(h.element('#invite-code').value, 'ADI3-NEW');
    assert.equal(h.element('#invite-view').hidden, false);
    assert.equal(h.evaluate('operationId'), null);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/status').length, 0);
  });

  await t.test('identity change discards an older room result', async () => {
    const h = createHarness();
    h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'; currentInvite = 'ADI3-OLD'; inviteCode.value = currentInvite; show('invite')");
    const oldRoom = h.click('#start-room');
    await new Promise((resolve) => setImmediate(resolve));
    const oldRequest = h.requestFor('/api/chat/create');
    h.evaluate("identityId.textContent = 'identity-B'; token = 'session-B'; identitySessionGeneration += 1; show('entry'); message.textContent = '다른 신원 화면'");
    oldRequest.resolve(response('old-operation'));
    await oldRoom;
    assert.equal(h.element('#message').textContent, '다른 신원 화면');
    assert.equal(h.element('#identity-entry').hidden, false);
    assert.equal(h.evaluate('operationId'), null);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/status').length, 0);
    assert.equal(h.requests.filter((item) => item.path === '/api/chat/cancel').length, 0);
  });
});

test('actual UI: chat phases show only the actions available at each step', async () => {
  const h = createHarness();
  h.evaluate("operationId = 'operation-phases'; identityId.textContent = 'identity-test'");

  const showPhase = (phase, extras = {}) => h.evaluate(`updateChatView({
    phase: ${JSON.stringify(phase)}, messageCount: 0, messageEpoch: 1,
    identityTransition: [], ...${JSON.stringify(extras)}
  })`);

  showPhase('connecting');
  assert.equal(h.element('#chat-title').textContent, '대화 연결');
  assert.match(h.element('#chat-status').textContent, /relay에 연결하고 상대를 찾는 중/);
  assert.equal(h.element('#close-chat').hidden, false);
  assert.equal(h.element('#verification').hidden, true);
  assert.equal(h.element('#conversation').hidden, true);
  assert.equal(h.element('#send-form').hidden, true);
  assert.equal(h.element('#history-restore-request').hidden, true);
  assert.equal(h.element('#send-form').querySelector('button').disabled, true);

  const peer = 'ab'.repeat(32);
  const fingerprint = 'cd'.repeat(32);
  showPhase('verification', { peerId: peer, fingerprint });
  assert.equal(h.element('#chat-title').textContent, '대화 연결');
  assert.equal(h.element('#verification').hidden, false);
  assert.equal(h.element('#peer-id').textContent, peer);
  assert.equal(h.element('#fingerprint').textContent, fingerprint);
  assert.equal(h.element('#conversation').hidden, true);
  assert.equal(h.element('#send-form').hidden, true);
  assert.equal(h.element('#history-restore-request').hidden, true);
  assert.equal(h.element('#confirm-peer').disabled, false);
  const html = pageSource();
  assert.match(html, /<p class="verification-warning">코드가 한 자리라도 다르면 확인하지 마세요\.<\/p>\s*<button id="confirm-peer"/);
  assert.match(html, /id="confirm-peer"[^>]*>코드를 비교했고 일치함을 확인했습니다</);
  assert.match(html, /#chat-view\[data-phase="verification"\] \.chat-workflows\s*\{[^}]*max-height:\s*none;[^}]*overflow:\s*visible;/);
  assert.match(html, /#chat-view\[data-phase="connecting"\].*#chat-view\[data-phase="closed"\]\s*\{[^}]*align-content:\s*start;[^}]*flex:\s*0 0 auto;/);
  assert.match(html, /#chat-view\[data-phase="disconnected"\]\[data-chat-body="messages"\].*#chat-view\[data-phase="closed"\]\[data-chat-body="messages"\]\s*\{[^}]*align-content:\s*stretch;[^}]*flex:\s*1 1 auto;[^}]*min-height:\s*0;/);
  assert.match(html, /#chat-view #conversation\[hidden\]\s*\{[^}]*display:\s*none\s*!important;/);

  const confirmTask = h.click('#confirm-peer');
  await new Promise((resolve) => setImmediate(resolve));
  h.requestFor('/api/chat/confirm').resolve(response('ok'));
  await confirmTask;
  showPhase('confirming');
  assert.equal(h.element('#chat-title').textContent, '대화 연결');
  assert.match(h.element('#chat-status').textContent, /상대 확인 응답을 기다리는 중/);
  assert.equal(h.element('#confirm-peer').disabled, true);
  assert.equal(h.element('#conversation').hidden, true);
  assert.equal(h.element('#send-form').hidden, true);
  assert.equal(h.element('#history-restore-request').hidden, true);

  showPhase('connected', { pendingSends: 1, relayAck: 'pending', storageError: '기록 파일 쓰기 실패' });
  assert.equal(h.element('#chat-title').textContent, '대화');
  assert.match(h.element('#chat-status').textContent, /대화 연결이 활성화/);
  assert.equal(h.element('#conversation').hidden, false);
  assert.equal(h.element('#send-form').hidden, false);
  assert.equal(h.element('#send-form').querySelector('button').disabled, true, 'blank messages cannot be sent');
  inputChat(h, 'ready to send');
  assert.equal(h.element('#send-form').querySelector('button').disabled, false);
  assert.equal(h.element('#history-restore-request').hidden, false);
  assert.match(h.element('#delivery-status').textContent, /relay 접수 확인 대기/);
  assert.match(h.element('#storage-status').textContent, /이 기기의 기록 처리·저장 상태/);

  h.evaluate("appendMessages([{ sender: '상대', time: 1700000000, text: '기존 메시지 https://example.test/' }]); chatText.value = '연결이 끊겼을 때 남길 초안'");
  showPhase('disconnected', { error: '연결이 끊겼습니다.' });
  assert.equal(h.element('#chat-title').textContent, '대화');
  assert.equal(h.element('#chat-status').textContent, '연결이 끊겼습니다.');
  assert.equal(h.element('#conversation').hidden, false);
  assert.equal(h.element('#conversation').children.length, 1);
  assert.equal(h.element('#send-form').hidden, false);
  assert.equal(h.element('#send-form').querySelector('button').disabled, true);
  assert.equal(h.element('#chat-text').value, '연결이 끊겼을 때 남길 초안');
  assert.equal(h.element('#history-restore-request').hidden, true);
  assert.equal(h.element('#close-chat').hidden, false);

  showPhase('failed', { error: '연결에 실패했습니다.' });
  assert.equal(h.element('#chat-title').textContent, '대화');
  assert.equal(h.element('#conversation').children.length, 1);
  assert.equal(h.element('#chat-text').value, '연결이 끊겼을 때 남길 초안');

  showPhase('disconnected', {
    error: '연결이 끊겼습니다.', historyRestoreState: 'merging',
    historyRestoreInProgress: true, historyRestoreStatus: '최종 병합 작업 진행 중',
    historyRestoreOfferCount: 0, historyRestoreOffer: [],
  });
  assert.equal(h.element('#history-restore-panel').hidden, false);
  assert.equal(h.element('#chat-view').dataset.workflowVisible, 'true');
  assert.match(h.element('#history-restore-status').textContent, /최종 병합 작업 진행 중/);

  h.evaluate("clearConversationMessages(); chatText.value = ''");
  showPhase('disconnected', { error: '연결이 끊겼습니다.' });
  assert.equal(h.element('#conversation').hidden, true);
  h.evaluate("appendMessages([{ sender: '상대', time: 1700000001, text: '늦게 도착한 메시지' }])");
  assert.equal(h.element('#conversation').hidden, false);
  assert.equal(h.element('#chat-view').dataset.chatBody, 'messages');
});

test('chat phase focus moves only when the active workflow control disappears', () => {
  const h = createHarness();
  h.evaluate("operationId = 'operation-focus'; chatView.hidden = false");
  const showPhase = (phase) => h.evaluate(`updateChatView({
    phase: ${JSON.stringify(phase)}, messageCount: 0, messageEpoch: 1, identityTransition: []
  })`);

  showPhase('verification');
  h.element('#confirm-peer').focus();
  showPhase('confirming');
  assert.equal(h.document.activeElement, h.element('#chat-status'));
  h.element('#close-chat').focus();
  showPhase('confirming');
  assert.equal(h.document.activeElement, h.element('#close-chat'));

  const connected = createHarness();
  connected.evaluate("operationId = 'operation-connected'; chatView.hidden = false");
  connected.evaluate("updateChatView({ phase: 'connecting', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
  connected.element('#chat-status').focus();
  connected.evaluate("updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
  assert.equal(connected.document.activeElement, connected.element('#chat-text'));

  const otherControl = createHarness();
  otherControl.evaluate("operationId = 'operation-connected'; chatView.hidden = false");
  otherControl.evaluate("updateChatView({ phase: 'connecting', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
  otherControl.element('#close-chat').focus();
  otherControl.evaluate("updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
  assert.equal(otherControl.document.activeElement, otherControl.element('#close-chat'));

  const home = createHarness();
  home.evaluate("operationId = 'operation-home'; chatView.hidden = true");
  home.element('#brand-home').focus();
  home.evaluate("updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
  assert.equal(home.document.activeElement, home.element('#brand-home'));
});

test('peer confirmation request and phase polling stay scoped to the same conversation', async (t) => {
  for (const order of ['poll-before-response', 'response-before-poll']) {
    await t.test(order, async () => {
      const h = createHarness();
      h.evaluate("operationId = 'operation-A'; identityId.textContent = 'identity-A'; token = 'session-A'; chatView.hidden = false");
      h.evaluate("updateChatView({ phase: 'verification', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
      h.element('#confirm-peer').focus();
      const confirming = h.click('#confirm-peer');
      await new Promise((resolve) => setImmediate(resolve));
      const confirmRequest = h.requestFor('/api/chat/confirm');
      assert.equal(confirmRequest.init.body, 'operation-A');
      assert.equal(confirmRequest.init.headers.Authorization, 'Bearer session-A');
      if (order === 'poll-before-response') {
        h.document.activeElement = h.element('body');
        h.evaluate("updateChatView({ phase: 'confirming', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
        assert.equal(h.document.activeElement, h.element('#chat-status'));
      }
      confirmRequest.resolve(response('ok'));
      await confirming;
      if (order === 'response-before-poll') {
        h.evaluate("updateChatView({ phase: 'confirming', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
        assert.equal(h.document.activeElement, h.element('#chat-status'));
      }
      assert.match(h.element('#chat-status').textContent, /상대 확인 응답을 기다리는 중/);
      assert.equal(h.element('#confirm-peer').disabled, true);
    });
  }

  for (const outcome of ['success', 'failure']) {
    await t.test(`stale A ${outcome} after closing A and starting B`, async () => {
      const h = createHarness();
      h.evaluate("operationId = 'operation-A'; identityId.textContent = 'identity-A'; token = 'session-A'; chatView.hidden = false");
      h.evaluate("updateChatView({ phase: 'verification', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
      h.element('#confirm-peer').focus();
      const confirming = h.click('#confirm-peer');
      await new Promise((resolve) => setImmediate(resolve));
      const confirmRequest = h.requestFor('/api/chat/confirm');

      const closing = h.click('#close-chat');
      h.requestFor('/api/chat/cancel').resolve(response('ok'));
      await closing;
      const attaching = h.evaluate("attachChat('operation-B')");
      const statusRequest = await waitForRequest(() => h.requests.findLast((item) => item.path === '/api/chat/status'));
      statusRequest.resolve(response(JSON.stringify({ phase: 'verification', messageCount: 0, messageEpoch: 1 })));
      await attaching;
      const statusBeforeLateResponse = h.element('#chat-status').textContent;
      const buttonBeforeLateResponse = h.element('#confirm-peer').disabled;
      h.element('#close-chat').focus();

      confirmRequest.resolve(outcome === 'success' ? response('ok') : response('missing', 404));
      await confirming;
      assert.equal(h.evaluate('operationId'), 'operation-B');
      assert.equal(h.element('#chat-status').textContent, statusBeforeLateResponse);
      assert.equal(h.element('#confirm-peer').disabled, buttonBeforeLateResponse);
      assert.equal(h.document.activeElement, h.element('#close-chat'));
    });
  }

  await t.test('home navigation and connected polling are not overwritten by a late response', async () => {
    const h = createHarness();
    h.evaluate("operationId = 'operation-A'; identityId.textContent = 'identity-A'; token = 'session-A'; chatView.hidden = false");
    h.evaluate("updateChatView({ phase: 'verification', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
    h.element('#confirm-peer').focus();
    const confirming = h.click('#confirm-peer');
    await new Promise((resolve) => setImmediate(resolve));
    const confirmRequest = h.requestFor('/api/chat/confirm');
    h.element('#brand-home').focus();
    h.evaluate("show('active')");
    confirmRequest.resolve(response('ok'));
    await confirming;
    assert.equal(h.document.activeElement, h.element('#brand-home'));

    const connected = createHarness();
    connected.evaluate("operationId = 'operation-late-confirm'; identityId.textContent = 'identity-A'; token = 'session-A'; chatView.hidden = false");
    connected.evaluate("updateChatView({ phase: 'verification', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
    connected.element('#confirm-peer').focus();
    const lateConfirming = connected.click('#confirm-peer');
    await new Promise((resolve) => setImmediate(resolve));
    const lateConfirmRequest = connected.requestFor('/api/chat/confirm');
    connected.evaluate("updateChatView({ phase: 'confirming', messageCount: 0, messageEpoch: 1, identityTransition: [] }); updateChatView({ phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [] })");
    const connectedStatus = connected.element('#chat-status').textContent;
    assert.equal(connected.document.activeElement, connected.element('#chat-text'));
    lateConfirmRequest.resolve(response('ok'));
    await lateConfirming;
    assert.equal(connected.element('#chat-status').textContent, connectedStatus);
    assert.equal(connectedStatus, '대화 연결이 활성화되었습니다.');
  });
});

test('chat live status text is written only when its displayed value changes', () => {
  const h = createHarness();
  h.evaluate("operationId = 'operation-live-status'; chatView.hidden = false");
  const update = (storageError, restoreStatus, restoreReceived = 1) => h.evaluate(`updateChatView({
    phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [],
    pendingSends: 2, relayAck: 'pending', storageError: ${JSON.stringify(storageError)},
    historyRestoreStatus: ${JSON.stringify(restoreStatus)}, historyRestoreState: 'awaiting-transfer-consent',
    historyRestoreInProgress: true, historyRestoreReceived: ${restoreReceived}, historyRestoreTotal: 2,
    historyRestoreOfferCount: 1,
  })`);
  update('기록 쓰기 오류', '기록을 확인했습니다.');
  const statusElements = ['#chat-status', '#delivery-status', '#storage-status', '#history-restore-status']
    .map((selector) => h.element(selector));
  for (const item of statusElements) item.textContentSetCount = 0;
  update('기록 쓰기 오류', '기록을 확인했습니다.');
  assert.deepEqual(statusElements.map((item) => item.textContentSetCount), [0, 0, 0, 0]);

  update('새 기록 쓰기 오류', '기록을 확인했습니다.', 2);
  assert.deepEqual(statusElements.map((item) => item.textContentSetCount), [0, 0, 1, 1]);
  assert.match(h.element('#storage-status').textContent, /새 기록 쓰기 오류/);
  assert.equal(h.element('#history-restore-status').textContent, '상대 기록을 받는 중입니다: 2 / 2. 동의 전에는 로컬 기록을 변경하지 않습니다.');
});

test('send errors remain visible outside the hidden form after disconnect and emptying the draft', async (t) => {
  for (const failure of ['409', 'unknown']) {
    await t.test(failure, async () => {
      const h = createHarness();
      h.evaluate("identityId.textContent = 'identity-A'; token = 'session-A'");
      await attachChatInHarness(h, 'operation-A');
      inputChat(h, 'in-flight message');
      const sending = submitChat(h);
      const request = await waitForRequest(() => h.requestFor('/api/chat/send'));

      inputChat(h, '');
      h.evaluate("updateChatView({ phase: 'disconnected', error: '연결이 끊겼습니다.', messageCount: 0, messageEpoch: 1 })");
      assert.equal(h.element('#send-form').hidden, true);
      assert.equal(h.element('#send-form').querySelector('button').disabled, true);

      let body;
      if (failure === '409') {
        body = deferred();
        let bodyStartedResolve;
        const bodyStarted = new Promise((resolve) => { bodyStartedResolve = resolve; });
        request.resolve({
          ok: false, status: 409,
          text: () => { bodyStartedResolve(); return body.promise; },
        });
        await bodyStarted;
        body.resolve('현재 병합 중이어서 전송하지 않았습니다.');
      } else {
        request.reject(new Error('response lost'));
      }
      await sending;

      assert.equal(h.element('#chat-view').hidden, false);
      assert.equal(h.element('#send-status').hidden, false);
      assert.equal(h.element('#send-status').textContent, failure === '409'
        ? '현재 병합 중이어서 전송하지 않았습니다.'
        : '전송 결과를 확인하지 못했습니다. 입력을 보존했습니다. 다시 보내면 중복될 수 있습니다.');
      assert.equal(h.element('#send-form').hidden, true);
      assert.equal(h.element('#send-form').querySelector('button').disabled, true);
      assert.equal(h.element('#chat-status').textContent, '연결이 끊겼습니다.');

      h.evaluate("updateChatView({ phase: 'disconnected', error: '연결이 계속 끊겨 있습니다.', messageCount: 0, messageEpoch: 1 })");
      assert.equal(h.element('#send-status').hidden, false);
      assert.equal(h.element('#send-form').hidden, true);
      assert.equal(h.element('#send-form').querySelector('button').disabled, true);

      h.evaluate("updateChatView({ phase: 'verification', messageCount: 0, messageEpoch: 1 })");
      assert.equal(h.element('#verification').hidden, false);
      assert.equal(h.element('#send-form').querySelector('button').disabled, true);
    });
  }
});

test('actual UI: relay settings display the active relay list and save edited lists', async (t) => {
  const h = createHarness();
  const settings = {
    savedMode: 'general', socks: null, activeMode: 'general', activeSocks: null,
    notifications: false, savedRelays: ['wss://relay.one', 'wss://relay.two'],
    activeRelays: ['wss://relay.old', 'wss://relay.backup'], activeRelay: 'wss://relay.old',
    restartRequired: true, relayRestartRequired: true,
  };
  const refresh = h.evaluate('refreshNetworkSettings()');
  h.requestFor('/api/settings/get').resolve(response(JSON.stringify(settings)));
  await refresh;
  assert.equal(h.element('#relay-list').value, 'wss://relay.one\nwss://relay.two');
  assert.match(h.element('#active-relay').textContent, /wss:\/\/relay\.old/);
  assert.match(h.element('#active-relay').textContent, /wss:\/\/relay\.backup/);
  assert.doesNotMatch(h.element('#active-relay').textContent, /첫 주소만/);
  assert.match(h.element('#settings-status').textContent, /다시 실행/);

  await t.test('save sends the entered list and reports restart requirement', async () => {
    h.element('#relay-list').value = 'wss://relay.new\nwss://relay.backup';
    const saving = h.click('#save-settings');
    const request = h.requestFor('/api/settings/save');
    assert.deepEqual(JSON.parse(request.init.body).relayUrls, [
      'wss://relay.new', 'wss://relay.backup',
    ]);
    request.resolve(response(JSON.stringify({ ...settings, savedRelays: ['wss://relay.new', 'wss://relay.backup'] })));
    await saving;
    assert.match(h.element('#settings-status').textContent, /다시 실행/);
    assert.match(h.element('#active-relay').textContent, /wss:\/\/relay\.old/);
    assert.match(h.element('#active-relay').textContent, /wss:\/\/relay\.backup/);
  });

  await t.test('invalid address detail is shown as text', async () => {
    const saving = h.click('#save-settings');
    h.requestFor('/api/settings/save').resolve(response('2번째 relay 주소가 올바르지 않습니다.', 400));
    await saving;
    assert.equal(h.element('#settings-status').textContent, '2번째 relay 주소가 올바르지 않습니다.');
  });

  await t.test('Tor guidance states service and external-browser limits', async () => {
    const torHarness = createHarness();
    const torSettings = {
      savedMode: 'tor', socks: '127.0.0.1:9050',
      activeMode: 'tor', activeSocks: '127.0.0.1:9050',
      notifications: false, savedRelays: ['wss://relay.one'],
      activeRelays: ['wss://relay.one'], restartRequired: false,
    };
    const refreshing = torHarness.evaluate('refreshNetworkSettings()');
    torHarness.requestFor('/api/settings/get').resolve(response(JSON.stringify(torSettings)));
    await refreshing;
    assert.match(torHarness.element('#network-mode').textContent, /SOCKS 서비스가 Tor인지 앱에서 확인하지 않으며/);
    assert.match(torHarness.element('#network-mode').textContent, /외부 브라우저의 네트워크 경로도 제어하지 않습니다/);
    assert.match(fs.readFileSync('web/index.html', 'utf8'), /Tor 서비스를 별도로 실행하세요/);
    assert.match(fs.readFileSync('web/index.html', 'utf8'), /외부 브라우저의 네트워크 경로도 제어하지 않습니다/);
  });
});

test('actual UI: live and saved messages link only valid HTTP(S) URLs safely', async (t) => {
  const h = createHarness();
  const generalSettings = {
    savedMode: 'tor', socks: '127.0.0.1:9050', activeMode: 'general', activeSocks: null,
    notifications: false, savedRelays: ['wss://relay.one'], activeRelays: ['wss://relay.one'],
  };
  const refresh = h.evaluate('refreshNetworkSettings()');
  h.requestFor('/api/settings/get').resolve(response(JSON.stringify(generalSettings)));
  await refresh;

  h.evaluate(`appendMessages(${JSON.stringify([{ time: 1, sender: '상대', text: 'visit https://example.com/path?x=1.\n<img src=x onerror=alert(1)> javascript:alert(1) http://' }])})`);
  const liveBody = h.element('#conversation').children[0].children[1];
  const liveLinks = liveBody.children.filter((child) => child.tagName === undefined && child.href);
  assert.equal(liveLinks.length, 1);
  assert.equal(liveLinks[0].href, 'https://example.com/path?x=1');
  assert.equal(liveLinks[0].target, '_blank');
  assert.equal(liveLinks[0].rel, 'noopener noreferrer');
  assert.equal(liveBody.children.some((child) => child.textContent.includes('<img src=x onerror=alert(1)> javascript:alert(1) http://')), true);

  let confirmCalls = 0;
  h.window.confirm = () => { confirmCalls += 1; return false; };
  assert.equal(typeof liveLinks[0].listeners.click, 'undefined');
  assert.equal(confirmCalls, 0, 'saved Tor mode must not override active general mode');

  await t.test('Tor confirmation applies to stored history links and cancel blocks opening', async () => {
    const torSettings = { ...generalSettings, activeMode: 'tor', savedMode: 'general' };
    const loading = h.evaluate('refreshNetworkSettings()');
    h.requestFor('/api/settings/get').resolve(response(JSON.stringify(torSettings)));
    await loading;
    h.evaluate(`selectedHistoryMessages = [{index: 0, time: 1, sender: '상대', text: 'https://safe.example and data:text/html,<b>x</b>'}]; renderHistoryMessages()`);
    const storedBody = h.element('#history-messages').children[0].children[2];
    const storedLink = storedBody.children.find((child) => child.type === 'button');
    assert.ok(storedLink);
    assert.equal(storedLink.textContent, 'https://safe.example');
    assert.equal(storedBody.children.some((child) => child.href), false, 'Tor rendering must not expose a directly navigable href');
    let warning = '';
    h.window.confirm = (text) => { warning = text; return false; };
    storedLink.listeners.click({});
    assert.match(warning, /외부 브라우저가 Tor를 사용하지 않아/);
    assert.equal(h.window.openedUrls.length, 0);
    assert.equal(storedBody.children.some((child) => child.textContent.includes('data:text/html')), true);
  });

  await t.test('Tor confirmation allows opening only after explicit confirmation', async () => {
    h.window.confirm = () => true;
    const button = h.element('#history-messages').children[0].children[2].children.find((child) => child.type === 'button');
    button.listeners.click({});
    assert.deepEqual(h.window.openedUrls, [{
      url: 'https://safe.example/', target: '_blank', features: 'noopener,noreferrer',
    }]);
  });
});

test('actual UI: stale polls cannot change another identity after response or JSON awaits', async (t) => {
  const settings = JSON.stringify({
    savedMode: 'general', socks: null, activeMode: 'general', activeSocks: null,
    restartRequired: false, notifications: false,
    savedRelays: ['wss://relay.primal.net'], activeRelays: ['wss://relay.primal.net'],
    activeRelay: 'wss://relay.primal.net',
  });
  const switchIdentity = async (h, identity) => {
    const refresh = h.evaluate('refreshIdentity()');
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/identity/status').at(-1).resolve(response(identity));
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/settings/get').at(-1).resolve(response(settings));
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/history/list').at(-1).resolve(response('[]'));
    await refresh;
  };
  const seedA = (h) => h.evaluate(`identityId.textContent='identity-A'; operationId='operation-A'; sessionStorage.setItem('local-history-restore-job', JSON.stringify({jobs:{'identity-A':'operation-A'}}))`);

  await t.test('A status request completing 404 after switch to B preserves A reference; B logout then A reconnect resumes', async () => {
    const h = createHarness();
    seedA(h);
    const poll = h.evaluate('pollChat()');
    const oldStatus = h.requestFor('/api/chat/status');
    await switchIdentity(h, 'identity-B');
    const bState = { chat: h.element('#chat-status').textContent, operation: h.evaluate('operationId') };
    oldStatus.resolve(response('', 404));
    await poll;
    assert.deepEqual(JSON.parse(h.evaluate("sessionStorage.getItem('local-history-restore-job')")), {
      jobs: { 'identity-A': 'operation-A' },
    });
    assert.equal(h.element('#chat-status').textContent, bState.chat);
    assert.equal(h.evaluate('operationId'), bState.operation);

    await h.click('#logout');
    const reconnect = h.evaluate('refreshIdentity()');
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/identity/status').at(-1).resolve(response('identity-A'));
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/settings/get').at(-1).resolve(response(settings));
    await new Promise((resolve) => setImmediate(resolve));
    h.requests.filter((item) => item.path === '/api/history/list').at(-1).resolve(response('[]'));
    await new Promise((resolve) => setImmediate(resolve));
    const resumed = h.requests.filter((item) => item.path === '/api/chat/status').at(-1);
    assert.equal(resumed.init.body, 'operation-A');
    resumed.resolve(response(JSON.stringify({
      phase: 'connected', messageEpoch: 0, messages: [], messageCount: 0,
      historyRestoreState: 'merging', historyRestoreInProgress: true,
      historyRestoreStatus: 'A still merging', historyRestoreOfferCount: 0,
      historyRestoreLegacyCount: 0, historyRestoreReceived: 0,
      historyRestoreTotal: 0, historyRestoreOffer: [], identityTransition: [],
    })));
    await reconnect;
    assert.equal(h.element('#history-restore-status').textContent, 'A still merging');
  });

  await t.test('delayed status JSON is discarded after identity change', async () => {
    const h = createHarness();
    seedA(h);
    const poll = h.evaluate('pollChat()');
    const delayed = deferredJsonResponse();
    h.requestFor('/api/chat/status').resolve(delayed.response);
    await delayed.jsonStarted;
    await switchIdentity(h, 'identity-B');
    h.element('#chat-status').textContent = 'B screen';
    delayed.json.resolve({
      phase: 'connected', messageEpoch: 0, messages: [], messageCount: 0,
      historyRestoreState: 'merging', historyRestoreInProgress: true,
      historyRestoreStatus: 'A secret restore status', historyRestoreOfferCount: 0,
      historyRestoreLegacyCount: 0, historyRestoreReceived: 0,
      historyRestoreTotal: 0, historyRestoreOffer: [], identityTransition: [],
    });
    await poll;
    assert.equal(h.element('#chat-status').textContent, 'B screen');
    assert.equal(h.element('#history-restore-status').textContent.includes('A secret restore status'), false);
    assert.deepEqual(JSON.parse(h.evaluate("sessionStorage.getItem('local-history-restore-job')")), {
      jobs: { 'identity-A': 'operation-A' },
    });
  });

  await t.test('delayed messages JSON is discarded after identity change', async () => {
    const h = createHarness();
    seedA(h);
    const poll = h.evaluate('pollChat()');
    h.requestFor('/api/chat/status').resolve(response(JSON.stringify({
      phase: 'connected', messageEpoch: 0, messages: [], messageCount: 1,
      historyRestoreState: 'idle', historyRestoreInProgress: false,
      historyRestoreStatus: '', historyRestoreOfferCount: 0,
      historyRestoreLegacyCount: 0, historyRestoreReceived: 0,
      historyRestoreTotal: 0, historyRestoreOffer: [], identityTransition: [],
    })));
    await new Promise((resolve) => setImmediate(resolve));
    const messageRequest = h.requestFor('/api/chat/messages');
    const delayed = deferredJsonResponse();
    messageRequest.resolve(delayed.response);
    await delayed.jsonStarted;
    await switchIdentity(h, 'identity-B');
    delayed.json.resolve([{ unixTime: 1, sender: '상대방', text: 'A private message' }]);
    await poll;
    assert.equal(h.element('#conversation').children.some((item) => item.textContent === 'A private message'), false);
    assert.equal(h.evaluate('messageCursor'), 0);
    assert.deepEqual(JSON.parse(h.evaluate("sessionStorage.getItem('local-history-restore-job')")), {
      jobs: { 'identity-A': 'operation-A' },
    });
  });
});

test('actual UI: staging cleanup failure remains visible after disconnect', () => {
  const h = createHarness();
  h.evaluate(`updateChatView({
    phase: 'disconnected', messageEpoch: 0, messages: [], peerId: 'peer',
    historyRestoreState: 'failed', historyRestoreInProgress: false,
    historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: '연결이 종료되었습니다.',
    historyRestoreCleanupError: '복구 임시 파일 제거 실패: /isolated/staging'
  })`);
  assert.equal(h.element('#history-restore-panel').hidden, false);
  assert.match(h.element('#history-restore-status').textContent, /복구 임시 파일 제거 실패/);
});

const backupTransferActions = (harness) => harness.requests
  .filter((item) => item.path === '/api/history/backup-transfer')
  .map((item) => JSON.parse(item.init.body));

test('importing a forgeable or unauthenticated legacy format asks first and cancelling sends nothing', async () => {
  const expectations = [
    ['ADBACK2\0', /ADBACK2 백업은 이전 형식/, /비밀번호를 아는 사람은 상대가 보낸 것처럼 보이는 기록을 만들어 넣을 수 있습니다/],
    ['ADPACK1\0', /ADPACK1 묶음은 이전 형식/, /묶음 인증이 없고/],
  ];
  for (const [magic, kind, risk] of expectations) {
    const h = createHarness();
    h.element('#history-backup-file').files = [file('legacy.adbak', `${magic}payload`)];
    let warning = '';
    h.window.confirm = (text) => { warning = text; return false; };
    await h.click('#history-backup-import');
    assert.match(warning, kind);
    assert.match(warning, risk);
    assert.match(warning, /서명 없음 · 미검증/);
    assert.deepEqual(backupTransferActions(h), [], 'nothing is uploaded or imported after cancelling');
  }
});

test('the legacy opt-in flag is sent only after the user confirmed a legacy format', async () => {
  for (const magic of ['ADBACK2\0', 'ADBACK6\0', 'ADPACK1\0', 'ADPACK2\0']) {
    const h = createHarness({ importFailure: 'stop after the import request' });
    h.element('#history-backup-file').files = [file('legacy.adbak', `${magic}payload`)];
    h.window.confirm = () => true;
    const task = h.click('#history-backup-import');
    await new Promise((resolve) => setImmediate(resolve));
    await task;
    const imports = backupTransferActions(h).filter((item) => item.action === 'import');
    assert.equal(imports.length, 1, magic);
    assert.equal(imports[0].allowLegacy, true, magic);
  }
});

test('current formats import without a legacy prompt or opt-in flag', async () => {
  for (const magic of ['ADBACK7\0', 'ADPACK3\0']) {
    const h = createHarness({ importFailure: 'stop after the import request' });
    h.element('#history-backup-file').files = [file('current.adbak', `${magic}payload`)];
    const prompts = [];
    h.window.confirm = (text) => { prompts.push(text); return true; };
    const task = h.click('#history-backup-import');
    await new Promise((resolve) => setImmediate(resolve));
    await task;
    const imports = backupTransferActions(h).filter((item) => item.action === 'import');
    assert.equal(imports.length, 1, magic);
    assert.equal('allowLegacy' in imports[0], false, magic);
    assert.equal(prompts.some((text) => /이전 형식/.test(text)), false, magic);
  }
});

test('re-protecting a legacy backup needs the same confirmation and opt-in flag', async () => {
  const cancelled = createHarness();
  await chooseSource(cancelled, sourceHandle('legacy.adbak', 'ADBACK2\0payload'));
  enterSecrets(cancelled, 'A');
  let warning = '';
  cancelled.window.confirm = (text) => { warning = text; return false; };
  await cancelled.click('#history-reprotect');
  assert.match(warning, /ADBACK2 백업은 이전 형식/);
  assert.match(warning, /서명 없음 · 미검증/);
  assert.deepEqual(backupTransferActions(cancelled), []);
  assert.match(cancelled.element('#message').textContent, /재보호를 취소했습니다/);

  const accepted = createHarness();
  await chooseSource(accepted, sourceHandle('legacy.adbak', 'ADBACK2\0payload'));
  enterSecrets(accepted, 'B');
  accepted.window.confirm = () => true;
  const task = accepted.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const request = accepted.requestForAction('reprotect');
  assert.equal(JSON.parse(request.init.body).allowLegacy, true);
  request.resolve(reprotectResponse(accepted, 'QmFja3VwQg==', 'result-legacy'));
  await task;

  const current = createHarness();
  await chooseSource(current, sourceHandle('current.adbak', 'ADBACK7\0payload'));
  enterSecrets(current, 'C');
  current.window.confirm = () => { throw new Error('current formats must not prompt'); };
  const currentTask = current.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const currentRequest = current.requestForAction('reprotect');
  assert.equal('allowLegacy' in JSON.parse(currentRequest.init.body), false);
  currentRequest.resolve(reprotectResponse(current, 'QmFja3VwQw==', 'result-current'));
  await currentTask;
});

test('history list marks messages without a signature as unverified, in text', () => {
  const h = createHarness();
  h.evaluate(`selectedHistoryMessages = [
    {index: 0, time: 1, sender: '상대', text: 'signed message', signed: true},
    {index: 1, time: 2, sender: '상대', text: 'unsigned message', signed: false},
    {index: 2, time: 3, sender: '신원 변경', text: 'identity changed', signed: false},
    {index: 3, time: 4, sender: '상대', text: 'no flag from an older server'},
  ]; renderHistoryMessages()`);
  // The fake DOM has no childElementCount, so it also appends the empty-list
  // paragraph; only the four message cards matter here.
  const cards = h.element('#history-messages').children.slice(0, 4);
  const notes = cards.map((card) => card.children
    .filter((child) => child.className === 'unsigned-note')
    .map((child) => child.textContent));
  assert.deepEqual(notes, [[], ['서명 없음 · 미검증'], [], []]);
  // Order: selection, time, marker, body. The marker sits between the time and the text.
  const [, time, marker, body] = cards[1].children;
  assert.match(time.textContent, /\[상대\]/);
  assert.equal(marker.textContent, '서명 없음 · 미검증');
  assert.equal(body.children.map((child) => child.textContent).join(''), 'unsigned message');
});

test('a 401 for the active session ends it and returns to the connection-code screen', async () => {
  const h = createHarness();
  h.evaluate(`token = 'session-A'; identityId.textContent = 'identity-A'; sessionStorage.setItem(sessionKey, 'session-A'); show('active')`);
  const pending = h.evaluate("request('/api/history/list')");
  h.requestFor('/api/history/list').resolve(response('', 401));
  await pending;
  assert.equal(h.evaluate('token'), null);
  assert.equal(h.evaluate('sessionStorage.getItem(sessionKey)'), null);
  assert.equal(h.evaluate('bridgeForm.hidden'), false, 'the connection-code form is shown');
  assert.equal(h.evaluate('active.hidden'), true);
  assert.equal(h.evaluate('identityId.textContent'), '');
  assert.match(h.element('#message').textContent, /세션이 끝났습니다.*연결 코드/);
});

test('a 401 for an older session does not end the current one', async () => {
  const h = createHarness();
  h.evaluate("token = 'session-B'; identityId.textContent = 'identity-B'; show('active')");
  const pending = h.evaluate("request('/api/history/list', '', 'session-A')");
  h.requestFor('/api/history/list').resolve(response('', 401));
  await pending;
  assert.equal(h.evaluate('token'), 'session-B');
  assert.equal(h.evaluate('bridgeForm.hidden'), true);
  assert.equal(h.evaluate('active.hidden'), false);
});

test('a 412 means no identity is logged in: show the identity screen and keep the session', async () => {
  const h = createHarness();
  h.evaluate("token = 'session-A'; show('active')");
  const refreshing = h.evaluate('refreshIdentity()');
  h.requestFor('/api/identity/status').resolve(response('', 412));
  assert.equal(await refreshing, false);
  assert.equal(h.evaluate('token'), 'session-A', 'the session is untouched');
  assert.equal(h.evaluate('entry.hidden'), false, 'the identity login screen is shown');
  assert.equal(h.evaluate('bridgeForm.hidden'), true);
});

test('a 401 from the identity status check lands on the connection-code screen, not the identity screen', async () => {
  const h = createHarness();
  h.evaluate("token = 'session-A'; show('active')");
  const refreshing = h.evaluate('refreshIdentity()');
  h.requestFor('/api/identity/status').resolve(response('', 401));
  assert.equal(await refreshing, false);
  assert.equal(h.evaluate('token'), null);
  assert.equal(h.evaluate('bridgeForm.hidden'), false);
  assert.equal(h.evaluate('entry.hidden'), true);
});

test('logout ends the session and asks for the new connection code', async () => {
  const h = createHarness();
  h.evaluate(`token = 'session-A'; identityId.textContent = 'identity-A'; sessionStorage.setItem(sessionKey, 'session-A'); show('active')`);
  await h.click('#logout');
  assert.equal(h.evaluate('token'), null);
  assert.equal(h.evaluate('sessionStorage.getItem(sessionKey)'), null);
  assert.equal(h.evaluate('bridgeForm.hidden'), false);
  assert.match(h.element('#message').textContent, /로그아웃했습니다.*새로 표시된 연결 코드/);
});

test('polling stops when the session ends and does not retry with a dead token', async () => {
  const h = createHarness();
  h.evaluate("token = 'session-A'; identityId.textContent = 'identity-A'; operationId = 'operation-A'; show('chat')");
  const polling = h.evaluate('pollChat()');
  h.requestFor('/api/chat/status').resolve(response('', 401));
  await polling;
  assert.equal(h.evaluate('operationId'), null);
  assert.equal(h.evaluate('token'), null);
  await new Promise((resolve) => setTimeout(resolve, 450));
  assert.equal(h.requests.filter((item) => item.path === '/api/chat/status').length, 1,
    'no further poll is scheduled after the session ended');
});

test('the page keeps its styling in app.css so the content security policy needs no inline styles', () => {
  const html = fs.readFileSync(`${__dirname}/index.html`, 'utf8');
  assert.match(html, /<link rel="stylesheet" href="\/app\.css">/);
  assert.doesNotMatch(html, /<style[\s>]/);
  assert.doesNotMatch(html, /\sstyle="/);
  // Scripts may use the CSSOM (element.style.x = ...) but not set the attribute as text.
  const script = fs.readFileSync(`${__dirname}/app.js`, 'utf8');
  assert.doesNotMatch(script, /setAttribute\(\s*['"]style['"]/);
  assert.doesNotMatch(script, /\.cssText\s*=/);
  assert.doesNotMatch(script, /insertAdjacentHTML|\.innerHTML\s*=/);
});

test('the confirmation code is the prominent value and the long identifiers are folded away', () => {
  const html = fs.readFileSync(`${__dirname}/index.html`, 'utf8');
  const panel = html.slice(html.indexOf('<div id="verification"'), html.indexOf('<div id="identity-transition-panel"'));
  // The short code comes first and is not inside the collapsed details.
  const code = panel.indexOf('id="confirmation-code"');
  const details = panel.indexOf('<details');
  assert.ok(code > 0 && details > code, 'the code is shown before the folded details');
  const folded = panel.slice(details, panel.indexOf('</details>'));
  assert.match(folded, /id="peer-id"/);
  assert.match(folded, /id="fingerprint"/);
  assert.doesNotMatch(folded, /id="confirmation-code"/);
  // Users are told to compare all twelve digits, not a prefix.
  assert.match(panel, /12자리를 .*처음부터 끝까지 비교/);
  assert.match(panel, /앞부분만 맞춰 보고 확인하지 마세요/);
});

test('entering the verification phase shows the code from the server and the full fingerprint', () => {
  const h = createHarness();
  h.evaluate(`updateChatView({ phase: 'verification', peerId: 'ab'.repeat(32), fingerprint: 'cd'.repeat(32), confirmationCode: '123456 789012', messageCount: 0, messageEpoch: 1, identityTransition: [] })`);
  assert.equal(h.element('#verification').hidden, false);
  assert.equal(h.element('#confirmation-code').textContent, '123456 789012');
  assert.equal(h.element('#fingerprint').textContent, 'cd'.repeat(32));
  assert.equal(h.element('#peer-id').textContent, 'ab'.repeat(32));
  assert.equal(h.element('#confirm-peer').disabled, false);
});

test('a snapshot without a confirmation code shows an empty code, never the old fingerprint as the code', () => {
  const h = createHarness();
  h.evaluate(`updateChatView({ phase: 'verification', peerId: 'ab'.repeat(32), fingerprint: 'cd'.repeat(32), messageCount: 0, messageEpoch: 1, identityTransition: [] })`);
  assert.equal(h.element('#confirmation-code').textContent, '');
  assert.notEqual(h.element('#confirmation-code').textContent, 'cd'.repeat(32));
});

test('a relay acceptance is never worded as the peer having received the message', () => {
  const snapshot = (extra) => `updateChatView(${JSON.stringify({ phase: 'connected', messageCount: 0, messageEpoch: 1, identityTransition: [], ...extra })})`;
  const status = (h) => h.element('#delivery-status').textContent;

  const accepted = createHarness();
  accepted.evaluate(snapshot({ relayAck: 'accepted', pendingSends: 0 }));
  assert.match(status(accepted), /relay가 이벤트를 수락했습니다/);
  assert.match(status(accepted), /수신이나 저장을 뜻하지 않습니다/);
  assert.doesNotMatch(status(accepted), /전달되었|전달됨|받았|도착/, 'acceptance must not read as delivery');

  const pending = createHarness();
  pending.evaluate(snapshot({ relayAck: 'pending', pendingSends: 2 }));
  assert.match(status(pending), /relay 접수 확인 대기 중 \(2건\)/);
  assert.match(status(pending), /수신이나 저장은 확인되지 않습니다/);

  const rejected = createHarness();
  rejected.evaluate(snapshot({ relayAck: 'rejected', pendingSends: 0 }));
  assert.match(status(rejected), /relay가 이벤트를 거부했습니다/);

  const unknown = createHarness();
  unknown.evaluate(snapshot({ relayAck: 'unknown', pendingSends: 0 }));
  assert.match(status(unknown), /전달 결과를 확인할 수 없습니다/);

  // No status at all when the relay has said nothing.
  const none = createHarness();
  none.evaluate(snapshot({ pendingSends: 0 }));
  assert.equal(status(none), '');
  assert.equal(none.element('#delivery-status').hidden, true);
});
