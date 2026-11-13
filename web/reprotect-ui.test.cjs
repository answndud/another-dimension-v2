const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ReprotectWork = require('./reprotect-work.js');

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
  return {
    name,
    size: contents.length,
    dataUrl: `data:application/octet-stream;base64,${Buffer.from(contents).toString('base64')}`,
  };
}

function createHarness(options = {}) {
  const elements = new Map();
  const requests = [];
  const storage = new Map();
  const themeStorage = options.themeStorage || new Map();
  const element = (selector) => {
    if (!elements.has(selector)) {
      const target = {
        value: '', textContent: '', hidden: false, disabled: false, checked: false,
        dataset: {}, style: {}, listeners: {}, children: [],
        addEventListener(type, callback) { this.listeners[type] = callback; },
        querySelector(selector) { return element(`${selector} inside ${selector}`); },
        querySelectorAll() { return []; },
        replaceChildren(...children) { this.children = children; },
        append(...children) { this.children.push(...children); },
        appendChild(child) { this.children.push(child); return child; },
        focus() {}, click() {}, remove() {}, setAttribute() {},
        classList: { add() {}, remove() {}, toggle() {} },
      };
      elements.set(selector, target);
    }
    return elements.get(selector);
  };
  const document = {
    documentElement: { dataset: {}, setAttribute() {} },
    querySelector: element,
    querySelectorAll: () => [],
    createElement: (tag) => element(`created:${tag}:${elements.size}`),
    createTextNode: (text) => ({ textContent: text }),
  };
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
    requests.push({ path, init, ...pending });
    if (path === '/api/identity/logout') pending.resolve(response('ok'));
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
    window, document, fetch, sessionStorage, localStorage, FileReader, Uint8Array,
    atob: (value) => Buffer.from(value, 'base64').toString('binary'),
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
  return { element, window, click, requests, requestFor, evaluate, themeStorage, document };
}

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

function enterSecrets(harness, suffix) {
  harness.element('#history-reprotect-previous-code').value = `code-${suffix}`;
  harness.element('#history-reprotect-previous-password').value = `old-${suffix}`;
  harness.element('#history-reprotect-new-password').value = `replacement-${suffix}-secret`;
  harness.element('#history-reprotect-new-password-confirm').value = `replacement-${suffix}-secret`;
}

test('actual UI: light and dark themes toggle and persist across reloads', async () => {
  const themeStorage = new Map();
  const first = createHarness({ themeStorage });
  assert.equal(first.document.documentElement.dataset.theme, 'light');
  first.element('#bridge-code').value = 'local-connection-code';
  first.element('#identity-code').value = 'private-identity-code';
  first.element('#created-note').textContent = '코드 생성 상태';
  await first.click('#theme-toggle');
  assert.equal(first.document.documentElement.dataset.theme, 'dark');
  assert.equal(first.element('#theme-toggle').textContent, '라이트 모드');
  assert.equal(themeStorage.get('another-dimension-theme'), 'dark');
  assert.equal(first.element('#bridge-code').value, 'local-connection-code');
  assert.equal(first.element('#identity-code').value, 'private-identity-code');
  assert.equal(first.element('#created-note').textContent, '코드 생성 상태');

  const reopened = createHarness({ themeStorage });
  assert.equal(reopened.document.documentElement.dataset.theme, 'dark');
  assert.equal(reopened.element('#theme-toggle').textContent, '라이트 모드');
  await reopened.click('#theme-toggle');
  assert.equal(reopened.document.documentElement.dataset.theme, 'light');
  assert.equal(themeStorage.get('another-dimension-theme'), 'light');
});

test('actual UI: request A then B, and B completes before A', async () => {
  const h = createHarness();
  const original = sourceHandle('source.adbak', 'encrypted-source');
  await chooseSource(h, original);
  enterSecrets(h, 'A');
  const taskA = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const requestA = h.requestFor('/api/history/reprotect-backup');
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
  const requestB = h.requests.filter((item) => item.path === '/api/history/reprotect-backup')[1];
  requestB.resolve(response('QmFja3VwQg=='));
  await taskB;
  assert.equal(h.element('#history-reprotect-save').disabled, false);
  assert.match(h.element('#message').textContent, /새 백업을 만들었습니다/);

  requestA.resolve(response('QmFja3VwQQ=='));
  await taskA;
  assert.equal(h.element('#history-reprotect-save').disabled, false);

  const output = createOutputHandle();
  let pickerOptions;
  h.window.showSaveFilePicker = async (options) => { pickerOptions = options; return output; };
  const saveTask = h.click('#history-reprotect-save');
  await new Promise((resolve) => setImmediate(resolve));
  const verifyRequest = h.requestFor('/api/history/verify-backup');
  assert.deepEqual(JSON.parse(verifyRequest.init.body), {
    backup: 'QmFja3VwQg==', password: 'replacement-B-secret',
  });
  verifyRequest.resolve(response(JSON.stringify({ messageCount: 1 })));
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
  assert.equal(h.requests.some((item) => item.path === '/api/history/import-backup'), false);
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
      const oldRequest = h.requestFor('/api/history/reprotect-backup');

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
      oldRequest.resolve(response('U1RBTEU='));
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
        oldRequest = h.requestFor('/api/history/reprotect-backup');
      }
      await h.click('#logout');
      assert.equal(h.element('#history-reprotect-source').textContent, '선택한 파일 없음');
      assert.equal(h.element('#history-reprotect-save').disabled, true);
      const logoutStatus = h.element('#message').textContent;
      if (picker) picker.resolve([sourceHandle('late.adbak', 'late encrypted')]);
      if (oldRequest) oldRequest.resolve(response('T0xE'));
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
      const reprotect = h.requestFor('/api/history/reprotect-backup');
      reprotect.resolve(response('U0FWRQ=='));
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
      assert.equal(h.requests.filter((item) => item.path === '/api/history/verify-backup').length, 0);
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
  h.requestFor('/api/history/reprotect-backup').resolve(response('T1VUUFVU'));
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
  h.requestFor('/api/history/reprotect-backup').resolve(response('VkFMSUQ='));
  await validTask;
  assert.equal(h.element('#history-reprotect-save').disabled, false);

  enterSecrets(h, 'invalid');
  const failedTask = h.click('#history-reprotect');
  await new Promise((resolve) => setImmediate(resolve));
  const failedRequest = h.requests.filter((item) => item.path === '/api/history/reprotect-backup')[1];
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

test('actual UI: transfer consent and final merge consent are separate states', async () => {
  const h = createHarness();
  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-transfer-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 120000, historyRestoreEstimateBytes: 80000000,
    historyRestoreOfferCount: 0, historyRestoreOffer: [],
    historyRestoreStatus: 'estimate only'
  })`);
  assert.equal(h.element('#history-restore-accept').textContent, '전송 동의');
  assert.equal(h.element('#history-restore-accept').disabled, true);
  h.evaluate(`updateChatView({
    phase: 'connected', messageEpoch: 0, messages: [], peerId: 'peer', identityTransition: [],
    historyRestoreState: 'awaiting-merge-consent', historyRestoreInProgress: false,
    historyRestoreTotal: 120000, historyRestoreOfferCount: 120000,
    historyRestoreOffer: [], historyRestoreStatus: 'preview'
  })`);
  assert.equal(h.element('#history-restore-accept').textContent, '제안된 기록 병합');
  assert.equal(h.element('#history-restore-accept').disabled, false);
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
  assert.equal(h.element('#chat-status').textContent, '기록 병합 중이라 메시지를 전송하지 않았습니다. 병합 완료 후 다시 보내세요.');
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
