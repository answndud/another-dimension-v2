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

function file(name, contents) {
  return {
    name,
    size: contents.length,
    dataUrl: `data:application/octet-stream;base64,${Buffer.from(contents).toString('base64')}`,
  };
}

function createHarness() {
  const elements = new Map();
  const requests = [];
  const storage = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) {
      const target = {
        value: '', textContent: '', hidden: false, disabled: false, checked: false,
        dataset: {}, style: {}, listeners: {}, children: [],
        addEventListener(type, callback) { this.listeners[type] = callback; },
        querySelector(selector) { return element(`${selector} inside ${selector}`); },
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
    querySelector: element,
    querySelectorAll: () => [],
    createElement: (tag) => element(`created:${tag}:${elements.size}`),
    createTextNode: (text) => ({ textContent: text }),
  };
  const window = {
    ReprotectWork,
    confirm: () => false,
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
  const context = {
    window, document, fetch, sessionStorage, FileReader, Uint8Array,
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
  return { element, window, click, requests, requestFor, evaluate };
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
  h.evaluate("selectedHistoryPeer = 'peer'; historyPageVersion = 'old-version'; selectedHistoryIndices.add(4)");
  const deletion = h.click('#delete-selected');
  await new Promise((resolve) => setImmediate(resolve));
  const request = h.requestFor('/api/history/delete-messages');
  assert.equal(JSON.parse(request.init.body).version, 'old-version');
  request.resolve(response('history changed; reload before applying selection', 409));
  await deletion;
  assert.equal(h.element('#message').textContent, 'history changed; reload before applying selection');
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
