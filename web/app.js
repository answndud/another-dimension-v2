const bridgeForm = document.querySelector('#connect-form');
const bridgeCode = document.querySelector('#bridge-code');
const entry = document.querySelector('#identity-entry');
const loginForm = document.querySelector('#login-form');
const identityCode = document.querySelector('#identity-code');
const created = document.querySelector('#created');
const generatedCode = document.querySelector('#generated-code');
const active = document.querySelector('#identity-active');
const identityId = document.querySelector('#identity-id');
const inviteView = document.querySelector('#invite-view');
const inviteCode = document.querySelector('#invite-code');
const joinForm = document.querySelector('#join-form');
const joinCode = document.querySelector('#join-code');
const chatView = document.querySelector('#chat-view');
const chatStatus = document.querySelector('#chat-status');
const storageStatus = document.querySelector('#storage-status');
const historyList = document.querySelector('#history-list');
const historyDetail = document.querySelector('#history-detail');
const historyMessages = document.querySelector('#history-messages');
const historyFilter = document.querySelector('#history-filter');
const messageFilter = document.querySelector('#message-filter');
const verification = document.querySelector('#verification');
const sendForm = document.querySelector('#send-form');
const chatText = document.querySelector('#chat-text');
const conversation = document.querySelector('#conversation');
const message = document.querySelector('#message');
const sessionKey = 'local-bridge-session';
const operationKey = 'local-chat-operation';
let token = sessionStorage.getItem(sessionKey);
let currentInvite = '';
let operationId = null;
let messageCursor = 0;
let pollTimer = null;
let lastPhase = '';
let selectedHistoryPeer = '';
let selectedHistoryMessages = [];
let selectedHistoryIndices = new Set();

function show(view) {
  bridgeForm.hidden = view !== 'bridge';
  entry.hidden = view !== 'entry';
  created.hidden = view !== 'created';
  active.hidden = view !== 'active';
  inviteView.hidden = view !== 'invite';
  chatView.hidden = view !== 'chat';
  historyDetail.hidden = view !== 'history';
  if (view !== 'active') {
    document.querySelector('#added-code').value = '';
    document.querySelector('#added-code-view').hidden = true;
  }
}

async function request(path, body = '', session = token) {
  const headers = { 'Content-Type': 'text/plain;charset=UTF-8' };
  if (session) headers.Authorization = `Bearer ${session}`;
  return fetch(path, { method: 'POST', headers, body, cache: 'no-store' });
}

async function refreshIdentity() {
  const response = await request('/api/identity/status');
  if (response.status === 401) { show('entry'); return false; }
  if (!response.ok) throw new Error('status failed');
  identityId.textContent = await response.text();
  await refreshNetworkSettings();
  show('active');
  await refreshHistoryList();
  return true;
}

async function refreshNetworkSettings() {
  const response = await request('/api/settings/get');
  if (!response.ok) throw new Error('settings unavailable');
  const settings = await response.json();
  const modeChoice = document.querySelector('#network-mode-choice');
  const torAddress = document.querySelector('#tor-socks-address');
  const notificationChoice = document.querySelector('#notifications-enabled');
  const status = document.querySelector('#settings-status');
  modeChoice.value = settings.savedMode;
  torAddress.value = settings.socks || '127.0.0.1:9050';
  notificationChoice.checked = settings.notifications;
  document.querySelector('#tor-settings').hidden = modeChoice.value !== 'tor';
  document.querySelector('#network-mode').textContent = settings.activeMode === 'tor'
    ? `현재 연결: Tor SOCKS (${settings.activeSocks}) · 서비스를 Tor로 검증하지 않습니다.`
    : '현재 연결: 일반 연결 · relay에 실제 IP가 보일 수 있습니다.';
  status.textContent = settings.restartRequired
    ? '저장된 모드가 실행 중인 모드와 다릅니다. 터미널에서 프로그램을 종료하고 다시 실행하세요.'
    : '';
}

async function refreshHistoryList() {
  historyList.replaceChildren();
  let items;
  try {
    const response = await request('/api/history/list');
    if (!response.ok) throw new Error('history list unavailable');
    items = await response.json();
  } catch (_) {
    const error = document.createElement('p');
    error.className = 'meta';
    error.textContent = '대화 기록 목록을 불러오지 못했습니다.';
    historyList.append(error);
    return;
  }
  for (const item of items) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'history-item';
    button.dataset.peerId = item.peerId;
    const label = document.createElement('span');
    label.textContent = `대화 ${item.peerId.slice(0, 12)}`;
    const details = document.createElement('small');
    const lastMessage = item.lastMessage ? formatTime(item.lastMessage) : '메시지 없음';
    details.textContent = `${item.messageCount}개 메시지 · ${lastMessage}`;
    button.append(label, details);
    button.addEventListener('click', () => openHistory(item.peerId).catch(() => {
      message.textContent = '대화 기록을 열지 못했습니다.';
    }));
    historyList.append(button);
  }
  filterHistoryList();
  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'meta';
    empty.textContent = '저장된 대화가 없습니다.';
    historyList.append(empty);
  } else if (!historyList.querySelector('button:not([hidden])')) {
    const empty = document.createElement('p');
    empty.className = 'meta';
    empty.textContent = '검색 결과가 없습니다.';
    historyList.append(empty);
  }
}

function filterHistoryList() {
  const query = historyFilter.value.trim().toLowerCase();
  for (const item of historyList.querySelectorAll('button[data-peer-id]')) {
    item.hidden = !item.dataset.peerId.toLowerCase().includes(query);
  }
}

function renderHistoryMessages() {
  const query = messageFilter.value.trim().toLocaleLowerCase();
  historyMessages.replaceChildren();
  for (const item of selectedHistoryMessages) {
    if (query && !item.text.toLocaleLowerCase().includes(query)) continue;
    const card = document.createElement('article');
    card.className = `entry${item.sender === '나' ? ' mine' : ''}`;
    const selection = document.createElement('label');
    selection.className = 'message-select';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = selectedHistoryIndices.has(item.index);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) selectedHistoryIndices.add(item.index);
      else selectedHistoryIndices.delete(item.index);
      updateSelectionCount();
    });
    selection.append(checkbox, document.createTextNode('삭제 선택'));
    const time = document.createElement('time');
    time.dateTime = new Date(item.time * 1000).toISOString();
    time.textContent = `${formatTime(item.time)} [${item.sender}]`;
    const body = document.createElement('div');
    body.textContent = item.text;
    card.append(selection, time, body);
    historyMessages.append(card);
  }
  if (!historyMessages.childElementCount) {
    const empty = document.createElement('p');
    empty.className = 'meta';
    empty.textContent = query ? '검색 결과가 없습니다.' : '저장된 메시지가 없습니다.';
    historyMessages.append(empty);
  }
}

function updateSelectionCount() {
  document.querySelector('#selection-count').textContent = selectedHistoryIndices.size
    ? `${selectedHistoryIndices.size}개 메시지 선택됨`
    : '선택한 메시지 없음';
}

async function openHistory(peerId) {
  const response = await request('/api/history/messages', peerId);
  if (!response.ok) { message.textContent = '대화 기록을 열지 못했습니다.'; return; }
  selectedHistoryPeer = peerId;
  selectedHistoryMessages = await response.json();
  selectedHistoryIndices.clear();
  document.querySelector('#history-peer').textContent = peerId;
  messageFilter.value = '';
  updateSelectionCount();
  renderHistoryMessages();
  show('history');
}

function stopPolling() {
  if (pollTimer) clearTimeout(pollTimer);
  pollTimer = null;
}

function formatTime(seconds) {
  const date = new Date(seconds * 1000);
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function appendMessages(items) {
  for (const item of items) {
    const card = document.createElement('article');
    card.className = `entry${item.sender === '나' ? ' mine' : ''}`;
    const time = document.createElement('time');
    time.dateTime = new Date(item.time * 1000).toISOString();
    time.textContent = `${formatTime(item.time)} [${item.sender}]`;
    const body = document.createElement('div');
    body.textContent = item.text;
    card.append(time, body);
    conversation.append(card);
    messageCursor += 1;
  }
  if (items.length) conversation.scrollTop = conversation.scrollHeight;
}

function updateChatView(snapshot) {
  const labels = {
    connecting: 'relay에 연결하고 상대를 찾는 중입니다.',
    verification: '상대 공개 키와 지문을 별도 경로로 비교하세요.',
    confirming: '상대 확인 응답을 기다리는 중입니다.',
    connected: '연결되었습니다. relay는 IP 주소와 연결 시각·통신량을 볼 수 있습니다.',
    disconnected: snapshot.error || '연결이 끊겼습니다.',
    failed: snapshot.error || '연결에 실패했습니다.',
    closed: '연결이 종료되었습니다.'
  };
  chatStatus.textContent = labels[snapshot.phase] || snapshot.error || '연결 상태를 확인하는 중입니다.';
  const deliveryStatus = document.querySelector('#delivery-status');
  const deliveryLabels = {
    pending: `relay 접수 확인 대기 중${snapshot.pendingSends > 1 ? ` (${snapshot.pendingSends}건)` : ''}. 상대방의 수신이나 저장은 확인되지 않습니다.`,
    accepted: 'relay가 이벤트를 수락했습니다. 상대방의 수신이나 저장을 뜻하지 않습니다.',
    rejected: 'relay가 이벤트를 거부했습니다. 상대방에게 전달되지 않았습니다.',
    unknown: '마지막 메시지의 전달 결과를 확인할 수 없습니다. 로컬 기록을 확인하고 다시 보낼 때는 중복 가능성을 고려하세요.'
  };
  deliveryStatus.textContent = snapshot.pendingSends > 0
    ? `relay 접수 확인 대기 중 (${snapshot.pendingSends}건). 상대방의 수신이나 저장은 확인되지 않습니다.`
    : deliveryLabels[snapshot.relayAck] || '';
  deliveryStatus.hidden = !deliveryStatus.textContent;
  storageStatus.hidden = !snapshot.storageError;
  storageStatus.textContent = snapshot.storageError || '';
  verification.hidden = snapshot.phase !== 'verification';
  sendForm.hidden = snapshot.phase !== 'connected';
  if (snapshot.phase === 'verification' && lastPhase !== 'verification') {
    document.querySelector('#peer-id').textContent = snapshot.peerId || '';
    document.querySelector('#fingerprint').textContent = snapshot.fingerprint || '';
    document.querySelector('#confirm-peer').disabled = false;
  }
  if (snapshot.phase === 'confirming') document.querySelector('#confirm-peer').disabled = true;
  if (snapshot.phase === 'connected') document.querySelector('#chat-title').textContent = '대화';
  if (snapshot.phase === 'disconnected' || snapshot.phase === 'failed' || snapshot.phase === 'closed') {
    sendForm.hidden = true;
    stopPolling();
  }
  lastPhase = snapshot.phase;
}

async function pollChat() {
  if (!operationId) return;
  try {
    const response = await request('/api/chat/status', operationId);
    if (!response.ok) throw new Error('status unavailable');
    const snapshot = await response.json();
    updateChatView(snapshot);
    if (snapshot.messageCount > messageCursor) {
      const messages = await request('/api/chat/messages', `${operationId}\n${messageCursor}`);
      if (!messages.ok) throw new Error('messages unavailable');
      appendMessages(await messages.json());
    }
  } catch (_) {
    chatStatus.textContent = '로컬 프로그램에서 연결 상태를 읽지 못했습니다.';
  }
  if (operationId && !['failed', 'disconnected', 'closed'].includes(lastPhase)) {
    pollTimer = setTimeout(pollChat, 350);
  }
}

async function attachChat(id) {
  stopPolling();
  operationId = id;
  sessionStorage.setItem(operationKey, operationId);
  messageCursor = 0;
  lastPhase = '';
  conversation.replaceChildren();
  document.querySelector('#chat-title').textContent = '대화 연결';
  document.querySelector('#confirm-peer').disabled = false;
  show('chat');
  await pollChat();
}

async function startChat(path, code) {
  message.textContent = '';
  try {
    const response = await request(path, code);
    if (!response.ok) {
      message.textContent = response.status === 401
        ? '로그인이 필요합니다.'
        : response.status === 409
          ? '연결 모드 설정을 적용하려면 터미널에서 프로그램을 종료한 뒤 다시 실행하세요.'
          : '초대 코드를 확인하거나 relay 연결을 다시 시도하세요.';
      return;
    }
    await attachChat(await response.text());
  } catch (_) {
    message.textContent = '연결을 시작하지 못했습니다.';
  }
}

async function restoreSession() {
  if (!token) { show('bridge'); return; }
  try {
    if ((await request('/api/session')).ok && await refreshIdentity()) {
      const savedOperation = sessionStorage.getItem(operationKey);
      if (savedOperation) {
        const status = await request('/api/chat/status', savedOperation);
        if (status.ok) { await attachChat(savedOperation); return; }
        sessionStorage.removeItem(operationKey);
      }
      return;
    }
    token = null;
    sessionStorage.removeItem(sessionKey);
    sessionStorage.removeItem(operationKey);
    show('bridge');
  } catch (_) {
    show('bridge');
    message.textContent = '로컬 프로그램에 연결할 수 없습니다.';
  }
}

bridgeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';
  try {
    const response = await request('/api/connect', bridgeCode.value.trim(), null);
    bridgeCode.value = '';
    if (!response.ok) { message.textContent = '연결할 수 없습니다. 터미널에서 새 코드를 발급받으세요.'; return; }
    token = await response.text();
    sessionStorage.setItem(sessionKey, token);
    await refreshIdentity();
  } catch (_) { message.textContent = '로컬 프로그램에 연결할 수 없습니다.'; }
});

document.querySelector('#create').addEventListener('click', async () => {
  message.textContent = '';
  try {
    const response = await request('/api/identity/create');
    if (!response.ok) { message.textContent = '코드를 생성할 수 없습니다.'; return; }
    generatedCode.value = await response.text();
    show('created');
  } catch (_) { message.textContent = '코드를 생성할 수 없습니다.'; }
});

document.querySelector('#copy-code').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(generatedCode.value); message.textContent = '코드를 복사했습니다.'; }
  catch (_) { message.textContent = '복사하지 못했습니다. 코드를 직접 선택해 복사하세요.'; }
});

document.querySelector('#save-code').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([generatedCode.value + '\n'], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'another-dimension-code.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  message.textContent = '코드 저장을 요청했습니다.';
});

document.querySelector('#continue').addEventListener('click', async () => {
  generatedCode.value = '';
  message.textContent = '';
  try { await refreshIdentity(); } catch (_) { message.textContent = '신원을 확인할 수 없습니다.'; }
});

document.querySelector('#add-code').addEventListener('click', async () => {
  message.textContent = '';
  try {
    const response = await request('/api/identity/add-code');
    if (!response.ok) { message.textContent = '새 코드를 발급하지 못했습니다.'; return; }
    document.querySelector('#added-code').value = await response.text();
    document.querySelector('#added-code-view').hidden = false;
  } catch (_) { message.textContent = '새 코드를 발급하지 못했습니다.'; }
});

document.querySelector('#copy-added-code').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(document.querySelector('#added-code').value);
    message.textContent = '코드를 복사했습니다.';
  } catch (_) { message.textContent = '복사하지 못했습니다. 코드를 직접 선택해 복사하세요.'; }
});

document.querySelector('#save-added-code').addEventListener('click', () => {
  const value = document.querySelector('#added-code').value;
  const url = URL.createObjectURL(new Blob([value + '\n'], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'another-dimension-code.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  message.textContent = '코드 저장을 요청했습니다.';
});

document.querySelector('#close-added-code').addEventListener('click', () => {
  document.querySelector('#added-code').value = '';
  document.querySelector('#added-code-view').hidden = true;
});

document.querySelector('#network-mode-choice').addEventListener('change', (event) => {
  document.querySelector('#tor-settings').hidden = event.target.value !== 'tor';
});

document.querySelector('#save-settings').addEventListener('click', async () => {
  const mode = document.querySelector('#network-mode-choice').value;
  const socks = document.querySelector('#tor-socks-address').value.trim();
  const notifications = document.querySelector('#notifications-enabled').checked;
  const status = document.querySelector('#settings-status');
  try {
    const response = await request('/api/settings/save', JSON.stringify({ mode, socks, notifications }));
    if (response.status === 409) {
      status.textContent = '연결 중인 대화를 먼저 종료하세요.';
      return;
    }
    if (!response.ok) {
      status.textContent = '설정을 저장하지 못했습니다. SOCKS 주소를 확인하세요.';
      return;
    }
    const saved = await response.json();
    status.textContent = saved.restartRequired
      ? '설정을 저장했습니다. 모드 적용을 위해 터미널에서 프로그램을 종료한 뒤 다시 실행하세요. 터미널의 새 주소와 로컬 연결 코드를 사용하고, 다시 연 화면에서 개인 접속 코드로 로그인하세요.'
      : '설정을 저장했습니다.';
    document.querySelector('#network-mode').textContent = saved.activeMode === 'tor'
      ? `현재 연결: Tor SOCKS (${saved.activeSocks}) · 서비스를 Tor로 검증하지 않습니다.`
      : '현재 연결: 일반 연결 · relay에 실제 IP가 보일 수 있습니다.';
  } catch (_) {
    status.textContent = '설정을 저장하지 못했습니다.';
  }
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';
  try {
    const response = await request('/api/identity/login', identityCode.value.trim());
    identityCode.value = '';
    if (!response.ok) { message.textContent = '코드 형식을 확인하세요. 이미 로그인되어 있다면 새로고침하세요.'; return; }
    await refreshIdentity();
  } catch (_) { identityCode.value = ''; message.textContent = '로그인할 수 없습니다.'; }
});

document.querySelector('#logout').addEventListener('click', async () => {
  try {
    if (!(await request('/api/identity/logout')).ok) throw new Error('logout failed');
    stopPolling();
    operationId = null;
    sessionStorage.removeItem(operationKey);
    identityId.textContent = '';
    selectedHistoryPeer = '';
    selectedHistoryMessages = [];
    historyMessages.replaceChildren();
    historyList.replaceChildren();
    show('entry');
    message.textContent = '';
  } catch (_) { message.textContent = '로그아웃하지 못했습니다. 로컬 프로그램을 종료하세요.'; }
});

document.querySelectorAll('.disconnect').forEach((button) => button.addEventListener('click', async () => {
  try {
    const response = await request('/api/disconnect');
    if (!response.ok && response.status !== 401) throw new Error('disconnect failed');
  } catch (_) { message.textContent = '연결을 해제하지 못했습니다. 로컬 프로그램을 종료하세요.'; return; }
  token = null;
  sessionStorage.removeItem(sessionKey);
  identityId.textContent = '';
  show('bridge');
  message.textContent = '터미널에서 새 코드를 발급받으세요.';
}));

document.querySelector('#create-invite').addEventListener('click', async () => {
  message.textContent = '';
  try {
    const response = await request('/api/invite/create');
    if (response.status === 409) { message.textContent = '연결 모드 설정을 적용하려면 프로그램을 다시 실행하세요.'; return; }
    if (!response.ok) throw new Error('invite generation failed');
    currentInvite = await response.text();
    inviteCode.value = currentInvite;
    show('invite');
  } catch (_) { message.textContent = '초대 코드를 생성할 수 없습니다.'; }
});

document.querySelector('#copy-invite').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(currentInvite); message.textContent = '초대 코드를 복사했습니다.'; }
  catch (_) { message.textContent = '복사하지 못했습니다. 코드를 직접 선택해 복사하세요.'; }
});

document.querySelector('#save-invite').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([currentInvite + '\n'], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'another-dimension-invite.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  message.textContent = '초대 코드 저장을 요청했습니다.';
});

document.querySelector('#start-room').addEventListener('click', async () => {
  const code = currentInvite;
  inviteCode.value = '';
  currentInvite = '';
  await startChat('/api/chat/create', code);
});

document.querySelector('#discard-invite').addEventListener('click', () => {
  inviteCode.value = '';
  currentInvite = '';
  show('active');
});

joinForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const code = joinCode.value.trim();
  joinCode.value = '';
  if (code.startsWith('ADI1-')) {
    message.textContent = '이 초대 코드는 이전 연결 프로토콜용입니다. 두 기기에서 같은 앱 버전을 사용해 새 코드를 만드세요.';
    return;
  }
  await startChat('/api/chat/join', code);
});

document.querySelector('#confirm-peer').addEventListener('click', async () => {
  if (!operationId) return;
  try {
    const response = await request('/api/chat/confirm', operationId);
    if (!response.ok) throw new Error('confirmation failed');
    chatStatus.textContent = '상대 확인 응답을 기다리는 중입니다.';
    document.querySelector('#confirm-peer').disabled = true;
  } catch (_) { chatStatus.textContent = '확인 요청을 보내지 못했습니다.'; }
});

sendForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!operationId || !chatText.value.trim()) return;
  const body = `${operationId}\n${chatText.value}`;
  try {
    const response = await request('/api/chat/send', body);
    if (!response.ok) throw new Error('send failed');
    chatText.value = '';
    chatText.focus();
  } catch (_) { chatStatus.textContent = '메시지를 보낼 수 없습니다.'; }
});

document.querySelector('#close-chat').addEventListener('click', async () => {
  if (operationId) await request('/api/chat/cancel', operationId).catch(() => {});
  stopPolling();
  operationId = null;
  sessionStorage.removeItem(operationKey);
  conversation.replaceChildren();
  show('active');
  refreshHistoryList().catch(() => {});
});

historyFilter.addEventListener('input', filterHistoryList);
messageFilter.addEventListener('input', renderHistoryMessages);
document.querySelector('#history-back').addEventListener('click', () => show('active'));
document.querySelector('#history-export').addEventListener('click', () => {
  const lines = selectedHistoryMessages.map((item) => `${formatTime(item.time)} [${item.sender}]: ${item.text}`);
  const url = URL.createObjectURL(new Blob([lines.join('\n') + (lines.length ? '\n' : '')], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `another-dimension-${selectedHistoryPeer.slice(0, 12)}.txt`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

document.querySelector('#history-backup-export').addEventListener('click', async () => {
  const passwordField = document.querySelector('#history-backup-export-password');
  const confirmationField = document.querySelector('#history-backup-export-password-confirm');
  const password = passwordField.value;
  if (password !== confirmationField.value) {
    passwordField.value = '';
    confirmationField.value = '';
    message.textContent = '백업 비밀번호가 일치하지 않습니다.';
    return;
  }
  if (password && [...password].length < 12) {
    passwordField.value = '';
    confirmationField.value = '';
    message.textContent = '백업 비밀번호는 12자 이상이어야 합니다.';
    return;
  }
  try {
    const response = await request('/api/history/export-backup', JSON.stringify({ peerId: selectedHistoryPeer, password }));
    if (response.status === 409) { message.textContent = '먼저 해당 대화의 연결을 종료한 뒤 다시 시도하세요.'; return; }
    if (!response.ok) { message.textContent = '암호화 백업을 만들지 못했습니다.'; return; }
    const binary = atob(await response.text());
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'another-dimension-backup.adbak';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message.textContent = '암호화 백업 파일을 저장했습니다.';
  } catch (_) {
    message.textContent = '암호화 백업을 저장하지 못했습니다.';
  } finally {
    passwordField.value = '';
    confirmationField.value = '';
  }
});

document.querySelector('#history-backup-import').addEventListener('click', async () => {
  const file = document.querySelector('#history-backup-file').files[0];
  const passwordField = document.querySelector('#history-backup-import-password');
  const password = passwordField.value;
  if (!file) {
    passwordField.value = '';
    message.textContent = '가져올 백업 파일을 선택하세요.';
    return;
  }
  if (file.size > 16 * 1024 * 1024) {
    passwordField.value = '';
    message.textContent = '백업 파일은 16 MB 이하여야 합니다.';
    return;
  }
  if (password && [...password].length < 12) {
    passwordField.value = '';
    message.textContent = '백업 비밀번호는 12자 이상이어야 합니다.';
    return;
  }
  try {
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
    const encoded = String(dataUrl).slice(String(dataUrl).indexOf(',') + 1);
    const response = await request('/api/history/import-backup', JSON.stringify({ backup: encoded, password }));
    if (response.status === 409) { message.textContent = '먼저 모든 대화 연결을 종료한 뒤 다시 시도하세요.'; return; }
    if (!response.ok) { message.textContent = '파일, 비밀번호 또는 신원 코드가 맞지 않습니다.'; return; }
    const result = await response.json();
    document.querySelector('#history-backup-file').value = '';
    await refreshHistoryList();
    await openHistory(result.peerId);
    message.textContent = '백업을 확인해 기존 기록과 병합했습니다.';
  } catch (_) {
    message.textContent = '백업 파일을 읽지 못했습니다.';
  } finally {
    passwordField.value = '';
  }
});

async function reloadHistoryDetail() {
  await openHistory(selectedHistoryPeer);
  await refreshHistoryList();
}

async function deleteHistoryRange(start, end, prompt) {
  if (!selectedHistoryPeer || !window.confirm(prompt)) return;
  const response = await request('/api/history/delete-range', `${selectedHistoryPeer}\n${start}\n${end}`);
  if (response.status === 409) {
    message.textContent = '먼저 해당 대화의 연결을 종료한 뒤 다시 시도하세요.';
    return;
  }
  if (!response.ok) { message.textContent = '기록을 삭제하지 못했습니다.'; return; }
  await reloadHistoryDetail();
  message.textContent = '선택한 기간의 기록을 삭제했습니다.';
}

document.querySelector('#delete-selected').addEventListener('click', async () => {
  if (!selectedHistoryIndices.size) return;
  const count = selectedHistoryIndices.size;
  if (!window.confirm(`선택한 메시지 ${count}개를 이 기기에서 삭제할까요?`)) return;
  const response = await request('/api/history/delete-messages', JSON.stringify({
    peerId: selectedHistoryPeer,
    indices: [...selectedHistoryIndices]
  }));
  if (response.status === 409) {
    message.textContent = '먼저 해당 대화의 연결을 종료한 뒤 다시 시도하세요.';
    return;
  }
  if (!response.ok) { message.textContent = '기록을 삭제하지 못했습니다.'; return; }
  await reloadHistoryDetail();
  message.textContent = `${count}개 메시지를 삭제했습니다.`;
});

document.querySelector('#delete-range').addEventListener('click', async () => {
  const from = document.querySelector('#delete-from').value;
  const to = document.querySelector('#delete-to').value;
  if (!from || !to || from > to) { message.textContent = '올바른 시작일과 종료일을 선택하세요.'; return; }
  const start = Math.floor(new Date(`${from}T00:00:00`).getTime() / 1000);
  const end = Math.floor(new Date(`${to}T23:59:59.999`).getTime() / 1000);
  await deleteHistoryRange(start, end, `${from}부터 ${to}까지의 메시지를 이 기기에서 삭제할까요?`);
});

document.querySelector('#keep-recent').addEventListener('click', async () => {
  const days = Number(document.querySelector('#keep-days').value);
  if (!Number.isInteger(days) || days < 1 || days > 36500) {
    message.textContent = '보관할 기간을 1일 이상 입력하세요.';
    return;
  }
  const cutoff = Math.floor(Date.now() / 1000) - days * 86400;
  await deleteHistoryRange(0, cutoff, `최근 ${days}일 이전의 메시지를 이 기기에서 삭제할까요?`);
});

document.querySelector('#delete-conversation').addEventListener('click', async () => {
  if (!selectedHistoryPeer || !window.confirm('이 대화의 모든 기록을 이 기기에서 삭제할까요? 상대방 기록과 백업은 삭제되지 않습니다.')) return;
  const response = await request('/api/history/delete-conversation', selectedHistoryPeer);
  if (response.status === 409) {
    message.textContent = '먼저 해당 대화의 연결을 종료한 뒤 다시 시도하세요.';
    return;
  }
  if (!response.ok) { message.textContent = '대화를 삭제하지 못했습니다.'; return; }
  selectedHistoryPeer = '';
  selectedHistoryMessages = [];
  selectedHistoryIndices.clear();
  show('active');
  await refreshHistoryList();
  message.textContent = '대화 기록을 삭제했습니다.';
});

restoreSession();
