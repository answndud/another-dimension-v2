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

function show(view) {
  bridgeForm.hidden = view !== 'bridge';
  entry.hidden = view !== 'entry';
  created.hidden = view !== 'created';
  active.hidden = view !== 'active';
  inviteView.hidden = view !== 'invite';
  chatView.hidden = view !== 'chat';
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
  show('active');
  return true;
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
    disconnected: '연결이 끊겼습니다.',
    failed: snapshot.error || '연결에 실패했습니다.',
    closed: '연결이 종료되었습니다.'
  };
  chatStatus.textContent = labels[snapshot.phase] || snapshot.error || '연결 상태를 확인하는 중입니다.';
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
      message.textContent = response.status === 401 ? '로그인이 필요합니다.' : '초대 코드를 확인하거나 relay 연결을 다시 시도하세요.';
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
});

restoreSession();
