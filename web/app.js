const bridgeForm = document.querySelector('#connect-form');
const bridgeCode = document.querySelector('#bridge-code');
const entry = document.querySelector('#identity-entry');
const loginForm = document.querySelector('#login-form');
const identityCode = document.querySelector('#identity-code');
const created = document.querySelector('#created');
const generatedCode = document.querySelector('#generated-code');
const active = document.querySelector('#identity-active');
const identityId = document.querySelector('#identity-id');
const message = document.querySelector('#message');
const storageKey = 'local-bridge-session';
let token = sessionStorage.getItem(storageKey);

function show(view) {
  bridgeForm.hidden = view !== 'bridge';
  entry.hidden = view !== 'entry';
  created.hidden = view !== 'created';
  active.hidden = view !== 'active';
}

async function request(path, body = '', session = token) {
  const headers = { 'Content-Type': 'text/plain;charset=UTF-8' };
  if (session) headers.Authorization = `Bearer ${session}`;
  return fetch(path, { method: 'POST', headers, body, cache: 'no-store' });
}

async function refreshIdentity() {
  const response = await request('/api/identity/status');
  if (response.status === 401) { show('entry'); return; }
  if (!response.ok) throw new Error('status failed');
  identityId.textContent = await response.text();
  show('active');
}

async function restoreSession() {
  if (!token) { show('bridge'); return; }
  try {
    if ((await request('/api/session')).ok) { await refreshIdentity(); return; }
    token = null;
    sessionStorage.removeItem(storageKey);
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
    sessionStorage.setItem(storageKey, token);
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
  sessionStorage.removeItem(storageKey);
  identityId.textContent = '';
  show('bridge');
  message.textContent = '터미널에서 새 코드를 발급받으세요.';
}));

restoreSession();
