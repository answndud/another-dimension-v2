const bridgeForm = document.querySelector('#connect-form');
const bridgeCode = document.querySelector('#bridge-code');
const entry = document.querySelector('#identity-entry');
const loginForm = document.querySelector('#login-form');
const identityCode = document.querySelector('#identity-code');
const created = document.querySelector('#created');
const generatedCode = document.querySelector('#generated-code');
const createdNote = document.querySelector('#created-note');
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
const restoreJobKey = 'local-history-restore-job';
const historyDeleteJobKey = 'local-history-delete-jobs';
let token = sessionStorage.getItem(sessionKey);
let currentInvite = '';
let operationId = null;
let latestChatSnapshot = null;
let messageCursor = 0;
let messageEpoch = null;
let pollTimer = null;
let pollGeneration = 0;
let lastPhase = '';
let sendingMessage = false;
let selectedHistoryPeer = '';
let selectedHistoryMessages = [];
let selectedHistoryIndices = new Set();
let historyCursorStack = [null];
let historyNextCursor = null;
let historyPageVersion = null;
const historyDeletionPollers = new Set();
const historyPageSize = 50;
let verifiedPeers = new Set();
let reprotectSourceHandle = null;
let reprotectSourceName = '';
let reprotectOutput = null;
let reprotectPassword = '';
const reprotectWork = new window.ReprotectWork();
let historySummaries = [];
let dismissedTransitionKey = '';

function clearReprotectSecrets() {
  document.querySelector('#history-reprotect-previous-code').value = '';
  document.querySelector('#history-reprotect-previous-password').value = '';
  document.querySelector('#history-reprotect-new-password').value = '';
  document.querySelector('#history-reprotect-new-password-confirm').value = '';
}

function clearReprotectState() {
  reprotectWork.begin();
  clearReprotectSecrets();
  reprotectSourceHandle = null;
  reprotectSourceName = '';
  reprotectOutput = null;
  reprotectPassword = '';
  const source = document.querySelector('#history-reprotect-source');
  if (source) source.textContent = '선택한 파일 없음';
  const save = document.querySelector('#history-reprotect-save');
  if (save) save.disabled = true;
}

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
  const currentIdentityId = await response.text();
  const previousIdentityId = identityId.textContent.trim();
  if (previousIdentityId && previousIdentityId !== currentIdentityId) {
    if (latestChatSnapshot && ['merge-queued', 'merging'].includes(latestChatSnapshot.historyRestoreState) && operationId) {
      rememberRestoreJob(operationId);
    }
    stopPolling();
    operationId = null;
    latestChatSnapshot = null;
    sessionStorage.removeItem(operationKey);
    conversation.replaceChildren();
    chatStatus.textContent = '';
    document.querySelector('#history-restore-panel').hidden = true;
    setHistoryDeletionBusy(false);
  }
  identityId.textContent = currentIdentityId;
  await refreshNetworkSettings();
  show('active');
  await refreshHistoryList();
  resumeHistoryDeletions(currentIdentityId);
  const savedJob = getRestoreJob(currentIdentityId);
  if (savedJob && typeof savedJob.operationId === 'string') {
    if (sessionStorage.getItem(operationKey) !== savedJob.operationId) {
      await attachChat(savedJob.operationId);
    }
  }
  return true;
}

function readRestoreJobs() {
  try {
    const value = JSON.parse(sessionStorage.getItem(restoreJobKey) || '{}');
    if (value && value.jobs && typeof value.jobs === 'object') return value.jobs;
    if (value && typeof value.operationId === 'string' && typeof value.identityId === 'string') {
      const jobs = { [value.identityId]: value.operationId };
      sessionStorage.setItem(restoreJobKey, JSON.stringify({ jobs }));
      return jobs;
    }
  } catch (_) {}
  return {};
}

function getRestoreJob(ownerIdentityId) {
  const operationId = readRestoreJobs()[ownerIdentityId];
  return typeof operationId === 'string' ? { operationId, identityId: ownerIdentityId } : null;
}

function rememberRestoreJob(operationId) {
  const ownerIdentityId = identityId.textContent.trim();
  if (!operationId || !ownerIdentityId) return;
  const jobs = readRestoreJobs();
  jobs[ownerIdentityId] = operationId;
  sessionStorage.setItem(restoreJobKey, JSON.stringify({ jobs }));
}

function forgetRestoreJob(ownerIdentityId, expectedOperationId = null) {
  if (!ownerIdentityId) return;
  const jobs = readRestoreJobs();
  if (expectedOperationId && jobs[ownerIdentityId] !== expectedOperationId) return;
  delete jobs[ownerIdentityId];
  if (Object.keys(jobs).length) sessionStorage.setItem(restoreJobKey, JSON.stringify({ jobs }));
  else sessionStorage.removeItem(restoreJobKey);
}

function readHistoryDeletionJobs() {
  try {
    const value = JSON.parse(sessionStorage.getItem(historyDeleteJobKey) || '{}');
    return value && value.jobs && typeof value.jobs === 'object' ? value.jobs : {};
  } catch (_) { return {}; }
}

function rememberHistoryDeletion(job) {
  const jobs = readHistoryDeletionJobs();
  const ownerJobs = Array.isArray(jobs[job.identityId]) ? jobs[job.identityId] : [];
  if (!ownerJobs.some((item) => item.operationId === job.operationId)) ownerJobs.push(job);
  jobs[job.identityId] = ownerJobs;
  sessionStorage.setItem(historyDeleteJobKey, JSON.stringify({ jobs }));
}

function forgetHistoryDeletion(ownerIdentityId, operationId) {
  const jobs = readHistoryDeletionJobs();
  const remaining = (Array.isArray(jobs[ownerIdentityId]) ? jobs[ownerIdentityId] : [])
    .filter((job) => job.operationId !== operationId);
  if (remaining.length) jobs[ownerIdentityId] = remaining;
  else delete jobs[ownerIdentityId];
  if (Object.keys(jobs).length) sessionStorage.setItem(historyDeleteJobKey, JSON.stringify({ jobs }));
  else sessionStorage.removeItem(historyDeleteJobKey);
}

function setHistoryDeletionBusy(busy) {
  for (const selector of ['#delete-selected', '#delete-range', '#keep-recent', '#delete-conversation']) {
    document.querySelector(selector).disabled = busy;
  }
}

function newHistoryDeletionId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}

function resumeHistoryDeletions(ownerIdentityId) {
  const jobs = readHistoryDeletionJobs();
  for (const job of Array.isArray(jobs[ownerIdentityId]) ? jobs[ownerIdentityId] : []) {
    pollHistoryDeletion(job);
  }
}

async function pollHistoryDeletion(job) {
  const pollerKey = `${job.identityId}:${job.operationId}`;
  if (historyDeletionPollers.has(pollerKey)) return;
  historyDeletionPollers.add(pollerKey);
  if (identityId.textContent.trim() === job.identityId) {
    setHistoryDeletionBusy(true);
    message.textContent = '기록 삭제를 진행 중입니다. 완료 상태를 확인하고 있습니다.';
  }
  try {
    while (identityId.textContent.trim() === job.identityId) {
      let response;
      try {
        response = await request('/api/history/delete-status', job.operationId);
      } catch (_) {
        if (identityId.textContent.trim() !== job.identityId) return;
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      if (identityId.textContent.trim() !== job.identityId) return;
      if (response.status === 404) {
        forgetHistoryDeletion(job.identityId, job.operationId);
        message.textContent = '삭제 작업 결과를 찾을 수 없습니다. 프로그램이 재시작됐거나 작업이 만료됐을 수 있습니다.';
        break;
      }
      if (!response.ok) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      const snapshot = await response.json();
      if (identityId.textContent.trim() !== job.identityId) return;
      if (snapshot.state === 'queued' || snapshot.state === 'running') {
        message.textContent = '기록 삭제를 진행 중입니다. 다른 대화 작업은 계속 사용할 수 있습니다.';
        await new Promise((resolve) => setTimeout(resolve, 300));
        continue;
      }
      forgetHistoryDeletion(job.identityId, job.operationId);
      if (snapshot.state === 'completed') {
        if (selectedHistoryPeer.toLowerCase() === job.peerId.toLowerCase()) await reloadHistoryDetail();
        if (identityId.textContent.trim() === job.identityId) {
          message.textContent = '기록 삭제를 완료했습니다.';
        }
      } else {
        message.textContent = snapshot.error || '기록을 삭제하지 못했습니다. 기록은 보존되었습니다.';
      }
      break;
    }
  } finally {
    historyDeletionPollers.delete(pollerKey);
    if (identityId.textContent.trim() === job.identityId) {
      const remaining = readHistoryDeletionJobs()[job.identityId] || [];
      setHistoryDeletionBusy(remaining.length > 0);
    }
  }
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
  historySummaries = [];
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
  historySummaries = items;
  verifiedPeers = new Set(items.filter(item => item.verified).map(item => item.peerId));
  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'history-bundle-row';
    const checkLabel = document.createElement('label');
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.dataset.bundlePeerId = item.peerId;
    checkLabel.append(check, document.createTextNode(' 백업 선택'));
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'history-item';
    button.dataset.peerId = item.peerId;
    const label = document.createElement('span');
    label.textContent = `대화 ${item.peerId.slice(0, 12)}`;
    const details = document.createElement('small');
    const lastMessage = item.lastMessage ? formatTime(item.lastMessage) : '메시지 없음';
    details.textContent = `${item.messageCount}개 메시지 · ${lastMessage} · ${item.verified ? '상대 확인 기록 있음' : '상대 확인 필요'}`;
    button.append(label, details);
    button.addEventListener('click', () => openHistory(item.peerId).catch(() => {
      message.textContent = '대화 기록을 열지 못했습니다.';
    }));
    row.append(checkLabel, button);
    historyList.append(row);
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
    const row = item.closest('.history-bundle-row');
    if (row) row.hidden = item.hidden;
  }
}

function renderHistoryMessages() {
  const query = messageFilter.value.trim().toLocaleLowerCase();
  historyMessages.replaceChildren();
  for (const item of selectedHistoryMessages) {
    if (query && !item.text.toLocaleLowerCase().includes(query)) continue;
    const card = document.createElement('article');
    card.className = `entry${item.sender === '나' ? ' mine' : ''}${item.sender === '신원 변경' ? ' system' : ''}`;
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
  selectedHistoryPeer = peerId;
  selectedHistoryIndices.clear();
  historyCursorStack = [null];
  historyNextCursor = null;
  historyPageVersion = null;
  document.querySelector('#history-peer').textContent = peerId;
  document.querySelector('#contact-reconnect').hidden = !verifiedPeers.has(peerId);
  document.querySelector('#contact-export').hidden = !verifiedPeers.has(peerId);
  messageFilter.value = '';
  if (!(await loadHistoryPage(null))) return false;
  show('history');
  return true;
}

async function loadHistoryPage(cursor) {
  const requestedIdentityId = identityId.textContent.trim();
  const requestedPeerId = selectedHistoryPeer;
  const response = await request('/api/history/messages', JSON.stringify({
    peerId: requestedPeerId,
    cursor,
    limit: historyPageSize,
  }));
  if (identityId.textContent.trim() !== requestedIdentityId || selectedHistoryPeer !== requestedPeerId) return false;
  if (response.status === 409) {
    message.textContent = '기록이 바뀌어 선택을 적용할 수 없습니다. 다시 불러와 선택을 갱신하세요.';
    document.querySelector('#history-page-reload').disabled = false;
    return false;
  }
  if (!response.ok) { message.textContent = '대화 기록을 열지 못했습니다.'; return false; }
  const page = await response.json();
  if (identityId.textContent.trim() !== requestedIdentityId || selectedHistoryPeer !== requestedPeerId) return false;
  selectedHistoryMessages = page.messages;
  historyPageVersion = page.version;
  historyNextCursor = page.nextCursor;
  const index = historyCursorStack.length - 1;
  document.querySelector('#history-page-prev').disabled = index === 0;
  document.querySelector('#history-page-next').disabled = !historyNextCursor;
  document.querySelector('#history-page-status').textContent = `현재 페이지 ${selectedHistoryMessages.length}개 메시지 · 검색은 현재 페이지에만 적용됩니다.`;
  updateSelectionCount();
  renderHistoryMessages();
  return true;
}

function stopPolling() {
  pollGeneration += 1;
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
    card.className = `entry${item.sender === '나' ? ' mine' : ''}${item.sender === '신원 변경' ? ' system' : ''}`;
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
  latestChatSnapshot = snapshot;
  if (messageEpoch !== snapshot.messageEpoch) {
    conversation.replaceChildren();
    messageCursor = 0;
    messageEpoch = snapshot.messageEpoch;
  }
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
  const transitionPanel = document.querySelector('#identity-transition-panel');
  const previousIds = snapshot.identityTransition || [];
  const transitionKey = `${snapshot.peerId || ''}:${previousIds.join(',')}`;
  const eligibleHistories = historySummaries.filter(item =>
    item.verified && item.peerId !== snapshot.peerId && previousIds.includes(item.peerId),
  );
  transitionPanel.hidden = snapshot.phase !== 'connected'
    || !previousIds.length
    || transitionKey === dismissedTransitionKey;
  if (!transitionPanel.hidden) {
    const select = document.querySelector('#identity-transition-choice');
    if (select.dataset.transitionKey !== transitionKey) {
      select.replaceChildren();
      for (const item of eligibleHistories) {
        const option = document.createElement('option');
        option.value = item.peerId;
        option.textContent = `확인된 대화 ${item.peerId.slice(0, 12)} · ${item.messageCount}개 기록`;
        select.append(option);
      }
      select.dataset.transitionKey = transitionKey;
    }
    document.querySelector('#identity-transition-copy').textContent = eligibleHistories.length
      ? `상대가 이전 신원 ID ${eligibleHistories.map(item => item.peerId.slice(0, 12)).join(', ')}를 제시했습니다. 이 주장은 동일 인물의 증명이 아닙니다. 새 지문을 별도 연락 수단으로 확인했고, 기존 대화를 이어갈 기록이 맞는 경우에만 선택하세요.`
      : `상대가 이전 신원 ID ${previousIds.map(id => id.slice(0, 12)).join(', ')}를 제시했지만, 이 기기에서 일치하는 확인 기록을 찾지 못했습니다. 별도 대화로 계속할 수 있습니다.`;
    document.querySelector('#identity-transition-accept').disabled = eligibleHistories.length === 0;
    document.querySelector('#identity-transition-dismiss').dataset.transitionKey = transitionKey;
  }
  const restoreOffer = snapshot.historyRestoreOffer || [];
  const restoreState = snapshot.historyRestoreState || 'idle';
  const restorePanel = document.querySelector('#history-restore-panel');
  const restoreStatus = document.querySelector('#history-restore-status');
  const restorePreview = document.querySelector('#history-restore-preview');
  const restoreKey = `${snapshot.historyRestoreStatus || ''}:${snapshot.historyRestoreOfferCount || 0}:${snapshot.historyRestoreLegacyCount || 0}:${restoreOffer.map(item => `${item.time}:${item.sender}:${item.text}`).join('|')}`;
  const merging = ['merge-queued', 'merging'].includes(restoreState);
  const restoreTerminal = ['completed', 'failed'].includes(restoreState);
  restorePanel.hidden = (snapshot.phase !== 'connected' && !snapshot.historyRestoreCleanupError && !merging && !restoreTerminal)
    || (!snapshot.historyRestoreInProgress && !restoreOffer.length && !snapshot.historyRestoreStatus);
  restoreStatus.textContent = merging
    ? (snapshot.historyRestoreStatus || '최종 병합 중입니다. 대화 기록 저장은 잠금 때문에 잠시 대기할 수 있습니다. 연결 종료 후에도 계속됩니다.')
    : snapshot.historyRestoreInProgress
      ? `상대 기록을 받는 중입니다: ${snapshot.historyRestoreReceived || 0} / ${snapshot.historyRestoreTotal || 0}. 동의 전에는 로컬 기록을 변경하지 않습니다.`
      : snapshot.historyRestoreStatus || '';
  if (snapshot.historyRestoreCleanupError) {
    restoreStatus.textContent += ` 임시 기록 정리 실패: ${snapshot.historyRestoreCleanupError}`;
  }
  document.querySelector('#history-restore-request').disabled = snapshot.phase !== 'connected'
    || snapshot.historyRestoreInProgress || (snapshot.historyRestoreOfferCount || 0) > 0
    || !['idle', 'failed', 'completed'].includes(restoreState);
  document.querySelector('#history-restore-accept').disabled = snapshot.historyRestoreInProgress
    || !['awaiting-transfer-consent', 'awaiting-merge-consent'].includes(restoreState)
    || (snapshot.historyRestoreOfferCount || 0) === 0;
  document.querySelector('#history-restore-accept').textContent = restoreState === 'awaiting-merge-consent'
    ? '제안된 기록 병합' : '전송 동의';
  document.querySelector('#history-restore-decline').disabled = ['idle', 'failed', 'completed', 'merging', 'merge-queued'].includes(restoreState);
  document.querySelector('#history-restore-decline').textContent = snapshot.historyRestoreInProgress
    ? (restoreState === 'estimating' ? '예상 확인 취소' : '전송 취소')
    : (restoreState === 'awaiting-transfer-consent' ? '전송 거부' : '복원 거부');
  if (restorePreview.dataset.offerKey !== restoreKey) {
    restorePreview.replaceChildren();
    for (const item of restoreOffer) {
      const row = document.createElement('article');
      row.className = 'entry';
      const header = document.createElement('small');
      header.textContent = `${formatTime(item.time)} · ${item.sender} · ${item.signed ? '서명 확인됨' : '기존 서명 없음'}`;
      const text = document.createElement('div');
      text.textContent = item.text;
      row.append(header, text);
      restorePreview.append(row);
    }
    if ((snapshot.historyRestoreOfferCount || 0) > restoreOffer.length) {
      const more = document.createElement('p');
      more.className = 'meta';
      more.textContent = `미리 보기는 ${restoreOffer.length}개입니다. 동의하면 총 ${snapshot.historyRestoreOfferCount}개를 모두 가져옵니다.`;
      restorePreview.append(more);
    }
    restorePreview.dataset.offerKey = restoreKey;
  }
  verification.hidden = snapshot.phase !== 'verification';
  sendForm.hidden = snapshot.phase !== 'connected' && !chatText.value;
  sendForm.querySelector('button').disabled = snapshot.phase !== 'connected' || sendingMessage;
  if (snapshot.phase === 'verification' && lastPhase !== 'verification') {
    document.querySelector('#peer-id').textContent = snapshot.peerId || '';
    document.querySelector('#fingerprint').textContent = snapshot.fingerprint || '';
    document.querySelector('#confirm-peer').disabled = false;
  }
  if (snapshot.phase === 'confirming') document.querySelector('#confirm-peer').disabled = true;
  if (snapshot.phase === 'connected') document.querySelector('#chat-title').textContent = '대화';
  if ((snapshot.phase === 'disconnected' || snapshot.phase === 'failed' || snapshot.phase === 'closed') && !merging) {
    stopPolling();
  }
  lastPhase = snapshot.phase;
}

async function pollChat() {
  if (!operationId) return;
  const polledOperationId = operationId;
  const polledIdentityId = identityId.textContent.trim();
  const polledGeneration = pollGeneration;
  const isCurrentPoll = () => pollGeneration === polledGeneration
    && operationId === polledOperationId
    && identityId.textContent.trim() === polledIdentityId;
  let missingRestoreJob = false;
  try {
    const response = await request('/api/chat/status', polledOperationId);
    if (!isCurrentPoll()) return;
    if (!response.ok) {
      if (response.status === 404) {
        if (!isCurrentPoll()) return;
        forgetRestoreJob(polledIdentityId, polledOperationId);
        chatStatus.textContent = '복원 작업을 찾을 수 없습니다. 프로그램이 재시작됐거나 작업이 만료됐을 수 있습니다.';
        missingRestoreJob = true;
      }
      throw new Error('status unavailable');
    }
    const snapshot = await response.json();
    if (!isCurrentPoll()) return;
    updateChatView(snapshot);
    if (['merge-queued', 'merging'].includes(snapshot.historyRestoreState)) {
      rememberRestoreJob(polledOperationId);
    } else if (snapshot.historyRestoreState === 'completed' || snapshot.historyRestoreState === 'failed') {
      forgetRestoreJob(polledIdentityId, polledOperationId);
    }
    if (snapshot.messageCount > messageCursor) {
      const messages = await request('/api/chat/messages', `${polledOperationId}\n${messageCursor}`);
      if (!isCurrentPoll()) return;
      if (!messages.ok) throw new Error('messages unavailable');
      const entries = await messages.json();
      if (!isCurrentPoll()) return;
      appendMessages(entries);
    }
  } catch (_) {
    if (isCurrentPoll() && !missingRestoreJob) chatStatus.textContent = '로컬 프로그램에서 연결 상태를 읽지 못했습니다.';
  }
  if (isCurrentPoll() && operationId && (!['failed', 'disconnected', 'closed'].includes(lastPhase)
    || ['merge-queued', 'merging'].includes(latestChatSnapshot?.historyRestoreState))) {
    const timerGeneration = polledGeneration;
    pollTimer = setTimeout(() => {
      if (pollGeneration === timerGeneration) pollChat();
    }, 350);
  }
}

async function attachChat(id) {
  stopPolling();
  operationId = id;
  sessionStorage.setItem(operationKey, operationId);
  messageCursor = 0;
  messageEpoch = null;
  dismissedTransitionKey = '';
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
    createdNote.textContent = '';
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
  createdNote.textContent = '';
  message.textContent = '';
  try { await refreshIdentity(); } catch (_) { message.textContent = '신원을 확인할 수 없습니다.'; }
});

const replaceIdentityDialog = document.querySelector('#replace-identity-dialog');
document.querySelector('#replace-identity').addEventListener('click', () => {
  replaceIdentityDialog.showModal();
});
document.querySelector('#cancel-identity-replacement').addEventListener('click', () => {
  replaceIdentityDialog.close();
});
document.querySelector('#confirm-identity-replacement').addEventListener('click', async () => {
  replaceIdentityDialog.close();
  message.textContent = '';
  try {
    const response = await request('/api/identity/replace');
    if (!response.ok) {
      message.textContent = response.status === 409
        ? '진행 중인 대화를 종료한 뒤 다시 시도하세요.'
        : '기록을 새 신원으로 복사하지 못했습니다. 기존 신원은 유지됩니다.';
      return;
    }
    generatedCode.value = await response.text();
    createdNote.textContent = '신원을 교체했습니다. 새 코드를 저장하고 상대와 새 초대에서 전체 지문을 별도 경로로 확인하세요. 상대는 기존 확인 기록이 일치하면 직접 선택해 대화를 연결할 수 있습니다. 이전 코드는 무효화되지 않았습니다.';
    show('created');
  } catch (_) {
    message.textContent = '신원을 교체하지 못했습니다. 기존 신원은 유지됩니다.';
  }
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
    if (latestChatSnapshot && ['merge-queued', 'merging'].includes(latestChatSnapshot.historyRestoreState) && operationId) {
      rememberRestoreJob(operationId);
    }
    stopPolling();
    if (!(await request('/api/identity/logout')).ok) throw new Error('logout failed');
    operationId = null;
    sessionStorage.removeItem(operationKey);
    latestChatSnapshot = null;
    identityId.textContent = '';
    setHistoryDeletionBusy(false);
    selectedHistoryPeer = '';
    selectedHistoryMessages = [];
    historySummaries = [];
    dismissedTransitionKey = '';
    clearReprotectState();
    historyMessages.replaceChildren();
    historyList.replaceChildren();
    show('entry');
    message.textContent = '';
  } catch (_) {
    message.textContent = '로그아웃하지 못했습니다. 로컬 프로그램을 종료하세요.';
    if (operationId) pollChat();
  }
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
  if (code.startsWith('ADI1-') || code.startsWith('ADI2-')) {
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

document.querySelector('#identity-transition-dismiss').addEventListener('click', () => {
  dismissedTransitionKey = document.querySelector('#identity-transition-dismiss').dataset.transitionKey || '';
  document.querySelector('#identity-transition-panel').hidden = true;
});

document.querySelector('#identity-transition-accept').addEventListener('click', async () => {
  const previousPeerId = document.querySelector('#identity-transition-choice').value;
  const button = document.querySelector('#identity-transition-accept');
  if (!operationId || !previousPeerId) return;
  button.disabled = true;
  try {
    const response = await request('/api/chat/link-identity', `${operationId}\n${previousPeerId}`);
    if (!response.ok) throw new Error((await response.text()) || 'link failed');
    document.querySelector('#identity-transition-panel').hidden = true;
    message.textContent = '기존 기록을 현재 대화에 연결했습니다. 상대가 변경 알림을 받았는지는 확인되지 않습니다.';
    await refreshHistoryList();
  } catch (error) {
    message.textContent = error instanceof Error && error.message && error.message !== 'link failed'
      ? error.message
      : '기록을 연결하지 못했습니다. 기존 기록은 유지되어 있습니다.';
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#history-restore-request').addEventListener('click', async () => {
  if (!operationId) return;
  try {
    const response = await request('/api/chat/request-history-restore', operationId);
    if (!response.ok) throw new Error((await response.text()) || 'request failed');
  } catch (error) {
    message.textContent = error instanceof Error && error.message !== 'request failed'
      ? error.message
      : '상대 기록을 요청하지 못했습니다.';
  }
});

async function resolveHistoryRestore(accept) {
  if (!operationId) return;
  const restoreState = latestChatSnapshot?.historyRestoreState || 'idle';
  const acceptingTransfer = accept && restoreState === 'awaiting-transfer-consent';
  const cancellingTransfer = !accept
    && document.querySelector('#history-restore-decline').textContent === '전송 취소';
  if (accept && restoreState === 'awaiting-merge-consent') {
    rememberRestoreJob(operationId);
  }
  try {
    const response = await request('/api/chat/resolve-history-restore', JSON.stringify({ operationId, accept }));
    if (!response.ok) throw new Error((await response.text()) || 'restore failed');
    if (accept && restoreState === 'awaiting-merge-consent') {
      rememberRestoreJob(operationId);
    }
    message.textContent = accept
      ? acceptingTransfer ? '전송 요청을 접수했습니다. 완료 후 미리 보기에서 최종 병합을 확인하세요.' : '최종 병합 요청을 접수했습니다. 상태 조회에서 완료 또는 실패를 확인하세요.'
      : cancellingTransfer
        ? '기록 전송을 취소했습니다. 로컬 기록은 변경되지 않았습니다.'
        : '복원을 거부했습니다. 로컬 기록은 변경되지 않았습니다.';
  } catch (error) {
    message.textContent = error instanceof Error && error.message !== 'restore failed'
      ? error.message
      : '기록 복원을 처리하지 못했습니다. 로컬 기록은 변경되지 않았습니다.';
  }
}

document.querySelector('#history-restore-accept').addEventListener('click', () => resolveHistoryRestore(true));
document.querySelector('#history-restore-decline').addEventListener('click', () => resolveHistoryRestore(false));

sendForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!operationId || sendingMessage || !chatText.value.trim()) return;
  const text = chatText.value;
  const body = `${operationId}\n${text}`;
  const button = sendForm.querySelector('button');
  sendingMessage = true;
  button.disabled = true;
  try {
    const response = await request('/api/chat/send', body);
    if (!response.ok) {
      const detail = await response.text();
      if (response.status === 409 && detail) {
        chatStatus.textContent = detail;
        return;
      }
      throw new Error('send failed');
    }
    if (chatText.value === text) chatText.value = '';
    chatText.focus();
  } catch (_) {
    sendForm.hidden = false;
    chatStatus.textContent = '전송 결과를 확인하지 못했습니다. 입력을 보존했습니다. 다시 보내면 중복될 수 있습니다.';
  } finally {
    sendingMessage = false;
    button.disabled = lastPhase !== 'connected';
  }
});

document.querySelector('#close-chat').addEventListener('click', async () => {
  if (latestChatSnapshot && ['merge-queued', 'merging'].includes(latestChatSnapshot.historyRestoreState) && operationId) {
    rememberRestoreJob(operationId);
  }
  const closingOperationId = operationId;
  stopPolling();
  if (closingOperationId) await request('/api/chat/cancel', closingOperationId).catch(() => {});
  operationId = null;
  sessionStorage.removeItem(operationKey);
  latestChatSnapshot = null;
  conversation.replaceChildren();
  show('active');
  refreshHistoryList().catch(() => {});
});

historyFilter.addEventListener('input', filterHistoryList);
messageFilter.addEventListener('input', renderHistoryMessages);
document.querySelector('#history-page-next').addEventListener('click', async () => {
  if (!historyNextCursor) return;
  historyCursorStack.push(historyNextCursor);
  if (!(await loadHistoryPage(historyNextCursor))) historyCursorStack.pop();
});
document.querySelector('#history-page-prev').addEventListener('click', async () => {
  if (historyCursorStack.length <= 1) return;
  historyCursorStack.pop();
  await loadHistoryPage(historyCursorStack[historyCursorStack.length - 1]);
});
document.querySelector('#history-page-reload').addEventListener('click', () => {
  if (selectedHistoryPeer) openHistory(selectedHistoryPeer).catch(() => {});
});
document.querySelector('#history-back').addEventListener('click', () => show('active'));
document.querySelector('#contact-reconnect').addEventListener('click', () => startChat('/api/chat/reconnect', selectedHistoryPeer));
document.querySelector('#contact-export').addEventListener('click', async () => {
  try {
    const response = await request('/api/contacts/export-backup', selectedHistoryPeer);
    if (!response.ok) throw new Error('backup unavailable');
    const binary = atob(await response.text());
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'another-dimension-contact.adcontact';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message.textContent = '상대 확인 백업을 저장했습니다.';
  } catch (_) { message.textContent = '상대 확인 기록을 백업하지 못했습니다.'; }
});
document.querySelector('#contact-import').addEventListener('click', async () => {
  const input = document.querySelector('#contact-file');
  const file = input.files[0];
  if (!file || file.size > 256) { message.textContent = '상대 확인 백업 파일을 선택하세요.'; return; }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const response = await request('/api/contacts/import-backup', btoa(String.fromCharCode(...bytes)));
    if (response.status === 409) { message.textContent = '연결을 종료하세요. 기존 확인 기록과 충돌하는 백업은 가져올 수 없습니다.'; return; }
    if (!response.ok) throw new Error('invalid backup');
    input.value = '';
    await refreshHistoryList();
    message.textContent = '상대 확인 기록을 복원했습니다. 오래된 백업의 최신 여부는 확인할 수 없습니다.';
  } catch (_) { message.textContent = '백업을 읽지 못했거나 개인 접속 코드가 다릅니다.'; }
});
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

document.querySelector('#history-bundle-export').addEventListener('click', async () => {
  const peerIds = [...historyList.querySelectorAll('input[data-bundle-peer-id]:checked')]
    .map(input => input.dataset.bundlePeerId);
  if (!peerIds.length) { message.textContent = '백업할 대화를 선택하세요.'; return; }
  if (!window.confirm(`선택한 ${peerIds.length}개 대화를 암호화 백업으로 저장할까요?`)) return;
  try {
    const response = await request('/api/history/export-backup-bundle', JSON.stringify({ peerIds }));
    if (response.status === 409) { message.textContent = '연결 중인 대화는 종료한 뒤 백업하세요.'; return; }
    if (!response.ok) throw new Error('bundle export failed');
    const binary = atob(await response.text());
    const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = 'another-dimension-conversations.adbak';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    message.textContent = `${peerIds.length}개 대화의 암호화 백업을 저장했습니다.`;
  } catch (_) { message.textContent = '대화 백업을 만들지 못했습니다.'; }
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
    const header = atob(encoded.slice(0, 16));
    const backupMagic = header.slice(0, 8);
    if ((backupMagic === 'ADBACK5\0' || backupMagic === 'ADPACK1\0')
      && !window.confirm('이 백업에는 이전 신원 연결 정보가 포함될 수 있습니다. 파일 인증에 성공한 경우에만 해당 관계를 이 기기에 복원합니다. 계속할까요?')) return;
    const response = await request('/api/history/import-backup', JSON.stringify({ backup: encoded, password }));
    if (response.status === 409) { message.textContent = '먼저 모든 대화 연결을 종료한 뒤 다시 시도하세요.'; return; }
    if (!response.ok) { message.textContent = (await response.text()) || '백업을 검증하거나 저장하지 못했습니다.'; return; }
    const result = await response.json();
    document.querySelector('#history-backup-file').value = '';
    await refreshHistoryList();
    if (Array.isArray(result.conversations)) {
      const linked = result.conversations.filter(item => item.linkedIdentityRestored).length;
      message.textContent = `${result.conversations.length}개 대화 백업을 기존 기록과 병합했습니다.${linked ? ` ${linked}개 대화의 인증된 이전 신원 관계도 복원했습니다.` : ''}`;
    } else {
      await openHistory(result.peerId);
      message.textContent = result.linkedIdentityRestored
        ? '백업을 확인해 기존 기록과 인증된 이전 신원 관계를 복원했습니다.'
        : '백업을 확인해 기존 기록과 병합했습니다.';
    }
  } catch (_) {
    message.textContent = '백업 파일을 읽지 못했습니다.';
  } finally {
    passwordField.value = '';
  }
});

document.querySelector('#history-reprotect-choose').addEventListener('click', async () => {
  const generation = reprotectWork.begin();
  if (!window.showOpenFilePicker) {
    if (reprotectWork.isCurrent(generation)) {
      message.textContent = '이 브라우저는 안전한 재보호 파일 선택을 지원하지 않습니다. Chromium 기반 브라우저에서 다시 시도하세요.';
    }
    return;
  }
  try {
    const [handle] = await window.showOpenFilePicker({
      multiple: false,
      types: [{ description: '암호화 대화 백업', accept: { 'application/octet-stream': ['.adbak'] } }],
    });
    if (!reprotectWork.isCurrent(generation)) return;
    const file = await handle.getFile();
    if (!reprotectWork.isCurrent(generation)) return;
    if (file.size > 16 * 1024 * 1024) {
      message.textContent = '백업 파일은 16 MB 이하여야 합니다.';
      return;
    }
    reprotectSourceHandle = handle;
    reprotectSourceName = file.name;
    reprotectOutput = null;
    reprotectPassword = '';
    document.querySelector('#history-reprotect-save').disabled = true;
    document.querySelector('#history-reprotect-source').textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
    message.textContent = '이전 백업 파일을 선택했습니다.';
  } catch (error) {
    if (!reprotectWork.isCurrent(generation)) return;
    if (error.name !== 'AbortError') message.textContent = '백업 파일을 열지 못했습니다.';
  }
});

document.querySelector('#history-reprotect').addEventListener('click', async () => {
  const codeField = document.querySelector('#history-reprotect-previous-code');
  const oldPasswordField = document.querySelector('#history-reprotect-previous-password');
  const newPasswordField = document.querySelector('#history-reprotect-new-password');
  const confirmField = document.querySelector('#history-reprotect-new-password-confirm');
  const { generation, values } = reprotectWork.beginAndClear([
    codeField, oldPasswordField, newPasswordField, confirmField,
  ]);
  const [previousCode, previousPassword, replacementPassword, replacementConfirmation] = values;
  const sourceHandle = reprotectSourceHandle;

  // Invalidate any prior output before validation or asynchronous work.
  reprotectOutput = null;
  reprotectPassword = '';
  document.querySelector('#history-reprotect-save').disabled = true;

  if (!sourceHandle) {
    message.textContent = '먼저 이전 백업 파일을 선택하세요.';
    return;
  }
  if (replacementPassword !== replacementConfirmation) {
    message.textContent = '새 백업 비밀번호가 일치하지 않습니다.';
    return;
  }
  if (replacementPassword && [...replacementPassword].length < 12) {
    message.textContent = '새 백업 비밀번호는 12자 이상이어야 합니다.';
    return;
  }
  try {
    const file = await sourceHandle.getFile();
    if (!reprotectWork.isCurrent(generation)) return;
    if (file.size > 16 * 1024 * 1024) throw new Error('oversized backup');
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
    if (!reprotectWork.isCurrent(generation)) return;
    const backup = String(dataUrl).slice(String(dataUrl).indexOf(',') + 1);
    const response = await request('/api/history/reprotect-backup', JSON.stringify({
      backup,
      previousCode,
      previousPassword,
      replacementPassword,
    }));
    if (!reprotectWork.isCurrent(generation)) return;
    if (!response.ok) throw new Error('reprotect failed');
    const output = await response.text();
    if (!reprotectWork.isCurrent(generation)) return;
    reprotectOutput = output;
    reprotectPassword = replacementPassword;
    document.querySelector('#history-reprotect-save').disabled = false;
    message.textContent = '새 백업을 만들었습니다. 저장 후 파일을 다시 읽어 확인하세요. 원본은 아직 보존되어 있습니다.';
  } catch (_) {
    if (!reprotectWork.isCurrent(generation)) return;
    reprotectOutput = null;
    reprotectPassword = '';
    document.querySelector('#history-reprotect-save').disabled = true;
    message.textContent = '백업, 이전 코드 또는 비밀번호를 확인하지 못했습니다. 원본 파일은 변경하지 않았습니다.';
  }
});

document.querySelector('#history-reprotect-save').addEventListener('click', async () => {
  const sourceHandle = reprotectSourceHandle;
  const output = reprotectOutput;
  const password = reprotectPassword;
  const sourceName = reprotectSourceName;
  if (!output || !sourceHandle) return;
  if (!window.showSaveFilePicker) {
    message.textContent = '이 브라우저는 새 백업을 저장 위치에서 다시 확인하는 기능을 지원하지 않습니다.';
    return;
  }
  const generation = reprotectWork.begin();
  const isCurrent = () => reprotectWork.isCurrent(generation);
  let writable = null;
  let saveStarted = false;
  try {
    const suggestedName = `${sourceName.replace(/\.adbak$/i, '')}.new-identity.adbak`;
    const outputHandle = await window.showSaveFilePicker({
      suggestedName,
      types: [{ description: '암호화 대화 백업', accept: { 'application/octet-stream': ['.adbak'] } }],
    });
    if (!isCurrent()) return;
    if (await sourceHandle.isSameEntry(outputHandle)) {
      if (isCurrent()) message.textContent = '원본 백업과 다른 새 파일을 선택하세요. 원본은 변경하지 않았습니다.';
      return;
    }
    if (!isCurrent()) return;
    saveStarted = true;
    const binary = atob(output);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    writable = await outputHandle.createWritable();
    if (!isCurrent()) {
      await writable.abort();
      writable = null;
      return;
    }
    await writable.write(bytes);
    if (!isCurrent()) {
      await writable.abort();
      writable = null;
      return;
    }
    await writable.close();
    writable = null;
    if (!isCurrent()) return;

    const savedFile = await outputHandle.getFile();
    if (!isCurrent()) return;
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(savedFile);
    });
    if (!isCurrent()) return;
    const savedBackup = String(dataUrl).slice(String(dataUrl).indexOf(',') + 1);
    const verification = await request('/api/history/verify-backup', JSON.stringify({
      backup: savedBackup,
      password,
    }));
    if (!isCurrent()) return;
    if (!verification.ok) throw new Error('saved backup verification failed');
    const result = await verification.json();
    if (!isCurrent()) return;
    reprotectOutput = null;
    reprotectPassword = '';
    document.querySelector('#history-reprotect-save').disabled = true;
    const removeSource = window.confirm(
      `새 파일을 저장 위치에서 다시 읽어 확인했습니다 (${result.messageCount}개 메시지).\n\n원본 파일은 그대로 있습니다. 원본을 삭제하려면 Finder에서 직접 삭제해야 합니다. 원본을 직접 삭제하시겠습니까?`,
    );
    if (!isCurrent()) return;
    message.textContent = removeSource
      ? '새 백업 확인 완료. Finder에서 선택한 원본 파일만 직접 삭제하세요. 다른 사본은 별도로 관리해야 합니다.'
      : '새 백업 확인 완료. 원본 파일을 보존했습니다.';
    document.querySelector('#history-reprotect-source').textContent = '선택한 파일 없음';
    reprotectSourceHandle = null;
    reprotectSourceName = '';
  } catch (error) {
    if (writable) {
      try { await writable.abort(); } catch (_) { /* keep the original backup */ }
    }
    if (!isCurrent()) return;
    if (error.name !== 'AbortError') {
      if (saveStarted) {
        reprotectOutput = null;
        reprotectPassword = '';
        document.querySelector('#history-reprotect-save').disabled = true;
      }
      message.textContent = '새 파일을 저장하거나 다시 확인하지 못했습니다. 원본은 보존되어 있습니다. 새 파일은 확인되지 않은 상태입니다.';
    }
  }
});

async function reloadHistoryDetail() {
  const opened = await openHistory(selectedHistoryPeer);
  if (!opened) return false;
  await refreshHistoryList();
  return true;
}

async function submitHistoryDeletion(path, payload, peerId) {
  const ownerIdentityId = identityId.textContent.trim();
  if (!ownerIdentityId) return;
  const job = { operationId: newHistoryDeletionId(), identityId: ownerIdentityId, peerId };
  rememberHistoryDeletion(job);
  setHistoryDeletionBusy(true);
  message.textContent = '기록 삭제를 시작하고 있습니다.';
  try {
    const response = await request(path, JSON.stringify({ ...payload, operationId: job.operationId }));
    if (identityId.textContent.trim() !== ownerIdentityId) return;
    if (response.status !== 202) {
      forgetHistoryDeletion(ownerIdentityId, job.operationId);
      setHistoryDeletionBusy((readHistoryDeletionJobs()[ownerIdentityId] || []).length > 0);
      message.textContent = (await response.text()) || '기록 삭제 요청이 거부됐습니다.';
      return;
    }
    pollHistoryDeletion(job);
  } catch (_) {
    if (identityId.textContent.trim() === ownerIdentityId) {
      message.textContent = '요청 응답을 받지 못했습니다. 실제 처리 여부를 상태에서 확인하고 있습니다.';
      pollHistoryDeletion(job);
    }
  }
}

async function deleteHistoryRange(start, end, prompt) {
  if (!selectedHistoryPeer || !window.confirm(prompt)) return;
  await submitHistoryDeletion('/api/history/delete-range', {
    peerId: selectedHistoryPeer, start, end,
  }, selectedHistoryPeer);
}

document.querySelector('#delete-selected').addEventListener('click', async () => {
  if (!selectedHistoryIndices.size) return;
  const count = selectedHistoryIndices.size;
  if (!window.confirm(`선택한 메시지 ${count}개를 이 기기에서 삭제할까요?`)) return;
  await submitHistoryDeletion('/api/history/delete-messages', {
    peerId: selectedHistoryPeer,
    version: historyPageVersion,
    indices: [...selectedHistoryIndices],
  }, selectedHistoryPeer);
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
  if (!response.ok) {
    const detail = await response.text();
    message.textContent = detail || '대화를 삭제하지 못했습니다.';
    return;
  }
  selectedHistoryPeer = '';
  selectedHistoryMessages = [];
  selectedHistoryIndices.clear();
  show('active');
  await refreshHistoryList();
  message.textContent = '대화 기록을 삭제했습니다.';
});

restoreSession();
