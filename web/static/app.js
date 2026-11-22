(() => {
  'use strict';

  const state = {
    selectedID: null,
    selectedHoneypot: null,
    honeypots: [],
    logs: [],
    totalLogs: 0,
    overview: null,
    autoRefresh: true,
    pollTimer: null,
    revealedSecrets: new Set(),
    lastFocusedElement: null,
  };

  const el = {
    banner: document.getElementById('global-banner'),
    statHoneypots: document.getElementById('stat-honeypots'),
    barHoneypots: document.getElementById('bar-honeypots'),
    statConnections: document.getElementById('stat-connections'),
    statAuthSplit: document.getElementById('stat-auth-split'),
    statCommands: document.getElementById('stat-commands'),
    statUniqueIPs: document.getElementById('stat-unique-ips'),

    viewHome: document.getElementById('view-home'),
    viewDetail: document.getElementById('view-detail'),

    honeypotsBody: document.getElementById('honeypots-tbody'),
    btnRefreshHome: document.getElementById('btn-refresh-home'),
    btnOpenCreate: document.getElementById('btn-open-create'),

    btnBackHome: document.getElementById('btn-back-home'),
    detailPath: document.getElementById('detail-path'),
    detailCmd: document.getElementById('detail-cmd'),
    detailErrorLine: document.getElementById('detail-error-line'),
    detailName: document.getElementById('detail-name'),
    detailEndpoint: document.getElementById('detail-endpoint'),
    detailCredentials: document.getElementById('detail-credentials'),
    detailState: document.getElementById('detail-state'),
    btnDetailToggle: document.getElementById('btn-detail-toggle'),
    btnDetailDelete: document.getElementById('btn-detail-delete'),

    detailLogsPath: document.getElementById('detail-logs-path'),
    detailLogsCmd: document.getElementById('detail-logs-cmd'),
    logsSummary: document.getElementById('logs-summary'),
    logsBody: document.getElementById('logs-tbody'),
    filterForm: document.getElementById('log-filter-form'),
    filterEvent: document.getElementById('filter-event'),
    filterQuery: document.getElementById('filter-query'),
    btnResetFilter: document.getElementById('btn-reset-filter'),
    btnExportJSONL: document.getElementById('btn-export-jsonl'),
    btnExportCSV: document.getElementById('btn-export-csv'),
    btnTogglePoll: document.getElementById('btn-toggle-poll'),
    btnRefreshLogs: document.getElementById('btn-refresh-logs'),
    btnClearLogs: document.getElementById('btn-clear-logs'),

    btnCloseCreate: document.getElementById('btn-close-create'),
    btnCancelCreate: document.getElementById('btn-cancel-create'),
    createModal: document.getElementById('create-modal'),
    createForm: document.getElementById('create-form'),
    createError: document.getElementById('create-error'),
    btnSubmitCreate: document.getElementById('btn-submit-create'),
    inputPort: document.getElementById('input-port'),
    inputUsername: document.getElementById('input-username'),
    inputPassword: document.getElementById('input-password'),
    inputName: document.getElementById('input-name'),

    statusSession: document.getElementById('status-session'),
    statusVersion: document.getElementById('status-version'),
    statusActive: document.getElementById('status-active'),
    statusClock: document.getElementById('status-clock'),
  };

  function showBanner(msg) {
    if (!msg) {
      el.banner.textContent = '';
      el.banner.classList.add('hidden');
      return;
    }
    el.banner.textContent = msg;
    el.banner.classList.remove('hidden');
  }

  function showCreateError(msg) {
    if (!msg) {
      el.createError.textContent = '';
      el.createError.classList.add('hidden');
      return;
    }
    el.createError.textContent = msg;
    el.createError.classList.remove('hidden');
  }

  async function apiFetch(url, options = {}) {
    const resp = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const text = await resp.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (_) {
        payload = null;
      }
    }
    if (!resp.ok) {
      const errMsg = payload && payload.error ? payload.error : `HTTP ${resp.status}`;
      const err = new Error(errMsg);
      err.status = resp.status;
      throw err;
    }
    return payload;
  }

  function formatBlockBar(active, total) {
    const width = 10;
    if (!total || total <= 0) {
      return '░'.repeat(width);
    }
    const filled = Math.max(0, Math.min(width, Math.round((active / total) * width)));
    return '█'.repeat(filled) + '░'.repeat(width - filled);
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    if (Number.isNaN(d.getTime())) return isoStr;
    return d.toISOString().replace('T', ' ').slice(0, 19);
  }

  function makeSpan(text, className) {
    const span = document.createElement('span');
    if (className) span.className = className;
    span.textContent = text;
    return span;
  }

  function clearChildren(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function renderCredentialsCell(container, hp, onToggleReveal) {
    clearChildren(container);
    const wrap = document.createElement('div');
    wrap.className = 'cred-wrap';
    const revealed = state.revealedSecrets.has(hp.id);
    const pwDisplay = revealed ? hp.password : '••••••••';
    wrap.appendChild(makeSpan(`${hp.username} : ${pwDisplay}`, ''));

    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'btn btn-inline';
    toggleBtn.textContent = revealed ? '[隐藏]' : '[显示]';
    toggleBtn.addEventListener('click', () => {
      if (state.revealedSecrets.has(hp.id)) {
        state.revealedSecrets.delete(hp.id);
      } else {
        state.revealedSecrets.add(hp.id);
      }
      onToggleReveal();
    });
    wrap.appendChild(toggleBtn);
    container.appendChild(wrap);
  }

  function renderOverview(overview) {
    if (!overview) return;
    state.overview = overview;
    el.statHoneypots.textContent = `${overview.running_honeypots} / ${overview.total_honeypots}`;
    el.barHoneypots.textContent = formatBlockBar(overview.running_honeypots, overview.total_honeypots);
    el.statConnections.textContent = String(overview.total_connections);
    el.statAuthSplit.textContent = `OK ${overview.auth_success_count} / FAIL ${overview.auth_failure_count}`;
    el.statCommands.textContent = String(overview.command_count);
    el.statUniqueIPs.textContent = String(overview.unique_ip_count);
    el.statusActive.textContent = `ACTIVE: ${overview.running_honeypots}`;
    el.statusVersion.textContent = (overview.version || 'dev').toUpperCase();
  }

  function renderHoneypots(honeypots) {
    state.honeypots = honeypots;
    clearChildren(el.honeypotsBody);

    if (honeypots.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 7;
      td.className = 'comment-cell';
      td.textContent = '# 当前无已配置的蜜罐节点。点击右上角「[+ 添加蜜罐]」创建仿真 SSH 服务。';
      tr.appendChild(td);
      el.honeypotsBody.appendChild(tr);
      return;
    }

    for (const hp of honeypots) {
      const tr = document.createElement('tr');

      // NAME / ID (点击进入具体蜜罐详情)
      const tdName = document.createElement('td');
      const nameBtn = document.createElement('button');
      nameBtn.type = 'button';
      nameBtn.className = 'link-btn';
      nameBtn.textContent = hp.name;
      nameBtn.addEventListener('click', () => navigateToHoneypot(hp.id));
      tdName.appendChild(nameBtn);
      tdName.appendChild(makeSpan(hp.id, 'cell-mono-sub'));
      tr.appendChild(tdName);

      // TYPE
      const tdType = document.createElement('td');
      tdType.appendChild(makeSpan((hp.type || 'ssh').toUpperCase(), 'accent-cyan'));
      tr.appendChild(tdType);

      // PORT
      const tdPort = document.createElement('td');
      tdPort.appendChild(makeSpan(`:${hp.port}`, 'accent-cyan'));
      tr.appendChild(tdPort);

      // CREDENTIALS
      const tdCred = document.createElement('td');
      renderCredentialsCell(tdCred, hp, () => renderHoneypots(state.honeypots));
      tr.appendChild(tdCred);

      // STATE
      const tdState = document.createElement('td');
      let stateText = 'STOPPED';
      let stateClass = 'accent-grey';
      if (hp.status === 'running') {
        stateText = 'RUNNING';
        stateClass = 'accent-phosphor';
      } else if (hp.status === 'error') {
        stateText = 'ERROR';
        stateClass = 'accent-amber';
      }
      tdState.appendChild(makeSpan(stateText, stateClass));
      if (hp.error_message) {
        tdState.appendChild(makeSpan(hp.error_message, 'cell-mono-sub accent-amber'));
      }
      tr.appendChild(tdState);

      // TELEMETRY
      const tdTel = document.createElement('td');
      tdTel.appendChild(makeSpan(`CONN ${hp.connection_count} / CMD ${hp.command_count}`, ''));
      tdTel.appendChild(makeSpan(`OK ${hp.auth_success_count} / FAIL ${hp.auth_failure_count}`, 'cell-mono-sub'));
      tr.appendChild(tdTel);

      // ACTIONS
      const tdActions = document.createElement('td');
      const actionWrap = document.createElement('div');
      actionWrap.className = 'row-actions';

      const detailBtn = document.createElement('button');
      detailBtn.type = 'button';
      detailBtn.className = 'btn btn-inline btn-primary';
      detailBtn.textContent = '[进入详情]';
      detailBtn.addEventListener('click', () => navigateToHoneypot(hp.id));
      actionWrap.appendChild(detailBtn);

      const toggleStateBtn = document.createElement('button');
      toggleStateBtn.type = 'button';
      toggleStateBtn.className = 'btn btn-inline';
      toggleStateBtn.textContent = hp.status === 'running' ? '[停止]' : '[启动]';
      toggleStateBtn.addEventListener('click', () => handleToggleHoneypot(hp));
      actionWrap.appendChild(toggleStateBtn);

      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn btn-inline btn-warn';
      delBtn.textContent = '[删除]';
      delBtn.addEventListener('click', () => handleDeleteHoneypot(hp));
      actionWrap.appendChild(delBtn);

      tdActions.appendChild(actionWrap);
      tr.appendChild(tdActions);

      el.honeypotsBody.appendChild(tr);
    }
  }

  function renderHoneypotDetail(hp) {
    state.selectedHoneypot = hp;
    if (!hp) return;

    el.detailPath.textContent = `~/fishing/honeypots/${hp.name}`;
    el.detailCmd.textContent = `fishing inspect --id=${hp.id}`;
    el.detailLogsPath.textContent = `~/fishing/honeypots/${hp.name}/logs`;
    el.detailLogsCmd.textContent = `fishing logs --honeypot=${hp.id} --limit=200`;
    el.statusSession.textContent = `FISHING // SSH-HONEYPOT [${hp.name}]`;

    if (hp.error_message) {
      el.detailErrorLine.textContent = `# 监听异常：${hp.error_message}`;
      el.detailErrorLine.classList.add('accent-amber');
    } else {
      el.detailErrorLine.textContent = '# 以下日志仅展示当前蜜罐实例捕获的连接尝试与会话指令。';
      el.detailErrorLine.classList.remove('accent-amber');
    }

    clearChildren(el.detailName);
    el.detailName.appendChild(makeSpan(hp.name, 'accent-phosphor'));
    el.detailName.appendChild(makeSpan(hp.id, 'cell-mono-sub'));

    el.detailEndpoint.textContent = `${(hp.type || 'ssh').toUpperCase()} :${hp.port}`;

    renderCredentialsCell(el.detailCredentials, hp, () => renderHoneypotDetail(state.selectedHoneypot));

    clearChildren(el.detailState);
    let stateText = 'STOPPED';
    let stateClass = 'accent-grey';
    if (hp.status === 'running') {
      stateText = 'RUNNING';
      stateClass = 'accent-phosphor';
    } else if (hp.status === 'error') {
      stateText = 'ERROR';
      stateClass = 'accent-amber';
    }
    el.detailState.appendChild(makeSpan(stateText, stateClass));
    el.detailState.appendChild(
      makeSpan(`CONN ${hp.connection_count} / CMD ${hp.command_count} (OK ${hp.auth_success_count} / FAIL ${hp.auth_failure_count})`, 'cell-mono-sub')
    );

    el.btnDetailToggle.textContent = hp.status === 'running' ? '[停止]' : '[启动]';
  }

  function formatEventBadge(entry) {
    switch (entry.event_type) {
      case 'auth_attempt':
        return entry.auth_success
          ? { text: 'AUTH_OK', cls: 'accent-phosphor' }
          : { text: 'AUTH_FAIL', cls: 'accent-amber' };
      case 'command':
        return { text: 'COMMAND', cls: 'accent-magenta' };
      case 'session_open':
        return { text: 'OPEN', cls: 'accent-cyan' };
      case 'session_close':
        return { text: 'CLOSE', cls: 'accent-grey' };
      default:
        return { text: (entry.event_type || 'EVENT').toUpperCase(), cls: 'accent-grey' };
    }
  }

  function renderLogs(logs, total) {
    state.logs = logs;
    state.totalLogs = total;

    el.logsSummary.textContent = `# 当前显示 ${logs.length} 条记录（共匹配 ${total} 条）。`;
    clearChildren(el.logsBody);

    if (logs.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'comment-cell';
      td.textContent = '# 当前蜜罐暂无匹配的访问或命令审计记录。';
      tr.appendChild(td);
      el.logsBody.appendChild(tr);
      return;
    }

    for (const entry of logs) {
      const tr = document.createElement('tr');

      // TIMESTAMP
      const tdTime = document.createElement('td');
      tdTime.appendChild(makeSpan(formatTimestamp(entry.timestamp), 'accent-grey'));
      tr.appendChild(tdTime);

      // SOURCE IP
      const tdIP = document.createElement('td');
      const ipText = entry.source_port ? `${entry.source_ip}:${entry.source_port}` : entry.source_ip || '-';
      tdIP.appendChild(makeSpan(ipText, 'accent-cyan'));
      if (entry.client_version) {
        tdIP.appendChild(makeSpan(entry.client_version, 'cell-mono-sub'));
      }
      tr.appendChild(tdIP);

      // SESSION
      const tdSession = document.createElement('td');
      tdSession.appendChild(makeSpan(entry.session_id || '-', 'accent-grey'));
      tr.appendChild(tdSession);

      // EVENT
      const tdEvent = document.createElement('td');
      const badge = formatEventBadge(entry);
      tdEvent.appendChild(makeSpan(badge.text, badge.cls));
      tr.appendChild(tdEvent);

      // AUTH / USER
      const tdAuth = document.createElement('td');
      if (entry.event_type === 'auth_attempt') {
        const userText = entry.username || '(empty)';
        const passText = entry.password || '(empty)';
        tdAuth.appendChild(makeSpan(`${userText} / ${passText}`, entry.auth_success ? 'accent-phosphor' : 'accent-amber'));
      } else {
        tdAuth.appendChild(makeSpan(entry.username || '-', ''));
      }
      tr.appendChild(tdAuth);

      // COMMAND / DETAIL
      const tdCmd = document.createElement('td');
      tdCmd.className = 'cmd-cell';
      if (entry.command) {
        tdCmd.appendChild(makeSpan(`$ ${entry.command}`, 'accent-magenta'));
        if (entry.detail) {
          tdCmd.appendChild(makeSpan(entry.detail, 'cell-mono-sub'));
        }
      } else {
        tdCmd.appendChild(makeSpan(entry.detail || '-', 'accent-grey'));
      }
      tr.appendChild(tdCmd);

      el.logsBody.appendChild(tr);
    }
  }

  function buildFilterParams(includeLimit) {
    const params = new URLSearchParams();
    if (includeLimit) {
      params.set('limit', '200');
    }
    if (el.filterEvent.value) {
      params.set('event_type', el.filterEvent.value);
    }
    if (el.filterQuery.value.trim()) {
      params.set('q', el.filterQuery.value.trim());
    }
    return params;
  }

  function buildDetailLogsURL(id) {
    const params = buildFilterParams(true);
    params.set('honeypot_id', id);
    return `/api/logs?${params.toString()}`;
  }

  function buildExportURL(id, format) {
    const params = buildFilterParams(false);
    params.set('format', format);
    return `/api/honeypots/${encodeURIComponent(id)}/logs/export?${params.toString()}`;
  }

  function parseRouteFromHash() {
    const hash = window.location.hash || '#/';
    const match = /^#\/honeypots\/([^/?#]+)$/.exec(hash);
    if (match) {
      return decodeURIComponent(match[1]);
    }
    return null;
  }

  function applyViewVisibility() {
    const inDetail = Boolean(state.selectedID);
    el.viewHome.classList.toggle('hidden', inDetail);
    el.viewDetail.classList.toggle('hidden', !inDetail);
    if (!inDetail) {
      el.statusSession.textContent = 'FISHING // SSH-HONEYPOT [HOME]';
    }
  }

  function syncRouteFromHash(resetFilters) {
    const nextID = parseRouteFromHash();
    const changed = nextID !== state.selectedID;
    state.selectedID = nextID;

    if (changed && resetFilters) {
      el.filterEvent.value = '';
      el.filterQuery.value = '';
    }
    applyViewVisibility();
    refreshActiveView();
  }

  function navigateHome() {
    if (window.location.hash !== '#/' && window.location.hash !== '') {
      window.location.hash = '#/';
    } else {
      syncRouteFromHash(true);
    }
  }

  function navigateToHoneypot(id) {
    const targetHash = `#/honeypots/${encodeURIComponent(id)}`;
    if (window.location.hash !== targetHash) {
      window.location.hash = targetHash;
    } else {
      syncRouteFromHash(true);
    }
  }

  async function refreshActiveView() {
    if (!state.selectedID) {
      try {
        const [overview, hpData] = await Promise.all([
          apiFetch('/api/overview'),
          apiFetch('/api/honeypots'),
        ]);
        showBanner('');
        renderOverview(overview);
        renderHoneypots(hpData.honeypots || []);
      } catch (err) {
        showBanner(`数据同步失败：${err.message}`);
      }
      return;
    }

    const id = state.selectedID;
    try {
      const [overview, detailData, logData] = await Promise.all([
        apiFetch('/api/overview'),
        apiFetch(`/api/honeypots/${encodeURIComponent(id)}`),
        apiFetch(buildDetailLogsURL(id)),
      ]);
      if (state.selectedID !== id) return;
      showBanner('');
      renderOverview(overview);
      renderHoneypotDetail(detailData.honeypot);
      renderLogs(logData.logs || [], logData.total || 0);
    } catch (err) {
      if (err.status === 404) {
        state.selectedID = null;
        state.selectedHoneypot = null;
        window.location.hash = '#/';
        showBanner('所选蜜罐实例已不存在，已返回实例列表。');
        return;
      }
      showBanner(`蜜罐详情读取失败：${err.message}`);
    }
  }

  async function refreshDetailLogsOnly() {
    if (!state.selectedID) return;
    const id = state.selectedID;
    try {
      const [overview, logData] = await Promise.all([
        apiFetch('/api/overview'),
        apiFetch(buildDetailLogsURL(id)),
      ]);
      if (state.selectedID !== id) return;
      showBanner('');
      renderOverview(overview);
      renderLogs(logData.logs || [], logData.total || 0);
    } catch (err) {
      showBanner(`日志读取失败：${err.message}`);
    }
  }

  async function handleToggleHoneypot(hp) {
    if (!hp) return;
    const action = hp.status === 'running' ? 'stop' : 'start';
    try {
      await apiFetch(`/api/honeypots/${encodeURIComponent(hp.id)}/${action}`, { method: 'POST' });
      await refreshActiveView();
    } catch (err) {
      showBanner(`操作失败：${err.message}`);
    }
  }

  async function handleDeleteHoneypot(hp) {
    if (!hp) return;
    const confirmed = window.confirm(`确认删除蜜罐「${hp.name}」(端口 ${hp.port})？历史访问日志将保留至数据目录。`);
    if (!confirmed) return;
    try {
      await apiFetch(`/api/honeypots/${encodeURIComponent(hp.id)}`, { method: 'DELETE' });
      state.revealedSecrets.delete(hp.id);
      if (state.selectedID === hp.id) {
        state.selectedHoneypot = null;
        navigateHome();
      } else {
        await refreshActiveView();
      }
    } catch (err) {
      showBanner(`删除蜜罐失败：${err.message}`);
    }
  }

  async function handleClearLogs() {
    if (!state.selectedID) return;
    const confirmed = window.confirm('确认清空当前蜜罐实例的全部访问与命令审计日志？该操作不可撤销。');
    if (!confirmed) return;

    try {
      await apiFetch(`/api/logs?honeypot_id=${encodeURIComponent(state.selectedID)}`, { method: 'DELETE' });
      await refreshActiveView();
    } catch (err) {
      showBanner(`清空日志失败：${err.message}`);
    }
  }

  function handleExportLogs(format) {
    if (!state.selectedID) return;
    const url = buildExportURL(state.selectedID, format);
    const link = document.createElement('a');
    link.href = url;
    link.download = '';
    link.className = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  function openCreateModal() {
    state.lastFocusedElement = document.activeElement;
    showCreateError('');
    el.createForm.reset();
    el.createModal.classList.remove('hidden');
    el.inputPort.focus();
  }

  function closeCreateModal() {
    el.createModal.classList.add('hidden');
    showCreateError('');
    if (state.lastFocusedElement && typeof state.lastFocusedElement.focus === 'function') {
      state.lastFocusedElement.focus();
    }
  }

  async function handleCreateSubmit(event) {
    event.preventDefault();
    showCreateError('');

    const port = Number.parseInt(el.inputPort.value, 10);
    const username = el.inputUsername.value.trim();
    const password = el.inputPassword.value;
    const name = el.inputName.value.trim();

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      showCreateError('监听端口必须为 1 至 65535 之间的整数。');
      el.inputPort.focus();
      return;
    }
    if (!username) {
      showCreateError('登录用户名不可为空。');
      el.inputUsername.focus();
      return;
    }
    if (!password) {
      showCreateError('登录密码不可为空。');
      el.inputPassword.focus();
      return;
    }

    el.btnSubmitCreate.disabled = true;
    el.btnSubmitCreate.textContent = '[创建中...]';

    try {
      await apiFetch('/api/honeypots', {
        method: 'POST',
        body: JSON.stringify({
          type: 'ssh',
          port,
          username,
          password,
          name,
        }),
      });
      closeCreateModal();
      await refreshActiveView();
    } catch (err) {
      showCreateError(`创建失败：${err.message}`);
    } finally {
      el.btnSubmitCreate.disabled = false;
      el.btnSubmitCreate.textContent = '[确认创建]';
    }
  }

  function toggleAutoRefresh() {
    state.autoRefresh = !state.autoRefresh;
    el.btnTogglePoll.textContent = state.autoRefresh ? '[自动刷新: 开]' : '[自动刷新: 关]';
    if (state.autoRefresh) {
      startPolling();
      refreshActiveView();
    } else {
      stopPolling();
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (state.autoRefresh && !document.hidden) {
        refreshActiveView();
      }
    }, 3000);
  }

  function stopPolling() {
    if (state.pollTimer !== null) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function updateClock() {
    const now = new Date();
    el.statusClock.textContent = now.toISOString().slice(11, 19) + ' UTC';
  }

  function bindEvents() {
    window.addEventListener('hashchange', () => syncRouteFromHash(true));

    el.btnRefreshHome.addEventListener('click', refreshActiveView);
    el.btnOpenCreate.addEventListener('click', openCreateModal);
    el.btnCloseCreate.addEventListener('click', closeCreateModal);
    el.btnCancelCreate.addEventListener('click', closeCreateModal);
    el.createForm.addEventListener('submit', handleCreateSubmit);

    el.createModal.addEventListener('click', (e) => {
      if (e.target === el.createModal) {
        closeCreateModal();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !el.createModal.classList.contains('hidden')) {
        closeCreateModal();
      }
    });

    el.btnBackHome.addEventListener('click', navigateHome);
    el.btnDetailToggle.addEventListener('click', () => handleToggleHoneypot(state.selectedHoneypot));
    el.btnDetailDelete.addEventListener('click', () => handleDeleteHoneypot(state.selectedHoneypot));

    el.btnExportJSONL.addEventListener('click', () => handleExportLogs('jsonl'));
    el.btnExportCSV.addEventListener('click', () => handleExportLogs('csv'));
    el.btnTogglePoll.addEventListener('click', toggleAutoRefresh);
    el.btnRefreshLogs.addEventListener('click', refreshActiveView);
    el.btnClearLogs.addEventListener('click', handleClearLogs);

    el.filterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      refreshDetailLogsOnly();
    });
    el.filterEvent.addEventListener('change', refreshDetailLogsOnly);
    el.btnResetFilter.addEventListener('click', () => {
      el.filterEvent.value = '';
      el.filterQuery.value = '';
      refreshDetailLogsOnly();
    });
  }

  bindEvents();
  updateClock();
  window.setInterval(updateClock, 1000);
  syncRouteFromHash(false);
  startPolling();
})();
