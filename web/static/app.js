(() => {
  'use strict';

  const state = {
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
    honeypotsBody: document.getElementById('honeypots-tbody'),
    logsBody: document.getElementById('logs-tbody'),
    logsSummary: document.getElementById('logs-summary'),
    filterForm: document.getElementById('log-filter-form'),
    filterHoneypot: document.getElementById('filter-honeypot'),
    filterEvent: document.getElementById('filter-event'),
    filterQuery: document.getElementById('filter-query'),
    btnResetFilter: document.getElementById('btn-reset-filter'),
    btnTogglePoll: document.getElementById('btn-toggle-poll'),
    btnRefreshLogs: document.getElementById('btn-refresh-logs'),
    btnClearLogs: document.getElementById('btn-clear-logs'),
    btnOpenCreate: document.getElementById('btn-open-create'),
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
      throw new Error(errMsg);
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

  function syncHoneypotFilterOptions(honeypots) {
    const currentVal = el.filterHoneypot.value;
    while (el.filterHoneypot.firstChild) {
      el.filterHoneypot.removeChild(el.filterHoneypot.firstChild);
    }
    const allOpt = document.createElement('option');
    allOpt.value = '';
    allOpt.textContent = '全部实例';
    el.filterHoneypot.appendChild(allOpt);

    for (const hp of honeypots) {
      const opt = document.createElement('option');
      opt.value = hp.id;
      opt.textContent = `${hp.name} (:${hp.port})`;
      el.filterHoneypot.appendChild(opt);
    }

    const exists = honeypots.some((hp) => hp.id === currentVal);
    el.filterHoneypot.value = exists ? currentVal : '';
  }

  function renderHoneypots(honeypots) {
    state.honeypots = honeypots;
    syncHoneypotFilterOptions(honeypots);

    while (el.honeypotsBody.firstChild) {
      el.honeypotsBody.removeChild(el.honeypotsBody.firstChild);
    }

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

      // NAME / ID
      const tdName = document.createElement('td');
      tdName.appendChild(makeSpan(hp.name, 'accent-phosphor'));
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
      const credWrap = document.createElement('div');
      credWrap.className = 'cred-wrap';
      const revealed = state.revealedSecrets.has(hp.id);
      const pwDisplay = revealed ? hp.password : '••••••••';
      credWrap.appendChild(makeSpan(`${hp.username} : ${pwDisplay}`, ''));

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
        renderHoneypots(state.honeypots);
      });
      credWrap.appendChild(toggleBtn);
      tdCred.appendChild(credWrap);
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

      const toggleStateBtn = document.createElement('button');
      toggleStateBtn.type = 'button';
      toggleStateBtn.className = 'btn btn-inline';
      toggleStateBtn.textContent = hp.status === 'running' ? '[停止]' : '[启动]';
      toggleStateBtn.addEventListener('click', () => handleToggleHoneypot(hp));
      actionWrap.appendChild(toggleStateBtn);

      const filterBtn = document.createElement('button');
      filterBtn.type = 'button';
      filterBtn.className = 'btn btn-inline';
      filterBtn.textContent = '[日志]';
      filterBtn.addEventListener('click', () => {
        el.filterHoneypot.value = hp.id;
        refreshLogs();
      });
      actionWrap.appendChild(filterBtn);

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

    while (el.logsBody.firstChild) {
      el.logsBody.removeChild(el.logsBody.firstChild);
    }

    if (logs.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'comment-cell';
      td.textContent = '# 暂无匹配的访问或命令审计记录。蜜罐端口收到连接或指令后将显示于此。';
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

      // TARGET
      const tdTarget = document.createElement('td');
      tdTarget.appendChild(makeSpan(`${entry.honeypot_name || entry.honeypot_id} :${entry.honeypot_port}`, ''));
      tdTarget.appendChild(makeSpan(`SID ${entry.session_id || '-'}`, 'cell-mono-sub'));
      tr.appendChild(tdTarget);

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

  async function refreshAll() {
    try {
      const [overview, hpData, logData] = await Promise.all([
        apiFetch('/api/overview'),
        apiFetch('/api/honeypots'),
        apiFetch(buildLogsURL()),
      ]);
      showBanner('');
      renderOverview(overview);
      renderHoneypots(hpData.honeypots || []);
      renderLogs(logData.logs || [], logData.total || 0);
    } catch (err) {
      showBanner(`数据同步失败：${err.message}`);
    }
  }

  function buildLogsURL() {
    const params = new URLSearchParams();
    params.set('limit', '200');
    if (el.filterHoneypot.value) {
      params.set('honeypot_id', el.filterHoneypot.value);
    }
    if (el.filterEvent.value) {
      params.set('event_type', el.filterEvent.value);
    }
    if (el.filterQuery.value.trim()) {
      params.set('q', el.filterQuery.value.trim());
    }
    return `/api/logs?${params.toString()}`;
  }

  async function refreshLogs() {
    try {
      const [overview, logData] = await Promise.all([
        apiFetch('/api/overview'),
        apiFetch(buildLogsURL()),
      ]);
      showBanner('');
      renderOverview(overview);
      renderLogs(logData.logs || [], logData.total || 0);
    } catch (err) {
      showBanner(`日志读取失败：${err.message}`);
    }
  }

  async function handleToggleHoneypot(hp) {
    const action = hp.status === 'running' ? 'stop' : 'start';
    try {
      await apiFetch(`/api/honeypots/${encodeURIComponent(hp.id)}/${action}`, { method: 'POST' });
      await refreshAll();
    } catch (err) {
      showBanner(`操作失败：${err.message}`);
    }
  }

  async function handleDeleteHoneypot(hp) {
    const confirmed = window.confirm(`确认删除蜜罐「${hp.name}」(端口 ${hp.port})？历史访问日志将保留，停止后可自行清空。`);
    if (!confirmed) return;
    try {
      await apiFetch(`/api/honeypots/${encodeURIComponent(hp.id)}`, { method: 'DELETE' });
      state.revealedSecrets.delete(hp.id);
      await refreshAll();
    } catch (err) {
      showBanner(`删除蜜罐失败：${err.message}`);
    }
  }

  async function handleClearLogs() {
    const hpID = el.filterHoneypot.value;
    const scopeLabel = hpID ? '当前选中蜜罐的' : '全部';
    const confirmed = window.confirm(`确认清空${scopeLabel}访问与命令审计日志？该操作不可撤销。`);
    if (!confirmed) return;

    const url = hpID ? `/api/logs?honeypot_id=${encodeURIComponent(hpID)}` : '/api/logs';
    try {
      await apiFetch(url, { method: 'DELETE' });
      await refreshAll();
    } catch (err) {
      showBanner(`清空日志失败：${err.message}`);
    }
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
      await refreshAll();
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
      refreshAll();
    } else {
      stopPolling();
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = window.setInterval(() => {
      if (state.autoRefresh && !document.hidden) {
        refreshAll();
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

    el.btnTogglePoll.addEventListener('click', toggleAutoRefresh);
    el.btnRefreshLogs.addEventListener('click', refreshAll);
    el.btnClearLogs.addEventListener('click', handleClearLogs);

    el.filterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      refreshLogs();
    });
    el.filterHoneypot.addEventListener('change', refreshLogs);
    el.filterEvent.addEventListener('change', refreshLogs);
    el.btnResetFilter.addEventListener('click', () => {
      el.filterHoneypot.value = '';
      el.filterEvent.value = '';
      el.filterQuery.value = '';
      refreshLogs();
    });
  }

  bindEvents();
  updateClock();
  window.setInterval(updateClock, 1000);
  refreshAll();
  startPolling();
})();
