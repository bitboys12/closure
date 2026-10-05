/**
 * CLOSURE Web Visualizer Client Logic
 */
let currentSessionId = null;
let currentBoundary = null;
let activeSocket = null;
let eventCount = 0;

const DOM = {
  presetsContainer: document.getElementById('presets-container'),
  commandInput: document.getElementById('command-input'),
  sessionBadge: document.getElementById('session-badge'),
  workingDir: document.getElementById('working-dir'),
  reInterceptBtn: document.getElementById('re-intercept-btn'),
  boundaryReads: document.getElementById('boundary-reads'),
  boundaryDenies: document.getElementById('boundary-denies'),
  boundaryExecs: document.getElementById('boundary-execs'),
  boundaryNetwork: document.getElementById('boundary-network'),
  approveBtn: document.getElementById('approve-btn'),
  rejectBtn: document.getElementById('reject-btn'),
  terminalBody: document.getElementById('terminal-body'),
  eventCountBadge: document.getElementById('event-count-badge'),
  clearTerminalBtn: document.getElementById('clear-terminal-btn'),
  executionState: document.getElementById('execution-state'),
  violationCard: document.getElementById('violation-card'),
  violationReason: document.getElementById('violation-reason'),
  violationSyscall: document.getElementById('violation-syscall'),
  violationTarget: document.getElementById('violation-target'),
  wsStatus: document.getElementById('ws-status'),
  wsIndicator: document.getElementById('ws-indicator')
};

async function init() {
  await loadPresets();
  setupEventListeners();
  // Trigger initial preset
  const defaultCommand = DOM.commandInput.value;
  await createSession(defaultCommand);
}

async function loadPresets() {
  try {
    const res = await fetch('/api/presets');
    const presets = await res.json();

    DOM.presetsContainer.innerHTML = '';
    presets.forEach((preset, index) => {
      const btn = document.createElement('button');
      btn.className = `px-3 py-1.5 rounded-xl text-xs font-medium border transition flex items-center space-x-1.5 ${
        index === 0
          ? 'bg-rose-950/40 text-rose-300 border-rose-800/80 hover:bg-rose-900/50'
          : 'bg-slate-800/60 text-slate-300 border-slate-700/60 hover:bg-slate-700/60'
      }`;
      btn.innerHTML = `
        <span>${preset.name}</span>
      `;
      btn.addEventListener('click', async () => {
        DOM.commandInput.value = preset.command;
        await createSession(preset.command);
      });
      DOM.presetsContainer.appendChild(btn);
    });
  } catch (err) {
    console.warn('[CLOSURE] Could not load presets from API:', err);
  }
}

async function createSession(command) {
  try {
    const res = await fetch('/api/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command: command,
        working_directory: '/workspace'
      })
    });

    const data = await res.json();
    currentSessionId = data.session_id;
    currentBoundary = data.boundary;

    DOM.sessionBadge.textContent = currentSessionId;
    DOM.executionState.textContent = 'READY FOR APPROVAL';
    DOM.executionState.className = 'text-blue-400 font-semibold';
    DOM.violationCard.classList.add('hidden');

    renderBoundary(data.boundary);
    appendTerminalLog(`[CLOSURE Gateway] Intercepted command: "${command}" (Session: ${currentSessionId})`, 'system');
  } catch (err) {
    console.error('[CLOSURE] Session creation failed:', err);
    appendTerminalLog(`[-] Error creating session: ${err.message}`, 'error');
  }
}

function renderBoundary(boundary) {
  // Reads
  DOM.boundaryReads.innerHTML = boundary.allowed_read_paths.map(p =>
    `<span class="px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 font-mono text-[11px] border border-slate-700/40">${p}</span>`
  ).join('');

  // Denies
  DOM.boundaryDenies.innerHTML = boundary.deny_sensitive_paths.map(p =>
    `<span class="px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 font-mono text-[11px] border border-rose-800/60 font-medium">${p}</span>`
  ).join('');

  // Executables
  DOM.boundaryExecs.innerHTML = boundary.allowed_executables.map(e =>
    `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700/40">${e}</span>`
  ).join('');

  // Network
  DOM.boundaryNetwork.innerHTML = boundary.allowed_network_hosts.map(h =>
    `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700/40">${h}</span>`
  ).join('');
}

function setupEventListeners() {
  DOM.reInterceptBtn.addEventListener('click', () => {
    createSession(DOM.commandInput.value);
  });

  DOM.commandInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      createSession(DOM.commandInput.value);
    }
  });

  DOM.approveBtn.addEventListener('click', startExecution);

  DOM.rejectBtn.addEventListener('click', () => {
    if (activeSocket) {
      activeSocket.send(JSON.stringify({ type: 'REJECT' }));
    }
    DOM.executionState.textContent = 'REJECTED';
    DOM.executionState.className = 'text-rose-400 font-semibold';
    appendTerminalLog(`[CLOSURE Operator] Execution rejected by human operator.`, 'warning');
  });

  DOM.clearTerminalBtn.addEventListener('click', () => {
    DOM.terminalBody.innerHTML = '<div class="text-slate-500 italic">Terminal cleared.</div>';
    eventCount = 0;
    DOM.eventCountBadge.textContent = '0 events';
  });
}

function startExecution() {
  if (!currentSessionId) return;

  if (activeSocket) {
    activeSocket.close();
  }

  DOM.violationCard.classList.add('hidden');
  DOM.executionState.textContent = 'RUNNING (ENFORCING)';
  DOM.executionState.className = 'text-amber-400 font-semibold animate-pulse';
  DOM.approveBtn.disabled = true;
  DOM.approveBtn.classList.add('opacity-50');

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/${currentSessionId}`;

  activeSocket = new WebSocket(wsUrl);

  activeSocket.onopen = () => {
    appendTerminalLog(`[CLOSURE Enforcer] Boundary approved. Starting sandbox telemetry stream...`, 'success');
    activeSocket.send(JSON.stringify({ type: 'APPROVE' }));
  };

  activeSocket.onmessage = (msgEvent) => {
    const msg = JSON.parse(msgEvent.data);

    if (msg.type === 'SYSCALL') {
      renderSyscallEvent(msg.data);
    } else if (msg.type === 'VIOLATION') {
      handleViolation(msg.data);
    } else if (msg.type === 'FINISHED') {
      handleFinished(msg.data);
    }
  };

  activeSocket.onclose = () => {
    DOM.approveBtn.disabled = false;
    DOM.approveBtn.classList.remove('opacity-50');
  };

  activeSocket.onerror = (err) => {
    console.error('[WebSocket Error]', err);
    DOM.approveBtn.disabled = false;
    DOM.approveBtn.classList.remove('opacity-50');
  };
}

function renderSyscallEvent(data) {
  eventCount++;
  DOM.eventCountBadge.textContent = `${eventCount} events`;

  const time = (data.timestamp || new Date().toISOString()).split('T')[1].slice(0, 8);
  const row = document.createElement('div');
  row.className = 'flex items-center space-x-2 py-0.5 hover:bg-slate-900/60 rounded px-1.5 transition text-[11px]';

  let badgeColor = 'bg-blue-950 text-blue-400 border-blue-800';
  if (data.syscall === 'execve') badgeColor = 'bg-purple-950 text-purple-400 border-purple-800';
  if (data.syscall === 'connect') badgeColor = 'bg-cyan-950 text-cyan-400 border-cyan-800';

  row.innerHTML = `
    <span class="text-slate-600 font-mono text-[10px]">${time}</span>
    <span class="px-1.5 py-0.2 text-[10px] font-mono rounded border ${badgeColor}">${data.syscall}</span>
    <span class="text-slate-500 font-mono text-[10px]">[pid ${data.pid || '-'}]</span>
    <span class="text-slate-300 font-mono truncate flex-1">${data.target}</span>
    <span class="text-emerald-400 font-mono text-[10px] bg-emerald-950/40 px-1.5 py-0.2 rounded border border-emerald-900/40">✓ IN_BOUND</span>
  `;

  DOM.terminalBody.appendChild(row);
  DOM.terminalBody.scrollTop = DOM.terminalBody.scrollHeight;
}

function handleViolation(data) {
  DOM.violationCard.classList.remove('hidden');
  DOM.violationReason.textContent = data.details || `Unauthorized access to ${data.target}`;
  DOM.violationSyscall.textContent = data.syscall;
  DOM.violationTarget.textContent = data.target;

  DOM.executionState.textContent = 'BLOCKED (SIGKILL)';
  DOM.executionState.className = 'text-rose-400 font-bold';

  const row = document.createElement('div');
  row.className = 'bg-rose-950/80 border border-rose-600 p-2.5 rounded-lg my-2 text-rose-200 font-mono text-xs';
  row.innerHTML = `
    <div class="font-bold text-rose-400 flex items-center space-x-1.5">
      <span>🚨 [VIOLATION]</span>
      <span>${data.category}</span>
    </div>
    <div class="text-rose-300 mt-1">Syscall: <code class="text-white">${data.syscall}("${data.target}")</code></div>
    <div class="text-emerald-400 text-[11px] mt-1">Action: Process tree terminated instantaneously via SIGKILL.</div>
  `;
  DOM.terminalBody.appendChild(row);
  DOM.terminalBody.scrollTop = DOM.terminalBody.scrollHeight;
}

function handleFinished(data) {
  DOM.approveBtn.disabled = false;
  DOM.approveBtn.classList.remove('opacity-50');

  if (data.status === 'COMPLETED_ALLOWED') {
    DOM.executionState.textContent = 'ALLOWED (EXIT 0)';
    DOM.executionState.className = 'text-emerald-400 font-bold';
    appendTerminalLog(`[CLOSURE Enforcer] Command completed cleanly within all approved effect boundaries.`, 'success');
  }
}

function appendTerminalLog(text, type = 'info') {
  const row = document.createElement('div');
  let color = 'text-slate-400';
  if (type === 'success') color = 'text-emerald-400 font-medium';
  if (type === 'warning') color = 'text-amber-400 font-medium';
  if (type === 'error') color = 'text-rose-400 font-medium';
  if (type === 'system') color = 'text-blue-400';

  row.className = `py-0.5 text-[11px] font-mono ${color}`;
  row.textContent = text;
  DOM.terminalBody.appendChild(row);
  DOM.terminalBody.scrollTop = DOM.terminalBody.scrollHeight;
}

// Initialize on load
window.addEventListener('DOMContentLoaded', init);
