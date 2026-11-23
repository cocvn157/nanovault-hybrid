import {
  InferenceMode,
  InferenceSource,
  detectOnDeviceCapabilities,
  runHybridInference,
  type FirebaseConfigInput,
  type HybridExecutionResult,
  type OnDeviceCapabilityReport,
} from './hybrid-engine.ts';
import { getPresetById } from './presets.ts';
import {
  buildRedactionDiff,
  scanAndRedact,
  searchVaultEntities,
  verifyZeroRawLeaks,
  type MaskStyle,
  type PrivacyPolicy,
  type RedactionResult,
} from './pii-guard.ts';
import {
  estimateHybridEconomics,
  formatUsd,
  summarizeSessionTelemetry,
  type HybridEconomicsReport,
} from './telemetry.ts';

const el = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing DOM element #${id}`);
  return node as T;
};

const promptInput = el<HTMLTextAreaElement>('promptInput');
const presetDescription = el<HTMLElement>('presetDescription');
const modeSelect = el<HTMLSelectElement>('modeSelect');
const taskSelect = el<HTMLSelectElement>('taskSelect');
const toggleSecrets = el<HTMLInputElement>('toggleSecrets');
const togglePii = el<HTMLInputElement>('togglePii');
const toggleSsn = el<HTMLInputElement>('toggleSsn');
const toggleNetwork = el<HTMLInputElement>('toggleNetwork');
const toggleStrictFirewall = el<HTMLInputElement>('toggleStrictFirewall');
const maskStyleSelect = el<HTMLSelectElement>('maskStyleSelect');
const toggleOfflineBtn = el<HTMLButtonElement>('toggleOfflineBtn');
const reprobeBtn = el<HTMLButtonElement>('reprobeBtn');
const toggleConfigBtn = el<HTMLButtonElement>('toggleConfigBtn');
const firebaseConfigDrawer = el<HTMLElement>('firebaseConfigDrawer');
const clearConfigBtn = el<HTMLButtonElement>('clearConfigBtn');
const fbApiKey = el<HTMLInputElement>('fbApiKey');
const fbProjectId = el<HTMLInputElement>('fbProjectId');
const fbAppId = el<HTMLInputElement>('fbAppId');
const fbCloudModel = el<HTMLInputElement>('fbCloudModel');
const runBtn = el<HTMLButtonElement>('runBtn');
const copySafeBtn = el<HTMLButtonElement>('copySafeBtn');
const scanStats = el<HTMLElement>('scanStats');
const vaultCountLabel = el<HTMLElement>('vaultCountLabel');
const vaultSearchInput = el<HTMLInputElement>('vaultSearchInput');
const entityList = el<HTMLElement>('entityList');
const riskMeter = el<HTMLElement>('riskMeter');
const riskLevelText = el<HTMLElement>('riskLevelText');
const nanoProbeBadge = el<HTMLElement>('nanoProbeBadge');
const activeModeBadge = el<HTMLElement>('activeModeBadge');
const capPromptApi = el<HTMLElement>('capPromptApi');
const capWebGpu = el<HTMLElement>('capWebGpu');
const capWasm = el<HTMLElement>('capWasm');
const capNetwork = el<HTMLElement>('capNetwork');
const resultStatusBadge = el<HTMLElement>('resultStatusBadge');
const metricSource = el<HTMLElement>('metricSource');
const metricLatency = el<HTMLElement>('metricLatency');
const metricBytes = el<HTMLElement>('metricBytes');
const metricCost = el<HTMLElement>('metricCost');
const zeroLeakBanner = el<HTMLElement>('zeroLeakBanner');
const barLocalLatency = el<HTMLElement>('barLocalLatency');
const barCloudLatency = el<HTMLElement>('barCloudLatency');
const lblLocalLatency = el<HTMLElement>('lblLocalLatency');
const lblCloudLatency = el<HTMLElement>('lblCloudLatency');
const lblLocalCost = el<HTMLElement>('lblLocalCost');
const lblCloudCost = el<HTMLElement>('lblCloudCost');
const lblSessionSaved = el<HTMLElement>('lblSessionSaved');
const panelDiff = el<HTMLElement>('panelDiff');
const diffBeforeBox = el<HTMLElement>('diffBeforeBox');
const diffAfterBox = el<HTMLElement>('diffAfterBox');
const panelRestored = el<HTMLElement>('panelRestored');
const panelEconomics = el<HTMLElement>('panelEconomics');
const panelWire = el<HTMLElement>('panelWire');
const panelRaw = el<HTMLElement>('panelRaw');
const panelAudit = el<HTMLElement>('panelAudit');
const auditBody = el<HTMLElement>('auditBody');
const auditCount = el<HTMLElement>('auditCount');

const auditHistory: HybridExecutionResult[] = [];
const SESSION_KEY = 'nanovault_firebase_session';

let offlineOverride = false;
let latestCapability: OnDeviceCapabilityReport | null = null;
let latestRedaction: RedactionResult | null = null;
let latestExecution: HybridExecutionResult | null = null;

function isOfflineEffective(): boolean {
  const browserOffline = typeof navigator !== 'undefined' && navigator.onLine === false;
  return offlineOverride || browserOffline;
}

function currentPolicy(): PrivacyPolicy {
  return {
    redactSecrets: toggleSecrets.checked,
    redactPii: togglePii.checked,
    redactSsn: toggleSsn.checked,
    redactNetwork: toggleNetwork.checked,
    maskStyle: (maskStyleSelect.value as MaskStyle) || 'redacted',
  };
}

function loadSessionFirebaseConfig(): void {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as Partial<FirebaseConfigInput & { cloudModel?: string }>;
    if (parsed.apiKey) fbApiKey.value = parsed.apiKey;
    if (parsed.projectId) fbProjectId.value = parsed.projectId;
    if (parsed.appId) fbAppId.value = parsed.appId;
    if (parsed.cloudModel) fbCloudModel.value = parsed.cloudModel;
  } catch {
    // ignore invalid session storage
  }
}

function saveSessionFirebaseConfig(): FirebaseConfigInput | null {
  const cfg: FirebaseConfigInput = {
    apiKey: fbApiKey.value.trim(),
    projectId: fbProjectId.value.trim(),
    appId: fbAppId.value.trim(),
  };
  try {
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ ...cfg, cloudModel: fbCloudModel.value.trim() || 'gemini-2.5-flash' })
    );
  } catch {
    // ignore storage errors
  }
  if (!cfg.apiKey || !cfg.projectId || !cfg.appId) return null;
  return cfg;
}

function renderDiffInspector(redaction: RedactionResult): void {
  const segments = buildRedactionDiff(redaction);
  diffBeforeBox.textContent = '';
  diffAfterBox.textContent = '';

  if (segments.length === 0) {
    diffBeforeBox.textContent = '(empty prompt)';
    diffAfterBox.textContent = '(empty prompt)';
    return;
  }

  for (const seg of segments) {
    if (seg.kind === 'unchanged') {
      diffBeforeBox.appendChild(document.createTextNode(seg.text));
      diffAfterBox.appendChild(document.createTextNode(seg.text));
    } else {
      const rawMark = document.createElement('mark');
      rawMark.className = 'diff-raw';
      rawMark.title = `${seg.category} (${seg.severity})`;
      rawMark.textContent = seg.text;
      diffBeforeBox.appendChild(rawMark);

      const safeMark = document.createElement('mark');
      safeMark.className = 'diff-redacted';
      safeMark.title = `Masked ${seg.category} (${seg.severity})`;
      safeMark.textContent = seg.token ?? '<REDACTED>';
      diffAfterBox.appendChild(safeMark);
    }
  }
}

function renderVaultList(redaction: RedactionResult): void {
  const filtered = searchVaultEntities(redaction.entities, vaultSearchInput.value);
  vaultCountLabel.textContent = vaultSearchInput.value.trim()
    ? `${filtered.length}/${redaction.entities.length}`
    : String(redaction.entities.length);

  if (redaction.entities.length === 0) {
    entityList.innerHTML = '<p class="muted small">No sensitive tokens detected.</p>';
    return;
  }

  if (filtered.length === 0) {
    entityList.innerHTML = '<p class="muted small">No vaulted entities match your local filter.</p>';
    return;
  }

  entityList.innerHTML = '';
  for (const ent of filtered) {
    const pill = document.createElement('div');
    pill.className = `entity-pill sev-${ent.severity}`;

    const tok = document.createElement('span');
    tok.className = 'tok';
    tok.textContent = `${ent.token} (${ent.category})`;

    const meta = document.createElement('span');
    meta.className = 'meta';
    meta.textContent = `${ent.severity} · ${ent.maskedPreview}`;

    pill.append(tok, meta);
    entityList.appendChild(pill);
  }
}

function renderEconomicsVisuals(econ: HybridEconomicsReport, redaction: RedactionResult): void {
  const maxLatency = Math.max(econ.estimatedCloudLatencyMs, econ.localLatencyMs, 100);
  const localPct = Math.max(4, Math.min(100, Math.round((econ.localLatencyMs / maxLatency) * 100)));
  const cloudPct = Math.max(12, Math.min(100, Math.round((econ.estimatedCloudLatencyMs / maxLatency) * 100)));

  barLocalLatency.style.width = `${localPct}%`;
  barCloudLatency.style.width = `${cloudPct}%`;
  lblLocalLatency.textContent = `Local: ${econ.localLatencyMs.toFixed(2)} ms`;
  lblCloudLatency.textContent = `Cloud est: ~${econ.estimatedCloudLatencyMs} ms`;
  lblLocalCost.textContent = 'On-Device / Offline: $0.00';
  lblCloudCost.textContent = `Cloud Flash est: $${econ.projected1kRequestsSavingsUsd.toFixed(2)} / 1k req`;

  const session = summarizeSessionTelemetry(auditHistory);
  lblSessionSaved.textContent = `Session: ${formatUsd(session.totalActualCostUsd)} spent · ${formatUsd(
    session.totalEstimatedSavingsUsd
  )} saved`;

  // Populate detailed Benchmark Chart tab
  panelEconomics.innerHTML = '';

  const grid = document.createElement('div');
  grid.className = 'bench-grid';
  const cards: Array<[string, string]> = [
    ['Actual Run Cost', formatUsd(econ.actualCostUsd)],
    ['Est. Cloud Flash / Run', formatUsd(econ.estimatedCloudFlashCostUsd)],
    ['Est. Cloud Pro / Run', formatUsd(econ.estimatedCloudProCostUsd)],
    ['1k Requests Local Savings', `$${econ.projected1kRequestsSavingsUsd.toFixed(2)}`],
    ['Tokens (In / Out)', `${econ.inputTokens} / ${econ.outputTokens}`],
    ['Raw Secret Bytes Leaked', `0 B (${redaction.entities.length} masked)`],
    ['Session Runs (Local / Cloud / Blocked)', `${session.totalRuns} (${session.onDeviceRuns}/${session.cloudRuns}/${session.blockedRuns})`],
    ['Avg Local vs Cloud Latency', `${session.avgLocalLatencyMs || econ.localLatencyMs} ms vs ${session.avgEstimatedCloudLatencyMs || econ.estimatedCloudLatencyMs} ms`],
  ];
  for (const [k, v] of cards) {
    const card = document.createElement('div');
    card.className = 'bench-card';
    const keyEl = document.createElement('span');
    keyEl.className = 'b-k';
    keyEl.textContent = k;
    const valEl = document.createElement('strong');
    valEl.className = 'b-v';
    valEl.textContent = v;
    card.append(keyEl, valEl);
    grid.appendChild(card);
  }
  panelEconomics.appendChild(grid);

  const svgWrap = document.createElement('div');
  svgWrap.className = 'bench-svg-wrap';
  const localWidth = Math.max(8, Math.round((econ.localLatencyMs / maxLatency) * 320));
  const cloudWidth = Math.max(24, Math.round((econ.estimatedCloudLatencyMs / maxLatency) * 320));
  const rawExposureWidth = redaction.entities.length > 0 ? 320 : 12;
  svgWrap.innerHTML = `
    <svg viewBox="0 0 540 120" width="100%" height="120" role="img" aria-label="Cost, Latency, and Secret Exposure Comparison">
      <text x="0" y="20" fill="#94a3b8" font-size="11" font-family="monospace">LOCAL / NANO LATENCY</text>
      <rect x="170" y="9" width="${localWidth}" height="14" rx="4" fill="#34d399" />
      <text x="${178 + localWidth}" y="20" fill="#e2e8f0" font-size="11" font-family="monospace">${econ.localLatencyMs.toFixed(2)} ms ($0.00)</text>

      <text x="0" y="54" fill="#94a3b8" font-size="11" font-family="monospace">CLOUD ESCALATION EST</text>
      <rect x="170" y="43" width="${cloudWidth}" height="14" rx="4" fill="#a855f7" />
      <text x="${178 + cloudWidth}" y="54" fill="#e2e8f0" font-size="11" font-family="monospace">~${econ.estimatedCloudLatencyMs} ms (${formatUsd(econ.estimatedCloudFlashCostUsd)})</text>

      <text x="0" y="88" fill="#94a3b8" font-size="11" font-family="monospace">RAW SECRET EXPOSURE</text>
      <rect x="170" y="77" width="${rawExposureWidth}" height="14" rx="4" fill="rgba(244,63,94,0.35)" />
      <rect x="170" y="77" width="6" height="14" rx="3" fill="#38bdf8" />
      <text x="184" y="88" fill="#34d399" font-size="11" font-family="monospace">0 B leaked via NanoVault Gate (${redaction.entities.length} isolated)</text>
    </svg>
  `;
  panelEconomics.appendChild(svgWrap);
}

function renderLiveRedaction(): void {
  const result = scanAndRedact(promptInput.value, currentPolicy());
  latestRedaction = result;

  scanStats.textContent = `${result.entities.length} entities · ${result.scanDurationMs} ms · $0.00 local scan`;
  riskLevelText.textContent = `${result.riskLevel} (${result.riskScore}/100)`;
  riskMeter.className = `risk-meter risk-${result.riskLevel}`;
  panelWire.textContent = result.redactedText || '(empty prompt)';

  const zeroCheck = verifyZeroRawLeaks(result.redactedText, result);
  if (zeroCheck.zeroLeaks) {
    zeroLeakBanner.className = 'zero-leak-banner gate-pass';
    zeroLeakBanner.textContent =
      result.entities.length > 0
        ? `ZERO-LEAK GATE PASSED · ${result.entities.length} sensitive item(s) masked (${
            result.maskStyle === 'vault' ? '{{NV_*}}' : '<REDACTED_*>'
          }) · 0 raw secrets in egress`
        : 'ZERO-LEAK GATE ARMED · 0 sensitive items detected in current prompt';
  } else {
    zeroLeakBanner.className = 'zero-leak-banner gate-blocked';
    zeroLeakBanner.textContent = 'ZERO-LEAK GATE ALERT · Unmasked secret residue blocked';
  }

  renderVaultList(result);
  renderDiffInspector(result);

  if (!latestExecution) {
    const previewEcon = estimateHybridEconomics({
      rawPrompt: promptInput.value,
      wirePayload: result.redactedText,
      outputText: '',
      inferenceSource: InferenceSource.ON_DEVICE,
      measuredLatencyMs: result.scanDurationMs,
      cloudBytesTransmitted: 0,
      offlineMode: isOfflineEffective(),
    });
    renderEconomicsVisuals(previewEcon, result);
  }
}

function renderAuditLog(): void {
  auditCount.textContent = String(auditHistory.length);
  if (auditHistory.length === 0) {
    auditBody.innerHTML = '<tr><td colspan="8" class="muted">No executions yet.</td></tr>';
    return;
  }

  auditBody.innerHTML = '';
  for (const row of auditHistory) {
    const tr = document.createElement('tr');
    const cells = [
      row.timestampIso.slice(11, 19),
      row.effectiveMode.toUpperCase(),
      row.executionKind === 'OFFLINE_LOCAL_FALLBACK'
        ? 'OFFLINE_LOCAL'
        : String(row.inferenceSource).toUpperCase(),
      `${row.latencyMs} ms`,
      formatUsd(row.economics.actualCostUsd),
      String(row.redaction.entities.length),
      `${row.cloudBytesTransmitted} B`,
      row.policyDecision,
    ];
    for (const val of cells) {
      const td = document.createElement('td');
      td.textContent = val;
      tr.appendChild(td);
    }
    auditBody.appendChild(tr);
  }
}

function activateTab(target: string): void {
  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab'));
  const tabMap: Record<string, HTMLElement> = {
    diff: panelDiff,
    restored: panelRestored,
    economics: panelEconomics,
    wire: panelWire,
    raw: panelRaw,
    audit: panelAudit,
  };

  tabs.forEach((tab) => {
    const isTarget = (tab.dataset.tab ?? 'diff') === target;
    tab.classList.toggle('active', isTarget);
    tab.setAttribute('aria-selected', isTarget ? 'true' : 'false');
    tab.setAttribute('tabindex', isTarget ? '0' : '-1');
  });

  Object.entries(tabMap).forEach(([key, panel]) => {
    panel.classList.toggle('hidden', key !== target);
  });
}

const POLICY_BADGE_LABEL: Record<string, string> = {
  ON_DEVICE_EXECUTED: 'ON_DEVICE',
  OFFLINE_LOCAL_FALLBACK_EXECUTED: 'OFFLINE_VAULT',
  CLOUD_FALLBACK_WITH_REDACTION: 'CLOUD_FALLBACK',
  CLOUD_PRIMARY_WITH_REDACTION: 'CLOUD_PRIMARY',
  BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE: 'BLOCKED_NO_NANO',
  BLOCKED_CRITICAL_SECRET_POLICY: 'BLOCKED_FIREWALL',
  BLOCKED_OFFLINE_NETWORK_DISABLED: 'BLOCKED_OFFLINE',
  BLOCKED_ZERO_LEAK_INTEGRITY: 'BLOCKED_LEAK',
};

function renderExecutionResult(res: HybridExecutionResult): void {
  latestExecution = res;
  resultStatusBadge.textContent = res.status;
  resultStatusBadge.className =
    res.status === 'BLOCKED'
      ? 'badge badge-blocked'
      : res.inferenceSource === InferenceSource.ON_DEVICE
        ? 'badge badge-on-device'
        : 'badge badge-in-cloud';

  metricSource.textContent =
    res.inferenceSource === 'BLOCKED'
      ? 'BLOCKED (0-CLOUD)'
      : res.executionKind === 'OFFLINE_LOCAL_FALLBACK'
        ? 'OFFLINE_LOCAL ($0 Vault)'
        : res.inferenceSource === InferenceSource.ON_DEVICE
          ? 'ON_DEVICE (Gemini Nano)'
          : `IN_CLOUD (${res.executionKind === 'FIREBASE_HYBRID_SDK' ? 'Firebase Live' : 'Demo Fallback'})`;

  metricLatency.textContent = `${res.latencyMs} ms`;
  metricBytes.textContent = `${res.cloudBytesTransmitted} B`;
  metricCost.textContent = `${formatUsd(res.economics.actualCostUsd)} · ${POLICY_BADGE_LABEL[res.policyDecision] ?? res.policyDecision}`;

  panelWire.textContent = res.wirePayload;
  if (res.status === 'BLOCKED') {
    zeroLeakBanner.className = 'zero-leak-banner gate-blocked';
    zeroLeakBanner.textContent = `EXECUTION BLOCKED (${res.policyDecision}) · 0 B cloud egress · $0.00 cost`;
    panelRaw.textContent = `[BLOCKED]\n${res.errorMessage ?? 'Blocked by privacy policy.'}`;
    panelRestored.textContent = `[EXECUTION BLOCKED BY PRIVACY POLICY]\n\n${res.errorMessage ?? ''}\n\nProtected Entities Held Locally: ${res.redaction.entities.length}\nCloud Bytes Sent: 0 B\nToken Cost: $0.0000`;
  } else {
    zeroLeakBanner.className = 'zero-leak-banner gate-pass';
    zeroLeakBanner.textContent =
      res.cloudBytesTransmitted === 0
        ? `ZERO-NETWORK LOCAL EXECUTION · 0 B cloud egress · $0.0000 cost (${res.redaction.entities.length} masked)`
        : `ZERO-LEAK CLOUD ESCALATION VERIFIED · ${res.redaction.entities.length} secrets masked · 0 raw secret bytes sent`;
    panelRaw.textContent = res.rawModelOutput;
    panelRestored.textContent = res.restoredOutput;
  }

  auditHistory.unshift(res);
  renderAuditLog();
  renderEconomicsVisuals(res.economics, res.redaction);
  activateTab('restored');
}

function updateNetworkStrip(): void {
  const offline = isOfflineEffective();
  toggleOfflineBtn.classList.toggle('active', offline);
  toggleOfflineBtn.setAttribute('aria-pressed', offline ? 'true' : 'false');
  toggleOfflineBtn.textContent = offline
    ? 'Airplane Mode (Offline $0): ON'
    : 'Airplane Mode (Offline $0): OFF';

  if (offline) {
    capNetwork.textContent = 'AIRPLANE · 0 B Egress';
    capNetwork.className = 'cap-val ok';
  } else {
    capNetwork.textContent = 'Online · Hybrid Ready';
    capNetwork.className = 'cap-val';
  }
}

function renderCapabilityStrip(report: OnDeviceCapabilityReport): void {
  latestCapability = report;
  if (report.availability === 'available') {
    nanoProbeBadge.textContent = `Gemini Nano: AVAILABLE (${report.apiDetected})`;
    nanoProbeBadge.className = 'badge badge-on-device';
    capPromptApi.textContent = `READY (${report.apiDetected})`;
    capPromptApi.className = 'cap-val ok';
  } else {
    nanoProbeBadge.textContent = `Gemini Nano: ${report.availability.toUpperCase()} (Fallback Ready)`;
    nanoProbeBadge.className = 'badge badge-in-cloud';
    capPromptApi.textContent = `${report.availability.toUpperCase()} · Vault Fallback`;
    capPromptApi.className = 'cap-val warn';
  }

  capWebGpu.textContent = report.webgpuAvailable ? report.webgpuAdapter : `CPU/WASM (${report.webgpuAdapter})`;
  capWebGpu.className = report.webgpuAvailable ? 'cap-val ok' : 'cap-val';
  capWasm.textContent = report.wasmReady ? 'Ready (<1 ms)' : 'JS Fallback';
  capWasm.className = report.wasmReady ? 'cap-val ok' : 'cap-val warn';
  updateNetworkStrip();
}

async function initCapabilityProbe(): Promise<void> {
  const report = await detectOnDeviceCapabilities();
  renderCapabilityStrip(report);
}

async function handleRun(): Promise<void> {
  runBtn.disabled = true;
  runBtn.textContent = 'Running Hybrid Pipeline...';
  try {
    const fbConfig = saveSessionFirebaseConfig();
    const res = await runHybridInference({
      prompt: promptInput.value,
      taskInstruction: taskSelect.value,
      mode: modeSelect.value as InferenceMode,
      policy: currentPolicy(),
      blockCloudOnCriticalSecrets: toggleStrictFirewall.checked,
      offlineMode: isOfflineEffective(),
      firebaseConfig: fbConfig,
      cloudModel: fbCloudModel.value.trim() || 'gemini-2.5-flash',
    });
    renderExecutionResult(res);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    resultStatusBadge.textContent = 'ERROR';
    resultStatusBadge.className = 'badge badge-blocked';
    panelRestored.textContent = `Execution Error: ${message}`;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = 'Run Hybrid Inference';
  }
}

function selectPreset(presetId: string): void {
  const preset = getPresetById(presetId);
  promptInput.value = preset.prompt;
  presetDescription.textContent = preset.description;

  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((btn) => {
    const active = btn.dataset.preset === preset.id;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
  });

  latestExecution = null;
  renderLiveRedaction();
}

function wireEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      selectPreset(btn.dataset.preset ?? 'outage');
    });
  });

  [promptInput, toggleSecrets, togglePii, toggleSsn, toggleNetwork, maskStyleSelect].forEach((node) => {
    node.addEventListener('input', () => {
      latestExecution = null;
      renderLiveRedaction();
    });
    node.addEventListener('change', () => {
      latestExecution = null;
      renderLiveRedaction();
    });
  });

  vaultSearchInput.addEventListener('input', () => {
    if (latestRedaction) renderVaultList(latestRedaction);
  });

  promptInput.addEventListener('keydown', (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') {
      ev.preventDefault();
      void handleRun();
    }
  });

  modeSelect.addEventListener('change', () => {
    activeModeBadge.textContent = modeSelect.value.toUpperCase();
  });

  toggleOfflineBtn.addEventListener('click', () => {
    offlineOverride = !offlineOverride;
    updateNetworkStrip();
    if (!latestExecution && latestRedaction) {
      renderLiveRedaction();
    }
  });

  reprobeBtn.addEventListener('click', () => {
    void initCapabilityProbe();
  });

  window.addEventListener('online', () => {
    if (latestCapability) renderCapabilityStrip({ ...latestCapability, online: true });
    updateNetworkStrip();
  });

  window.addEventListener('offline', () => {
    if (latestCapability) renderCapabilityStrip({ ...latestCapability, online: false });
    updateNetworkStrip();
  });

  toggleConfigBtn.addEventListener('click', () => {
    const hidden = firebaseConfigDrawer.classList.toggle('hidden');
    toggleConfigBtn.setAttribute('aria-expanded', hidden ? 'false' : 'true');
  });

  clearConfigBtn.addEventListener('click', () => {
    fbApiKey.value = '';
    fbProjectId.value = '';
    fbAppId.value = '';
    sessionStorage.removeItem(SESSION_KEY);
  });

  copySafeBtn.addEventListener('click', async () => {
    const redacted = scanAndRedact(promptInput.value, currentPolicy()).redactedText;
    await navigator.clipboard?.writeText(redacted);
    copySafeBtn.textContent = 'Copied Safe Packet!';
    setTimeout(() => {
      copySafeBtn.textContent = 'Copy Sanitized Packet';
    }, 1500);
  });

  runBtn.addEventListener('click', () => {
    void handleRun();
  });

  const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab'));
  tabs.forEach((tab, index) => {
    tab.addEventListener('click', () => {
      activateTab(tab.dataset.tab ?? 'diff');
    });

    tab.addEventListener('keydown', (ev) => {
      let nextIdx = index;
      if (ev.key === 'ArrowRight') nextIdx = (index + 1) % tabs.length;
      else if (ev.key === 'ArrowLeft') nextIdx = (index - 1 + tabs.length) % tabs.length;
      else if (ev.key === 'Home') nextIdx = 0;
      else if (ev.key === 'End') nextIdx = tabs.length - 1;
      else return;

      ev.preventDefault();
      const nextTab = tabs[nextIdx];
      activateTab(nextTab.dataset.tab ?? 'diff');
      nextTab.focus();
    });
  });
}

loadSessionFirebaseConfig();
activeModeBadge.textContent = modeSelect.value.toUpperCase();
wireEvents();
selectPreset('outage');
void initCapabilityProbe();
