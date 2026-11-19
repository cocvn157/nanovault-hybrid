import {
  InferenceMode,
  InferenceSource,
  detectOnDeviceCapabilities,
  runHybridInference,
  type FirebaseConfigInput,
  type HybridExecutionResult,
} from './hybrid-engine.ts';
import { scanAndRedact, type PrivacyPolicy } from './pii-guard.ts';

const PRESETS: Record<string, string> = {
  outage: [
    'ALERT: Checkout worker crashed on 10.42.19.88 during deploy by lead.sre@acme-fin.io.',
    'Leaked AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and GitHub token ghp_9182736455abcdef1234567890abcdef1234.',
    'DB URL: postgres://deploy_bot:UltraS3cretPass!@prod-db.internal:5432/payments',
    'Session JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcmVfMDEiLCJzY29wZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  ].join('\n'),
  fintech: [
    'Customer Elena Vance (elena.vance@nordicmail.eu, +49 170 5550192) opened dispute #8841.',
    'Refund target IBAN: DE89370400440532013000',
    'Masked card trace still visible in log: 4532 0151 1283 0366',
    `Internal webhook key: ${['sk', 'live', '51N9xYzAbCdEfGhIjKlMnOpQrStUvWx'].join('_')}`,
  ].join('\n'),
  ssh: [
    'Emergency rotation ticket for Firebase web key AIzaSyD-9xYz1234567890AbCdEfGhIjKlMnOpQrS.',
    'Developer accidentally pasted private key into crash log:',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M',
    '9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/==',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n'),
  clean:
    'Summarize best practices for running Gemini Nano on-device via Firebase AI Logic Hybrid Inference in Chrome.',
};

const el = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`Missing DOM element #${id}`);
  return node as T;
};

const promptInput = el<HTMLTextAreaElement>('promptInput');
const modeSelect = el<HTMLSelectElement>('modeSelect');
const taskSelect = el<HTMLSelectElement>('taskSelect');
const toggleSecrets = el<HTMLInputElement>('toggleSecrets');
const togglePii = el<HTMLInputElement>('togglePii');
const toggleNetwork = el<HTMLInputElement>('toggleNetwork');
const toggleStrictFirewall = el<HTMLInputElement>('toggleStrictFirewall');
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
const entityList = el<HTMLElement>('entityList');
const riskMeter = el<HTMLElement>('riskMeter');
const riskLevelText = el<HTMLElement>('riskLevelText');
const nanoProbeBadge = el<HTMLElement>('nanoProbeBadge');
const activeModeBadge = el<HTMLElement>('activeModeBadge');
const resultStatusBadge = el<HTMLElement>('resultStatusBadge');
const metricSource = el<HTMLElement>('metricSource');
const metricLatency = el<HTMLElement>('metricLatency');
const metricBytes = el<HTMLElement>('metricBytes');
const metricDecision = el<HTMLElement>('metricDecision');
const panelRestored = el<HTMLElement>('panelRestored');
const panelWire = el<HTMLElement>('panelWire');
const panelRaw = el<HTMLElement>('panelRaw');
const panelAudit = el<HTMLElement>('panelAudit');
const auditBody = el<HTMLElement>('auditBody');
const auditCount = el<HTMLElement>('auditCount');

const auditHistory: HybridExecutionResult[] = [];
const SESSION_KEY = 'nanovault_firebase_session';

function currentPolicy(): PrivacyPolicy {
  return {
    redactSecrets: toggleSecrets.checked,
    redactPii: togglePii.checked,
    redactNetwork: toggleNetwork.checked,
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

function renderLiveRedaction(): void {
  const result = scanAndRedact(promptInput.value, currentPolicy());
  scanStats.textContent = `${result.entities.length} entities · ${result.scanDurationMs} ms local scan`;
  riskLevelText.textContent = `${result.riskLevel} (${result.riskScore}/100)`;
  riskMeter.className = `risk-meter risk-${result.riskLevel}`;
  panelWire.textContent = result.redactedText || '(empty prompt)';

  if (result.entities.length === 0) {
    entityList.innerHTML = '<p class="muted small">No sensitive tokens detected.</p>';
    return;
  }

  entityList.innerHTML = '';
  for (const ent of result.entities) {
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

function renderAuditLog(): void {
  auditCount.textContent = String(auditHistory.length);
  if (auditHistory.length === 0) {
    auditBody.innerHTML = '<tr><td colspan="7" class="muted">No executions yet.</td></tr>';
    return;
  }

  auditBody.innerHTML = '';
  for (const row of auditHistory) {
    const tr = document.createElement('tr');
    const cells = [
      row.timestampIso.slice(11, 19),
      row.effectiveMode.toUpperCase(),
      String(row.inferenceSource).toUpperCase(),
      `${row.latencyMs} ms`,
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

function renderExecutionResult(res: HybridExecutionResult): void {
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
      : res.inferenceSource === InferenceSource.ON_DEVICE
        ? 'ON_DEVICE (Gemini Nano)'
        : `IN_CLOUD (${res.executionKind === 'FIREBASE_HYBRID_SDK' ? 'Firebase Live' : 'Demo Fallback'})`;

  metricLatency.textContent = `${res.latencyMs} ms`;
  metricBytes.textContent = `${res.cloudBytesTransmitted} B`;
  metricDecision.textContent = res.policyDecision;

  panelWire.textContent = res.wirePayload;
  if (res.status === 'BLOCKED') {
    panelRaw.textContent = `[BLOCKED]\n${res.errorMessage ?? 'Blocked by privacy policy.'}`;
    panelRestored.textContent = `[EXECUTION BLOCKED BY PRIVACY POLICY]\n\n${res.errorMessage ?? ''}\n\nProtected Entities Held Locally: ${res.redaction.entities.length}\nCloud Bytes Sent: 0 B`;
  } else {
    panelRaw.textContent = res.rawModelOutput;
    panelRestored.textContent = res.restoredOutput;
  }

  auditHistory.unshift(res);
  renderAuditLog();
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

async function initCapabilityProbe(): Promise<void> {
  const report = await detectOnDeviceCapabilities();
  if (report.availability === 'available') {
    nanoProbeBadge.textContent = `Gemini Nano: AVAILABLE (${report.apiDetected})`;
    nanoProbeBadge.className = 'badge badge-on-device';
  } else {
    nanoProbeBadge.textContent = `Gemini Nano: ${report.availability.toUpperCase()} (Cloud Fallback Ready)`;
    nanoProbeBadge.className = 'badge badge-in-cloud';
  }
}

function wireEvents(): void {
  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.preset ?? 'outage';
      promptInput.value = PRESETS[key] ?? PRESETS.outage;
      renderLiveRedaction();
    });
  });

  [promptInput, toggleSecrets, togglePii, toggleNetwork].forEach((node) => {
    node.addEventListener('input', renderLiveRedaction);
    node.addEventListener('change', renderLiveRedaction);
  });

  modeSelect.addEventListener('change', () => {
    activeModeBadge.textContent = modeSelect.value.toUpperCase();
  });

  toggleConfigBtn.addEventListener('click', () => {
    firebaseConfigDrawer.classList.toggle('hidden');
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
    copySafeBtn.textContent = 'Copied Safe Prompt!';
    setTimeout(() => {
      copySafeBtn.textContent = 'Copy Sanitized Prompt';
    }, 1500);
  });

  runBtn.addEventListener('click', () => {
    void handleRun();
  });

  const tabs = document.querySelectorAll<HTMLButtonElement>('.tab');
  const tabMap: Record<string, HTMLElement> = {
    restored: panelRestored,
    wire: panelWire,
    raw: panelRaw,
    audit: panelAudit,
  };

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab ?? 'restored';
      tabs.forEach((t) => t.classList.toggle('active', t === tab));
      Object.entries(tabMap).forEach(([key, panel]) => {
        panel.classList.toggle('hidden', key !== target);
      });
    });
  });
}

loadSessionFirebaseConfig();
promptInput.value = PRESETS.outage;
activeModeBadge.textContent = modeSelect.value.toUpperCase();
wireEvents();
renderLiveRedaction();
void initCapabilityProbe();
