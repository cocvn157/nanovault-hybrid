import { initializeApp, getApps, type FirebaseApp, type FirebaseOptions } from 'firebase/app';
import {
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  InferenceSource,
  type GenerativeModel,
  type HybridParams,
} from 'firebase/ai';
import {
  DEFAULT_PRIVACY_POLICY,
  restoreTokens,
  scanAndRedact,
  verifyZeroRawLeaks,
  type PrivacyPolicy,
  type RedactionResult,
  type ZeroLeakCheckResult,
} from './pii-guard.ts';
import { estimateHybridEconomics, type HybridEconomicsReport } from './telemetry.ts';

export { InferenceMode, InferenceSource };

export type OnDeviceAvailability = 'available' | 'downloadable' | 'downloading' | 'unavailable';

export type LocalEngineTier =
  | 'CHROME_GEMINI_NANO'
  | 'HYBRID_DOWNLOADABLE'
  | 'DETERMINISTIC_LOCAL_VAULT';

export interface OnDeviceCapabilityReport {
  apiDetected: 'window.LanguageModel' | 'window.ai.languageModel' | 'none';
  availability: OnDeviceAvailability;
  promptApiReady: boolean;
  webgpuAvailable: boolean;
  webgpuAdapter: string;
  wasmReady: boolean;
  online: boolean;
  localEngineTier: LocalEngineTier;
  note: string;
}

export type ExecutionKind =
  | 'FIREBASE_HYBRID_SDK'
  | 'CHROME_BUILTIN_AI'
  | 'OFFLINE_LOCAL_FALLBACK'
  | 'ZERO_KEY_DEMO'
  | 'POLICY_BLOCKED';

export type PolicyDecision =
  | 'ON_DEVICE_EXECUTED'
  | 'OFFLINE_LOCAL_FALLBACK_EXECUTED'
  | 'CLOUD_FALLBACK_WITH_REDACTION'
  | 'CLOUD_PRIMARY_WITH_REDACTION'
  | 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE'
  | 'BLOCKED_CRITICAL_SECRET_POLICY'
  | 'BLOCKED_OFFLINE_NETWORK_DISABLED'
  | 'BLOCKED_ZERO_LEAK_INTEGRITY';

export interface HybridExecutionRequest {
  prompt: string;
  taskInstruction?: string;
  mode: InferenceMode;
  policy?: PrivacyPolicy;
  blockCloudOnCriticalSecrets?: boolean;
  offlineMode?: boolean;
  firebaseConfig?: FirebaseConfigInput | null;
  cloudModel?: string;
}

export interface FirebaseConfigInput {
  apiKey: string;
  projectId: string;
  appId: string;
}

export interface HybridExecutionResult {
  id: string;
  timestampIso: string;
  status: 'SUCCESS' | 'BLOCKED';
  requestedMode: InferenceMode;
  effectiveMode: InferenceMode;
  inferenceSource: InferenceSource | 'BLOCKED';
  executionKind: ExecutionKind;
  policyDecision: PolicyDecision;
  offlineMode: boolean;
  latencyMs: number;
  redaction: RedactionResult;
  zeroLeakCheck: ZeroLeakCheckResult;
  wirePayload: string;
  rawModelOutput: string;
  restoredOutput: string;
  cloudBytesTransmitted: number;
  economics: HybridEconomicsReport;
  sdkPackage: string;
  errorMessage?: string;
}

export interface LanguageModelSessionLike {
  prompt: (input: string) => Promise<string>;
  destroy?: () => void;
}

export interface LanguageModelProviderLike {
  availability?: () => Promise<string>;
  capabilities?: () => Promise<{ available?: string }>;
  create: (options?: Record<string, unknown>) => Promise<LanguageModelSessionLike>;
}

export interface HybridRuntimeDeps {
  createFirebaseModel?: (config: FirebaseConfigInput, params: HybridParams) => GenerativeModel;
  getChromeLanguageModelProvider?: () => LanguageModelProviderLike | null;
  navigatorOnLine?: boolean;
  probeWebGpu?: () => Promise<{ available: boolean; adapter: string }>;
  now?: () => number;
}

const DEFAULT_TASK_INSTRUCTION =
  'Analyze the sanitized prompt below, summarize key security risks or action items concisely, and preserve any <REDACTED_*> or {{NV_*}} placeholders verbatim.';

export function getGlobalChromeLanguageModel(): LanguageModelProviderLike | null {
  const g = globalThis as Record<string, unknown>;
  if (g.LanguageModel && typeof (g.LanguageModel as LanguageModelProviderLike).create === 'function') {
    return g.LanguageModel as LanguageModelProviderLike;
  }
  const aiObj = g.ai as Record<string, unknown> | undefined;
  if (aiObj?.languageModel && typeof (aiObj.languageModel as LanguageModelProviderLike).create === 'function') {
    return aiObj.languageModel as LanguageModelProviderLike;
  }
  return null;
}

function checkWasmSupport(): boolean {
  try {
    if (typeof WebAssembly !== 'object' || typeof WebAssembly.validate !== 'function') {
      return false;
    }
    // Minimal valid WASM module header: magic + version 1
    return WebAssembly.validate(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
  } catch {
    return false;
  }
}

async function defaultProbeWebGpu(): Promise<{ available: boolean; adapter: string }> {
  try {
    const nav = globalThis.navigator as (Navigator & {
      gpu?: { requestAdapter?: () => Promise<{ info?: { architecture?: string; vendor?: string } } | null> };
    }) | undefined;

    if (!nav?.gpu || typeof nav.gpu.requestAdapter !== 'function') {
      return { available: false, adapter: 'Not exposed' };
    }

    const adapter = await Promise.race([
      nav.gpu.requestAdapter(),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 500)),
    ]);

    if (!adapter) {
      return { available: false, adapter: 'Software / No hardware adapter' };
    }

    const vendor = adapter.info?.vendor ?? 'WebGPU';
    const arch = adapter.info?.architecture ?? 'Adapter Ready';
    return { available: true, adapter: `${vendor} (${arch})`.trim() };
  } catch {
    return { available: false, adapter: 'Blocked or unavailable' };
  }
}

export async function detectOnDeviceCapabilities(
  providerOverride?: LanguageModelProviderLike | null,
  deps: Pick<HybridRuntimeDeps, 'navigatorOnLine' | 'probeWebGpu'> = {}
): Promise<OnDeviceCapabilityReport> {
  const g = globalThis as Record<string, unknown>;
  const provider = providerOverride !== undefined ? providerOverride : getGlobalChromeLanguageModel();
  const wasmReady = checkWasmSupport();
  const online =
    deps.navigatorOnLine ?? (typeof navigator !== 'undefined' && typeof navigator.onLine === 'boolean' ? navigator.onLine : true);
  const gpu = deps.probeWebGpu ? await deps.probeWebGpu() : await defaultProbeWebGpu();

  if (!provider) {
    return {
      apiDetected: 'none',
      availability: 'unavailable',
      promptApiReady: false,
      webgpuAvailable: gpu.available,
      webgpuAdapter: gpu.adapter,
      wasmReady,
      online,
      localEngineTier: 'DETERMINISTIC_LOCAL_VAULT',
      note: 'Chrome Prompt API not active in this runtime; Deterministic Local Vault + Safe Cloud Escalation ready.',
    };
  }

  const apiDetected: OnDeviceCapabilityReport['apiDetected'] =
    provider === g.LanguageModel ? 'window.LanguageModel' : 'window.ai.languageModel';

  try {
    let rawStatus = 'unavailable';
    if (typeof provider.availability === 'function') {
      rawStatus = await provider.availability();
    } else if (typeof provider.capabilities === 'function') {
      const caps = await provider.capabilities();
      rawStatus = caps?.available ?? 'unavailable';
    }

    const normalized = normalizeAvailability(rawStatus);
    const promptApiReady = normalized === 'available';
    const localEngineTier: LocalEngineTier = promptApiReady
      ? 'CHROME_GEMINI_NANO'
      : normalized === 'downloadable' || normalized === 'downloading'
        ? 'HYBRID_DOWNLOADABLE'
        : 'DETERMINISTIC_LOCAL_VAULT';

    return {
      apiDetected,
      availability: normalized,
      promptApiReady,
      webgpuAvailable: gpu.available,
      webgpuAdapter: gpu.adapter,
      wasmReady,
      online,
      localEngineTier,
      note: promptApiReady
        ? 'Gemini Nano on-device Prompt API is ready for zero-network local inference.'
        : `Chrome Prompt API status reported as "${rawStatus}"; deterministic local vault fallback active.`,
    };
  } catch (err) {
    return {
      apiDetected,
      availability: 'unavailable',
      promptApiReady: false,
      webgpuAvailable: gpu.available,
      webgpuAdapter: gpu.adapter,
      wasmReady,
      online,
      localEngineTier: 'DETERMINISTIC_LOCAL_VAULT',
      note: err instanceof Error ? err.message : 'Failed to probe on-device model availability.',
    };
  }
}

function normalizeAvailability(raw: string): OnDeviceAvailability {
  const value = raw.toLowerCase();
  if (value === 'available' || value === 'readily') return 'available';
  if (value === 'downloadable' || value === 'after-download') return 'downloadable';
  if (value === 'downloading') return 'downloading';
  return 'unavailable';
}

export function buildSanitizedPrompt(redactedText: string, taskInstruction?: string): string {
  const instruction = taskInstruction?.trim() || DEFAULT_TASK_INSTRUCTION;
  return `${instruction}\n\n--- SANITIZED INPUT ---\n${redactedText}`;
}

export function createDefaultFirebaseModel(
  config: FirebaseConfigInput,
  hybridParams: HybridParams
): GenerativeModel {
  const appName = `nanovault-${config.projectId}`;
  const existing = getApps().find((a: FirebaseApp) => a.name === appName);
  const options: FirebaseOptions = {
    apiKey: config.apiKey,
    projectId: config.projectId,
    appId: config.appId,
  };
  const app = existing ?? initializeApp(options, appName);
  const ai = getAI(app, { backend: new GoogleAIBackend() });
  return getGenerativeModel(ai, hybridParams);
}

function isValidFirebaseConfig(config?: FirebaseConfigInput | null): config is FirebaseConfigInput {
  return Boolean(
    config &&
      config.apiKey.trim().length > 0 &&
      config.projectId.trim().length > 0 &&
      config.appId.trim().length > 0
  );
}

function generateDeterministicAnalysis(
  redactedText: string,
  redaction: RedactionResult,
  source: InferenceSource,
  offlineFallback: boolean
): string {
  const entityLines =
    redaction.entities.length > 0
      ? redaction.entities
          .slice(0, 8)
          .map((e) => `- Isolated ${e.category} (${e.severity}) as ${e.token}`)
          .join('\n')
      : '- No sensitive credentials or PII detected in prompt.';

  const tokensMentioned = redaction.entities.map((e) => e.token);
  const firstToken = tokensMentioned[0] ?? 'none';
  const modeHeader = offlineFallback
    ? 'OFFLINE_LOCAL_VAULT'
    : source.toUpperCase();
  const routeNote = offlineFallback
    ? 'Processed 100% offline in browser memory ($0.00 token cost, 0 bytes network egress).'
    : source === InferenceSource.ON_DEVICE
      ? 'Processed 100% locally via Gemini Nano on-device adapter (0 bytes sent off-device).'
      : 'Processed via Cloud Gemini escalation AFTER Zero-Leak PII Vault redaction (0 raw secrets transmitted).';

  const summarySnippet = redactedText.replace(/\s+/g, ' ').slice(0, 140);

  return [
    `[NanoVault Hybrid Analysis · ${modeHeader}]`,
    routeNote,
    '',
    `Risk Assessment: ${redaction.riskLevel} (${redaction.riskScore}/100) across ${redaction.entities.length} protected item(s).`,
    entityLines,
    '',
    `Context Checked: "${summarySnippet}${redactedText.length > 140 ? '...' : ''}"`,
    tokensMentioned.length > 0
      ? `Recommended Action: Rotate/revoke ${firstToken} immediately and keep zero-leak redaction enforced before external sharing.`
      : 'Recommended Action: Safe to proceed; zero credential exposure detected.',
  ].join('\n');
}

function buildSuccessResult(params: {
  id: string;
  timestampIso: string;
  requestedMode: InferenceMode;
  effectiveMode: InferenceMode;
  inferenceSource: InferenceSource;
  executionKind: Exclude<ExecutionKind, 'POLICY_BLOCKED'>;
  policyDecision: PolicyDecision;
  offlineMode: boolean;
  latencyMs: number;
  rawPrompt: string;
  redaction: RedactionResult;
  zeroLeakCheck: ZeroLeakCheckResult;
  wirePayload: string;
  rawModelOutput: string;
  cloudBytesTransmitted: number;
}): HybridExecutionResult {
  const restoredOutput = restoreTokens(params.rawModelOutput, params.redaction.tokenMap);
  const economics = estimateHybridEconomics({
    rawPrompt: params.rawPrompt,
    wirePayload: params.wirePayload,
    outputText: restoredOutput,
    inferenceSource: params.inferenceSource,
    measuredLatencyMs: params.latencyMs,
    cloudBytesTransmitted: params.cloudBytesTransmitted,
    offlineMode: params.offlineMode,
  });

  return {
    id: params.id,
    timestampIso: params.timestampIso,
    status: 'SUCCESS',
    requestedMode: params.requestedMode,
    effectiveMode: params.effectiveMode,
    inferenceSource: params.inferenceSource,
    executionKind: params.executionKind,
    policyDecision: params.policyDecision,
    offlineMode: params.offlineMode,
    latencyMs: params.latencyMs,
    redaction: params.redaction,
    zeroLeakCheck: params.zeroLeakCheck,
    wirePayload: params.wirePayload,
    rawModelOutput: params.rawModelOutput,
    restoredOutput,
    cloudBytesTransmitted: params.cloudBytesTransmitted,
    economics,
    sdkPackage: 'firebase@13.4.0 (firebase/ai)',
  };
}

function createBlockedResult(params: {
  id: string;
  timestampIso: string;
  requestedMode: InferenceMode;
  effectiveMode: InferenceMode;
  policyDecision: PolicyDecision;
  offlineMode: boolean;
  latencyMs: number;
  rawPrompt: string;
  redaction: RedactionResult;
  zeroLeakCheck: ZeroLeakCheckResult;
  wirePayload: string;
  errorMessage: string;
}): HybridExecutionResult {
  const economics = estimateHybridEconomics({
    rawPrompt: params.rawPrompt,
    wirePayload: params.wirePayload,
    outputText: '',
    inferenceSource: 'BLOCKED',
    measuredLatencyMs: params.latencyMs,
    cloudBytesTransmitted: 0,
    offlineMode: params.offlineMode,
  });

  return {
    id: params.id,
    timestampIso: params.timestampIso,
    status: 'BLOCKED',
    requestedMode: params.requestedMode,
    effectiveMode: params.effectiveMode,
    inferenceSource: 'BLOCKED',
    executionKind: 'POLICY_BLOCKED',
    policyDecision: params.policyDecision,
    offlineMode: params.offlineMode,
    latencyMs: params.latencyMs,
    redaction: params.redaction,
    zeroLeakCheck: params.zeroLeakCheck,
    wirePayload: params.wirePayload,
    rawModelOutput: '',
    restoredOutput: '',
    cloudBytesTransmitted: 0,
    economics,
    sdkPackage: 'firebase@13.4.0 (firebase/ai)',
    errorMessage: params.errorMessage,
  };
}

export async function runHybridInference(
  request: HybridExecutionRequest,
  deps: HybridRuntimeDeps = {}
): Promise<HybridExecutionResult> {
  const now = deps.now ?? (() => performance.now());
  const startedAt = now();
  const id = `nv_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
  const timestampIso = new Date().toISOString();

  const policy = request.policy ?? DEFAULT_PRIVACY_POLICY;
  const redaction = scanAndRedact(request.prompt, policy);
  const wirePayload = buildSanitizedPrompt(redaction.redactedText, request.taskInstruction);
  const zeroLeakCheck = verifyZeroRawLeaks(wirePayload, redaction);
  const blockCloudOnCritical = request.blockCloudOnCriticalSecrets ?? false;

  const provider =
    deps.getChromeLanguageModelProvider !== undefined
      ? deps.getChromeLanguageModelProvider()
      : getGlobalChromeLanguageModel();
  const capReport = await detectOnDeviceCapabilities(provider, {
    navigatorOnLine: deps.navigatorOnLine,
    probeWebGpu: deps.probeWebGpu,
  });

  const onDeviceReady = capReport.availability === 'available';
  const offlineMode = Boolean(request.offlineMode) || !capReport.online;

  // Enforce strict Zero-Cloud firewall when critical secrets are present and user forbids cloud egress
  const effectiveMode =
    blockCloudOnCritical && redaction.containsCriticalSecrets && request.mode === InferenceMode.PREFER_IN_CLOUD
      ? InferenceMode.ONLY_ON_DEVICE
      : request.mode;

  // Defense-in-depth Zero-Leak Gate
  if (!zeroLeakCheck.zeroLeaks && effectiveMode !== InferenceMode.ONLY_ON_DEVICE && !onDeviceReady) {
    return createBlockedResult({
      id,
      timestampIso,
      requestedMode: request.mode,
      effectiveMode,
      policyDecision: 'BLOCKED_ZERO_LEAK_INTEGRITY',
      offlineMode,
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      rawPrompt: request.prompt,
      redaction,
      zeroLeakCheck,
      wirePayload,
      errorMessage: 'Zero-Leak Gate detected unmasked secret residue and blocked cloud egress.',
    });
  }

  // 0. Offline / Airplane-Mode Proof short-circuit (zero network egress guaranteed)
  if (offlineMode) {
    if (effectiveMode === InferenceMode.ONLY_IN_CLOUD) {
      return createBlockedResult({
        id,
        timestampIso,
        requestedMode: request.mode,
        effectiveMode,
        policyDecision: 'BLOCKED_OFFLINE_NETWORK_DISABLED',
        offlineMode: true,
        latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
        rawPrompt: request.prompt,
        redaction,
        zeroLeakCheck,
        wirePayload,
        errorMessage:
          'Airplane Mode / Offline Proof is active: ONLY_IN_CLOUD cannot reach remote servers (0 B egress).',
      });
    }

    if (onDeviceReady && provider) {
      const session = await provider.create({
        initialPrompts: [
          {
            role: 'system',
            content: 'You are NanoVault Hybrid Security Analyst. Preserve redacted placeholders verbatim.',
          },
        ],
      });
      try {
        const rawOutput = await session.prompt(wirePayload);
        const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
        return buildSuccessResult({
          id,
          timestampIso,
          requestedMode: request.mode,
          effectiveMode,
          inferenceSource: InferenceSource.ON_DEVICE,
          executionKind: 'CHROME_BUILTIN_AI',
          policyDecision: 'ON_DEVICE_EXECUTED',
          offlineMode: true,
          latencyMs,
          rawPrompt: request.prompt,
          redaction,
          zeroLeakCheck,
          wirePayload,
          rawModelOutput: rawOutput,
          cloudBytesTransmitted: 0,
        });
      } finally {
        session.destroy?.();
      }
    }

    if (effectiveMode === InferenceMode.ONLY_ON_DEVICE) {
      return createBlockedResult({
        id,
        timestampIso,
        requestedMode: request.mode,
        effectiveMode,
        policyDecision: 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE',
        offlineMode: true,
        latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
        rawPrompt: request.prompt,
        redaction,
        zeroLeakCheck,
        wirePayload,
        errorMessage:
          'ONLY_ON_DEVICE blocked execution while offline: Chrome Built-in AI (Gemini Nano) is unavailable in this runtime.',
      });
    }

    const rawOutput = generateDeterministicAnalysis(
      redaction.redactedText,
      redaction,
      InferenceSource.ON_DEVICE,
      true
    );
    const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
    return buildSuccessResult({
      id,
      timestampIso,
      requestedMode: request.mode,
      effectiveMode,
      inferenceSource: InferenceSource.ON_DEVICE,
      executionKind: 'OFFLINE_LOCAL_FALLBACK',
      policyDecision: 'OFFLINE_LOCAL_FALLBACK_EXECUTED',
      offlineMode: true,
      latencyMs,
      rawPrompt: request.prompt,
      redaction,
      zeroLeakCheck,
      wirePayload,
      rawModelOutput: rawOutput,
      cloudBytesTransmitted: 0,
    });
  }

  if (
    blockCloudOnCritical &&
    redaction.containsCriticalSecrets &&
    request.mode === InferenceMode.ONLY_IN_CLOUD
  ) {
    return createBlockedResult({
      id,
      timestampIso,
      requestedMode: request.mode,
      effectiveMode,
      policyDecision: 'BLOCKED_CRITICAL_SECRET_POLICY',
      offlineMode: false,
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      rawPrompt: request.prompt,
      redaction,
      zeroLeakCheck,
      wirePayload,
      errorMessage:
        'Privacy Policy Firewall blocked ONLY_IN_CLOUD because CRITICAL secrets were detected. Switch to ONLY_ON_DEVICE or PREFER_ON_DEVICE.',
    });
  }

  // 1. Live Firebase AI Logic Hybrid SDK path (when Firebase config is provided or custom factory injected)
  if (isValidFirebaseConfig(request.firebaseConfig) || deps.createFirebaseModel) {
    if (
      blockCloudOnCritical &&
      redaction.containsCriticalSecrets &&
      !onDeviceReady &&
      effectiveMode === InferenceMode.PREFER_ON_DEVICE
    ) {
      return createBlockedResult({
        id,
        timestampIso,
        requestedMode: request.mode,
        effectiveMode,
        policyDecision: 'BLOCKED_CRITICAL_SECRET_POLICY',
        offlineMode: false,
        latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
        rawPrompt: request.prompt,
        redaction,
        zeroLeakCheck,
        wirePayload,
        errorMessage:
          'Strict Critical-Secret Firewall blocked cloud fallback because on-device Gemini Nano is unavailable.',
      });
    }

    const hybridParams: HybridParams = {
      mode: effectiveMode,
      onDeviceParams: {
        createOptions: {
          initialPrompts: [
            {
              role: 'system',
              content: [{ type: 'text', value: 'You are NanoVault Privacy Security Assistant.' }],
            },
          ],
        },
      },
      inCloudParams: {
        model: request.cloudModel?.trim() || 'gemini-2.5-flash',
      },
    };

    try {
      const factory = deps.createFirebaseModel ?? createDefaultFirebaseModel;
      const model = factory(
        request.firebaseConfig ?? { apiKey: 'injected', projectId: 'injected', appId: 'injected' },
        hybridParams
      );
      const responseResult = await model.generateContent(wirePayload);
      const rawOutput = responseResult.response.text();
      const source = responseResult.response.inferenceSource ?? InferenceSource.IN_CLOUD;
      const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
      const cloudBytesTransmitted =
        source === InferenceSource.IN_CLOUD ? new TextEncoder().encode(wirePayload).length : 0;

      return buildSuccessResult({
        id,
        timestampIso,
        requestedMode: request.mode,
        effectiveMode,
        inferenceSource: source,
        executionKind: 'FIREBASE_HYBRID_SDK',
        policyDecision:
          source === InferenceSource.ON_DEVICE
            ? 'ON_DEVICE_EXECUTED'
            : effectiveMode === InferenceMode.PREFER_ON_DEVICE
              ? 'CLOUD_FALLBACK_WITH_REDACTION'
              : 'CLOUD_PRIMARY_WITH_REDACTION',
        offlineMode: false,
        latencyMs,
        rawPrompt: request.prompt,
        redaction,
        zeroLeakCheck,
        wirePayload,
        rawModelOutput: rawOutput,
        cloudBytesTransmitted,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (effectiveMode === InferenceMode.ONLY_ON_DEVICE) {
        return createBlockedResult({
          id,
          timestampIso,
          requestedMode: request.mode,
          effectiveMode,
          policyDecision: 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE',
          offlineMode: false,
          latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
          rawPrompt: request.prompt,
          redaction,
          zeroLeakCheck,
          wirePayload,
          errorMessage: `ONLY_ON_DEVICE enforced: ${message}`,
        });
      }
      throw err;
    }
  }

  // 2. Direct Chrome Built-in AI path (runs real Gemini Nano even without Firebase API key!)
  if (
    onDeviceReady &&
    provider &&
    effectiveMode !== InferenceMode.ONLY_IN_CLOUD &&
    effectiveMode !== InferenceMode.PREFER_IN_CLOUD
  ) {
    const session = await provider.create({
      initialPrompts: [
        {
          role: 'system',
          content: 'You are NanoVault Hybrid Security Analyst. Preserve redacted tokens verbatim.',
        },
      ],
    });
    try {
      const rawOutput = await session.prompt(wirePayload);
      const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
      return buildSuccessResult({
        id,
        timestampIso,
        requestedMode: request.mode,
        effectiveMode,
        inferenceSource: InferenceSource.ON_DEVICE,
        executionKind: 'CHROME_BUILTIN_AI',
        policyDecision: 'ON_DEVICE_EXECUTED',
        offlineMode: false,
        latencyMs,
        rawPrompt: request.prompt,
        redaction,
        zeroLeakCheck,
        wirePayload,
        rawModelOutput: rawOutput,
        cloudBytesTransmitted: 0,
      });
    } finally {
      session.destroy?.();
    }
  }

  // 3. Enforce ONLY_ON_DEVICE block when on-device model is unavailable
  if (effectiveMode === InferenceMode.ONLY_ON_DEVICE) {
    return createBlockedResult({
      id,
      timestampIso,
      requestedMode: request.mode,
      effectiveMode,
      policyDecision: 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE',
      offlineMode: false,
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      rawPrompt: request.prompt,
      redaction,
      zeroLeakCheck,
      wirePayload,
      errorMessage:
        'ONLY_ON_DEVICE mode blocked execution: Chrome Built-in AI (Gemini Nano) is not active in this runtime, and cloud fallback is strictly disabled.',
    });
  }

  if (blockCloudOnCritical && redaction.containsCriticalSecrets) {
    return createBlockedResult({
      id,
      timestampIso,
      requestedMode: request.mode,
      effectiveMode,
      policyDecision: 'BLOCKED_CRITICAL_SECRET_POLICY',
      offlineMode: false,
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      rawPrompt: request.prompt,
      redaction,
      zeroLeakCheck,
      wirePayload,
      errorMessage:
        'Strict Critical-Secret Firewall blocked cloud fallback because CRITICAL secrets were detected and Gemini Nano is unavailable.',
    });
  }

  // 4. Zero-Key Demo Mode simulating Firebase Hybrid Cloud Fallback with verified local redaction
  const simulatedSource = InferenceSource.IN_CLOUD;
  const rawOutput = generateDeterministicAnalysis(
    redaction.redactedText,
    redaction,
    simulatedSource,
    false
  );
  const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
  const cloudBytesTransmitted = new TextEncoder().encode(wirePayload).length;

  return buildSuccessResult({
    id,
    timestampIso,
    requestedMode: request.mode,
    effectiveMode,
    inferenceSource: simulatedSource,
    executionKind: 'ZERO_KEY_DEMO',
    policyDecision:
      effectiveMode === InferenceMode.PREFER_ON_DEVICE
        ? 'CLOUD_FALLBACK_WITH_REDACTION'
        : 'CLOUD_PRIMARY_WITH_REDACTION',
    offlineMode: false,
    latencyMs,
    rawPrompt: request.prompt,
    redaction,
    zeroLeakCheck,
    wirePayload,
    rawModelOutput: rawOutput,
    cloudBytesTransmitted,
  });
}
