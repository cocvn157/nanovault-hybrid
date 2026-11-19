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
  type PrivacyPolicy,
  type RedactionResult,
} from './pii-guard.ts';

export { InferenceMode, InferenceSource };

export type OnDeviceAvailability = 'available' | 'downloadable' | 'downloading' | 'unavailable';

export interface OnDeviceCapabilityReport {
  apiDetected: 'window.LanguageModel' | 'window.ai.languageModel' | 'none';
  availability: OnDeviceAvailability;
  note: string;
}

export type ExecutionKind =
  | 'FIREBASE_HYBRID_SDK'
  | 'CHROME_BUILTIN_AI'
  | 'ZERO_KEY_DEMO'
  | 'POLICY_BLOCKED';

export type PolicyDecision =
  | 'ON_DEVICE_EXECUTED'
  | 'CLOUD_FALLBACK_WITH_REDACTION'
  | 'CLOUD_PRIMARY_WITH_REDACTION'
  | 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE'
  | 'BLOCKED_CRITICAL_SECRET_POLICY';

export interface HybridExecutionRequest {
  prompt: string;
  taskInstruction?: string;
  mode: InferenceMode;
  policy?: PrivacyPolicy;
  blockCloudOnCriticalSecrets?: boolean;
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
  latencyMs: number;
  redaction: RedactionResult;
  wirePayload: string;
  rawModelOutput: string;
  restoredOutput: string;
  cloudBytesTransmitted: number;
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
  now?: () => number;
}

const DEFAULT_TASK_INSTRUCTION =
  'Analyze the sanitized prompt below, summarize key risks or action items concisely, and preserve any {{NV_*}} vault placeholders verbatim.';

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

export async function detectOnDeviceCapabilities(
  providerOverride?: LanguageModelProviderLike | null
): Promise<OnDeviceCapabilityReport> {
  const g = globalThis as Record<string, unknown>;
  const provider = providerOverride !== undefined ? providerOverride : getGlobalChromeLanguageModel();

  if (!provider) {
    return {
      apiDetected: 'none',
      availability: 'unavailable',
      note: 'Chrome Built-in AI (Gemini Nano Prompt API) not exposed in this browser runtime; Firebase Hybrid SDK will route via cloud fallback when permitted.',
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
    return {
      apiDetected,
      availability: normalized,
      note:
        normalized === 'available'
          ? 'Gemini Nano on-device model is ready for zero-network local inference.'
          : `Gemini Nano status reported as "${rawStatus}".`,
    };
  } catch (err) {
    return {
      apiDetected,
      availability: 'unavailable',
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

function generateDeterministicDemoAnalysis(
  redactedText: string,
  redaction: RedactionResult,
  source: InferenceSource
): string {
  const entityLines =
    redaction.entities.length > 0
      ? redaction.entities
          .slice(0, 6)
          .map((e) => `- Isolated ${e.category} (${e.severity}) as ${e.token}`)
          .join('\n')
      : '- No sensitive credentials or PII detected in prompt.';

  const tokensMentioned = redaction.entities.map((e) => e.token);
  const firstToken = tokensMentioned[0] ?? 'none';
  const routeNote =
    source === InferenceSource.ON_DEVICE
      ? 'Processed 100% locally via Gemini Nano on-device adapter (0 bytes sent off-device).'
      : 'Processed via Cloud Gemini fallback AFTER local PII Vault sanitization (0 raw secrets transmitted).';

  const summarySnippet = redactedText.replace(/\s+/g, ' ').slice(0, 140);

  return [
    `[NanoVault Hybrid Analysis · ${source.toUpperCase()}]`,
    routeNote,
    '',
    `Risk Assessment: ${redaction.riskLevel} (${redaction.riskScore}/100) across ${redaction.entities.length} protected item(s).`,
    entityLines,
    '',
    `Context Checked: "${summarySnippet}${redactedText.length > 140 ? '...' : ''}"`,
    tokensMentioned.length > 0
      ? `Recommended Action: Rotate/revoke ${firstToken} immediately and keep vault redaction active before external sharing.`
      : 'Recommended Action: Safe to proceed; zero credential exposure detected.',
  ].join('\n');
}

function createBlockedResult(params: {
  id: string;
  timestampIso: string;
  requestedMode: InferenceMode;
  effectiveMode: InferenceMode;
  policyDecision: PolicyDecision;
  latencyMs: number;
  redaction: RedactionResult;
  wirePayload: string;
  errorMessage: string;
}): HybridExecutionResult {
  return {
    id: params.id,
    timestampIso: params.timestampIso,
    status: 'BLOCKED',
    requestedMode: params.requestedMode,
    effectiveMode: params.effectiveMode,
    inferenceSource: 'BLOCKED',
    executionKind: 'POLICY_BLOCKED',
    policyDecision: params.policyDecision,
    latencyMs: params.latencyMs,
    redaction: params.redaction,
    wirePayload: params.wirePayload,
    rawModelOutput: '',
    restoredOutput: '',
    cloudBytesTransmitted: 0,
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
  const blockCloudOnCritical = request.blockCloudOnCriticalSecrets ?? false;

  const provider =
    deps.getChromeLanguageModelProvider !== undefined
      ? deps.getChromeLanguageModelProvider()
      : getGlobalChromeLanguageModel();
  const capReport = await detectOnDeviceCapabilities(provider);
  const onDeviceReady = capReport.availability === 'available';

  // Enforce strict Zero-Cloud firewall when critical secrets are present and user forbids cloud egress
  const effectiveMode =
    blockCloudOnCritical && redaction.containsCriticalSecrets && request.mode === InferenceMode.PREFER_IN_CLOUD
      ? InferenceMode.ONLY_ON_DEVICE
      : request.mode;

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
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      redaction,
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
        latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
        redaction,
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

      return {
        id,
        timestampIso,
        status: 'SUCCESS',
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
        latencyMs,
        redaction,
        wirePayload,
        rawModelOutput: rawOutput,
        restoredOutput: restoreTokens(rawOutput, redaction.tokenMap),
        cloudBytesTransmitted: source === InferenceSource.IN_CLOUD ? new TextEncoder().encode(wirePayload).length : 0,
        sdkPackage: 'firebase@13.4.0 (firebase/ai)',
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (effectiveMode === InferenceMode.ONLY_ON_DEVICE) {
        return createBlockedResult({
          id,
          timestampIso,
          requestedMode: request.mode,
          effectiveMode,
          policyDecision: 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE',
          latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
          redaction,
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
          content: 'You are NanoVault Hybrid Security Analyst. Preserve {{NV_*}} tokens verbatim.',
        },
      ],
    });
    try {
      const rawOutput = await session.prompt(wirePayload);
      const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));
      return {
        id,
        timestampIso,
        status: 'SUCCESS',
        requestedMode: request.mode,
        effectiveMode,
        inferenceSource: InferenceSource.ON_DEVICE,
        executionKind: 'CHROME_BUILTIN_AI',
        policyDecision: 'ON_DEVICE_EXECUTED',
        latencyMs,
        redaction,
        wirePayload,
        rawModelOutput: rawOutput,
        restoredOutput: restoreTokens(rawOutput, redaction.tokenMap),
        cloudBytesTransmitted: 0,
        sdkPackage: 'firebase@13.4.0 (firebase/ai)',
      };
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
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      redaction,
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
      latencyMs: Math.max(0.1, Number((now() - startedAt).toFixed(2))),
      redaction,
      wirePayload,
      errorMessage:
        'Strict Critical-Secret Firewall blocked cloud fallback because CRITICAL secrets were detected and Gemini Nano is unavailable.',
    });
  }

  // 4. Zero-Key Demo Mode simulating Firebase Hybrid Cloud Fallback with verified local redaction
  const simulatedSource = InferenceSource.IN_CLOUD;
  const rawOutput = generateDeterministicDemoAnalysis(redaction.redactedText, redaction, simulatedSource);
  const latencyMs = Math.max(0.1, Number((now() - startedAt).toFixed(2)));

  return {
    id,
    timestampIso,
    status: 'SUCCESS',
    requestedMode: request.mode,
    effectiveMode,
    inferenceSource: simulatedSource,
    executionKind: 'ZERO_KEY_DEMO',
    policyDecision:
      effectiveMode === InferenceMode.PREFER_ON_DEVICE
        ? 'CLOUD_FALLBACK_WITH_REDACTION'
        : 'CLOUD_PRIMARY_WITH_REDACTION',
    latencyMs,
    redaction,
    wirePayload,
    rawModelOutput: rawOutput,
    restoredOutput: restoreTokens(rawOutput, redaction.tokenMap),
    cloudBytesTransmitted: new TextEncoder().encode(wirePayload).length,
    sdkPackage: 'firebase@13.4.0 (firebase/ai)',
  };
}
