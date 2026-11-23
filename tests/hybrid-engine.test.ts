import { describe, it, expect } from 'vitest';
import {
  InferenceMode,
  InferenceSource,
  detectOnDeviceCapabilities,
  runHybridInference,
  type LanguageModelProviderLike,
} from '../src/hybrid-engine.ts';

describe('NanoVault Hybrid AI Router & Policy Engine', () => {
  it('detects Prompt API availability, downloadable states, and hardware readiness cleanly', async () => {
    const missing = await detectOnDeviceCapabilities(null, {
      navigatorOnLine: true,
      probeWebGpu: async () => ({ available: false, adapter: 'Not exposed' }),
    });
    expect(missing.apiDetected).toBe('none');
    expect(missing.availability).toBe('unavailable');
    expect(missing.localEngineTier).toBe('DETERMINISTIC_LOCAL_VAULT');

    const downloadable = await detectOnDeviceCapabilities(
      { availability: async () => 'after-download', create: async () => ({ prompt: async () => '' }) },
      { navigatorOnLine: true, probeWebGpu: async () => ({ available: true, adapter: 'MockGPU' }) }
    );
    expect(downloadable.availability).toBe('downloadable');
    expect(downloadable.localEngineTier).toBe('HYBRID_DOWNLOADABLE');
    expect(downloadable.webgpuAvailable).toBe(true);

    const ready = await detectOnDeviceCapabilities(
      { capabilities: async () => ({ available: 'readily' }), create: async () => ({ prompt: async () => '' }) },
      { navigatorOnLine: true, probeWebGpu: async () => ({ available: true, adapter: 'MockGPU' }) }
    );
    expect(ready.availability).toBe('available');
    expect(ready.promptApiReady).toBe(true);
    expect(ready.localEngineTier).toBe('CHROME_GEMINI_NANO');
  });

  it('blocks ONLY_ON_DEVICE cloud fallback when Chrome Built-in AI is unavailable', async () => {
    const result = await runHybridInference(
      {
        prompt: 'Rotate key ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa for bob@company.org',
        mode: InferenceMode.ONLY_ON_DEVICE,
      },
      {
        getChromeLanguageModelProvider: () => null,
        probeWebGpu: async () => ({ available: false, adapter: 'None' }),
      }
    );

    expect(result.status).toBe('BLOCKED');
    expect(result.inferenceSource).toBe('BLOCKED');
    expect(result.policyDecision).toBe('BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE');
    expect(result.cloudBytesTransmitted).toBe(0);
    expect(result.economics.actualCostUsd).toBe(0);
    expect(result.redaction.entities.length).toBe(2);
  });

  it('executes PREFER_ON_DEVICE locally with 0 cloud bytes and $0.00 cost when Gemini Nano is available', async () => {
    const mockProvider: LanguageModelProviderLike = {
      availability: async () => 'available',
      create: async () => ({
        prompt: async (sanitizedInput: string) => {
          expect(sanitizedInput.includes('bob@company.org')).toBe(false);
          const tokenMatch = sanitizedInput.match(/<REDACTED_EMAIL_\d+>/);
          expect(tokenMatch).not.toBeNull();
          return `Local Nano handled ticket for ${tokenMatch![0]} safely.`;
        },
        destroy: () => {},
      }),
    };

    const result = await runHybridInference(
      {
        prompt: 'Customer email bob@company.org requested password reset.',
        mode: InferenceMode.PREFER_ON_DEVICE,
      },
      {
        getChromeLanguageModelProvider: () => mockProvider,
        probeWebGpu: async () => ({ available: true, adapter: 'WebGPU Ready' }),
      }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.inferenceSource).toBe(InferenceSource.ON_DEVICE);
    expect(result.executionKind).toBe('CHROME_BUILTIN_AI');
    expect(result.policyDecision).toBe('ON_DEVICE_EXECUTED');
    expect(result.cloudBytesTransmitted).toBe(0);
    expect(result.economics.actualCostUsd).toBe(0);
    expect(result.zeroLeakCheck.zeroLeaks).toBe(true);
    expect(result.rawModelOutput.includes('bob@company.org')).toBe(false);
    expect(result.restoredOutput.includes('bob@company.org')).toBe(true);
  });

  it('falls back to Zero-Key Cloud Demo with Zero-Leak verification when permitted', async () => {
    const syntheticStripeKey = ['sk', 'live', '51N9xYzAbCdEfGhIjKlMnOpQrStUvWx'].join('_');
    const result = await runHybridInference(
      {
        prompt: `Check Stripe key ${syntheticStripeKey} and email dev@fin.io`,
        mode: InferenceMode.PREFER_ON_DEVICE,
        blockCloudOnCriticalSecrets: false,
      },
      {
        getChromeLanguageModelProvider: () => null,
        navigatorOnLine: true,
        probeWebGpu: async () => ({ available: false, adapter: 'None' }),
      }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.inferenceSource).toBe(InferenceSource.IN_CLOUD);
    expect(result.executionKind).toBe('ZERO_KEY_DEMO');
    expect(result.policyDecision).toBe('CLOUD_FALLBACK_WITH_REDACTION');
    expect(result.cloudBytesTransmitted).toBeGreaterThan(0);
    expect(result.zeroLeakCheck.zeroLeaks).toBe(true);
    expect(result.wirePayload.includes(syntheticStripeKey)).toBe(false);
    expect(result.wirePayload.includes('dev@fin.io')).toBe(false);
    expect(result.restoredOutput.includes(syntheticStripeKey)).toBe(true);
  });

  it('enforces Strict Critical-Secret Firewall across PREFER_ON_DEVICE, PREFER_IN_CLOUD, and ONLY_IN_CLOUD', async () => {
    const criticalPrompt = 'Leaky Firebase key AIzaSyD-9xYz1234567890AbCdEfGhIjKlMnOpQrS';

    const blockFallback = await runHybridInference(
      {
        prompt: criticalPrompt,
        mode: InferenceMode.PREFER_ON_DEVICE,
        blockCloudOnCriticalSecrets: true,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: true }
    );
    expect(blockFallback.status).toBe('BLOCKED');
    expect(blockFallback.policyDecision).toBe('BLOCKED_CRITICAL_SECRET_POLICY');
    expect(blockFallback.cloudBytesTransmitted).toBe(0);

    const blockOnlyCloud = await runHybridInference(
      {
        prompt: criticalPrompt,
        mode: InferenceMode.ONLY_IN_CLOUD,
        blockCloudOnCriticalSecrets: true,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: true }
    );
    expect(blockOnlyCloud.status).toBe('BLOCKED');
    expect(blockOnlyCloud.policyDecision).toBe('BLOCKED_CRITICAL_SECRET_POLICY');

    const downgradePreferCloud = await runHybridInference(
      {
        prompt: criticalPrompt,
        mode: InferenceMode.PREFER_IN_CLOUD,
        blockCloudOnCriticalSecrets: true,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: true }
    );
    expect(downgradePreferCloud.status).toBe('BLOCKED');
    expect(downgradePreferCloud.effectiveMode).toBe(InferenceMode.ONLY_ON_DEVICE);
  });

  it('routes through Firebase Hybrid SDK adapter with HybridParams and restores local tokens', async () => {
    let capturedMode: string | undefined;
    let capturedCloudModel: string | undefined;
    let capturedWirePrompt = '';

    const result = await runHybridInference(
      {
        prompt:
          'Audit JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
        mode: InferenceMode.PREFER_ON_DEVICE,
        blockCloudOnCriticalSecrets: false,
        firebaseConfig: {
          apiKey: 'demo-key',
          projectId: 'nanovault-demo',
          appId: '1:123:web:abc',
        },
        cloudModel: 'gemini-2.5-flash',
      },
      {
        getChromeLanguageModelProvider: () => null,
        navigatorOnLine: true,
        createFirebaseModel: (_cfg, params) => {
          capturedMode = params.mode;
          capturedCloudModel = params.inCloudParams?.model;
          return {
            generateContent: async (prompt: string) => {
              capturedWirePrompt = prompt;
              const jwtToken = prompt.match(/<REDACTED_JWT_\d+>/)?.[0] ?? '';
              return {
                response: {
                  text: () => `Revoke ${jwtToken} and rotate signing secret.`,
                  inferenceSource: InferenceSource.IN_CLOUD,
                },
              } as never;
            },
          } as never;
        },
      }
    );

    expect(capturedMode).toBe(InferenceMode.PREFER_ON_DEVICE);
    expect(capturedCloudModel).toBe('gemini-2.5-flash');
    expect(capturedWirePrompt.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')).toBe(false);
    expect(result.status).toBe('SUCCESS');
    expect(result.executionKind).toBe('FIREBASE_HYBRID_SDK');
    expect(result.restoredOutput.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')).toBe(true);
  });

  it('runs Offline / Airplane-Mode Proof at $0.00 cost and 0 B cloud egress for PREFER_ON_DEVICE fallback', async () => {
    const result = await runHybridInference(
      {
        prompt: 'Offline triage for SSN 412-88-9041 and lead@acme.io',
        mode: InferenceMode.PREFER_ON_DEVICE,
        offlineMode: true,
      },
      { getChromeLanguageModelProvider: () => null }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.offlineMode).toBe(true);
    expect(result.inferenceSource).toBe(InferenceSource.ON_DEVICE);
    expect(result.executionKind).toBe('OFFLINE_LOCAL_FALLBACK');
    expect(result.policyDecision).toBe('OFFLINE_LOCAL_FALLBACK_EXECUTED');
    expect(result.cloudBytesTransmitted).toBe(0);
    expect(result.economics.actualCostUsd).toBe(0);
    expect(result.restoredOutput).toContain('412-88-9041');
  });

  it('uses Chrome Gemini Nano even in Offline / Airplane Mode when Prompt API is available', async () => {
    const mockProvider: LanguageModelProviderLike = {
      availability: async () => 'available',
      create: async () => ({
        prompt: async () => 'Offline Nano executed <REDACTED_SSN_1>.',
        destroy: () => {},
      }),
    };

    const result = await runHybridInference(
      {
        prompt: 'Offline SSN 412-88-9041 check',
        mode: InferenceMode.PREFER_ON_DEVICE,
        offlineMode: true,
      },
      { getChromeLanguageModelProvider: () => mockProvider }
    );

    expect(result.status).toBe('SUCCESS');
    expect(result.executionKind).toBe('CHROME_BUILTIN_AI');
    expect(result.cloudBytesTransmitted).toBe(0);
    expect(result.economics.actualCostUsd).toBe(0);
    expect(result.restoredOutput).toContain('412-88-9041');
  });

  it('blocks ONLY_IN_CLOUD and ONLY_ON_DEVICE appropriately while offline or navigatorOnLine=false', async () => {
    const blockedCloud = await runHybridInference(
      {
        prompt: 'Check status',
        mode: InferenceMode.ONLY_IN_CLOUD,
        offlineMode: true,
      },
      { getChromeLanguageModelProvider: () => null }
    );
    expect(blockedCloud.status).toBe('BLOCKED');
    expect(blockedCloud.policyDecision).toBe('BLOCKED_OFFLINE_NETWORK_DISABLED');
    expect(blockedCloud.cloudBytesTransmitted).toBe(0);

    const autoOffline = await runHybridInference(
      {
        prompt: 'Check SSN 412-88-9041',
        mode: InferenceMode.PREFER_ON_DEVICE,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: false }
    );
    expect(autoOffline.offlineMode).toBe(true);
    expect(autoOffline.executionKind).toBe('OFFLINE_LOCAL_FALLBACK');
    expect(autoOffline.cloudBytesTransmitted).toBe(0);

    const blockedStrictNano = await runHybridInference(
      {
        prompt: 'Check SSN 412-88-9041',
        mode: InferenceMode.ONLY_ON_DEVICE,
        offlineMode: true,
      },
      { getChromeLanguageModelProvider: () => null }
    );
    expect(blockedStrictNano.status).toBe('BLOCKED');
    expect(blockedStrictNano.policyDecision).toBe('BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE');
  });

  it('blocks ONLY_ON_DEVICE gracefully when Firebase SDK throws on unavailable on-device model', async () => {
    const result = await runHybridInference(
      {
        prompt: 'Check SSN 412-88-9041',
        mode: InferenceMode.ONLY_ON_DEVICE,
        firebaseConfig: { apiKey: 'k', projectId: 'p', appId: 'a' },
      },
      {
        getChromeLanguageModelProvider: () => null,
        navigatorOnLine: true,
        createFirebaseModel: () =>
          ({
            generateContent: async () => {
              throw new Error('On-device Prompt API not downloaded');
            },
          }) as never,
      }
    );

    expect(result.status).toBe('BLOCKED');
    expect(result.policyDecision).toBe('BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE');
    expect(result.errorMessage).toContain('ONLY_ON_DEVICE enforced');
  });

  it('detects and executes via legacy window.ai.languageModel namespace when LanguageModel is absent', async () => {
    const g = globalThis as Record<string, unknown>;
    const prevLm = g.LanguageModel;
    const prevAi = g.ai;
    const legacyProvider: LanguageModelProviderLike = {
      capabilities: async () => ({ available: 'readily' }),
      create: async () => ({
        prompt: async (input: string) => `Legacy Nano checked ${input.match(/<REDACTED_EMAIL_\d+>/)?.[0]}`,
      }),
    };
    g.LanguageModel = undefined;
    g.ai = { languageModel: legacyProvider };

    try {
      const cap = await detectOnDeviceCapabilities(undefined, {
        navigatorOnLine: true,
        probeWebGpu: async () => ({ available: false, adapter: 'None' }),
      });
      expect(cap.apiDetected).toBe('window.ai.languageModel');
      expect(cap.availability).toBe('available');

      const res = await runHybridInference(
        { prompt: 'Contact ops@acme.io', mode: InferenceMode.PREFER_ON_DEVICE },
        { navigatorOnLine: true, probeWebGpu: async () => ({ available: false, adapter: 'None' }) }
      );
      expect(res.executionKind).toBe('CHROME_BUILTIN_AI');
      expect(res.restoredOutput).toContain('ops@acme.io');
    } finally {
      g.LanguageModel = prevLm;
      g.ai = prevAi;
    }
  });

  it('routes PREFER_IN_CLOUD and ONLY_IN_CLOUD online with redaction when firewall is off', async () => {
    const preferCloud = await runHybridInference(
      {
        prompt: 'Check SSN 412-88-9041 and dev@fin.io',
        mode: InferenceMode.PREFER_IN_CLOUD,
        blockCloudOnCriticalSecrets: false,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: true }
    );
    expect(preferCloud.status).toBe('SUCCESS');
    expect(preferCloud.inferenceSource).toBe(InferenceSource.IN_CLOUD);
    expect(preferCloud.policyDecision).toBe('CLOUD_PRIMARY_WITH_REDACTION');
    expect(preferCloud.zeroLeakCheck.zeroLeaks).toBe(true);

    const onlyCloud = await runHybridInference(
      {
        prompt: 'Check SSN 412-88-9041',
        mode: InferenceMode.ONLY_IN_CLOUD,
        blockCloudOnCriticalSecrets: false,
      },
      { getChromeLanguageModelProvider: () => null, navigatorOnLine: true }
    );
    expect(onlyCloud.status).toBe('SUCCESS');
    expect(onlyCloud.policyDecision).toBe('CLOUD_PRIMARY_WITH_REDACTION');
  });

  it('propagates non-ONLY_ON_DEVICE Firebase SDK errors cleanly', async () => {
    await expect(
      runHybridInference(
        {
          prompt: 'Check status',
          mode: InferenceMode.PREFER_ON_DEVICE,
          firebaseConfig: { apiKey: 'k', projectId: 'p', appId: 'a' },
        },
        {
          getChromeLanguageModelProvider: () => null,
          navigatorOnLine: true,
          createFirebaseModel: () =>
            ({
              generateContent: async () => {
                throw new Error('Quota exceeded');
              },
            }) as never,
        }
      )
    ).rejects.toThrow('Quota exceeded');
  });
});
