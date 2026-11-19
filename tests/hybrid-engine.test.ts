import test from 'node:test';
import assert from 'node:assert/strict';
import { scanAndRedact, restoreTokens } from '../src/pii-guard.ts';
import {
  InferenceMode,
  InferenceSource,
  detectOnDeviceCapabilities,
  runHybridInference,
  type LanguageModelProviderLike,
} from '../src/hybrid-engine.ts';

test('PII Guard redacts secrets, JWTs, private keys, IBAN, Visa Luhn, and emails with lossless local restoration', () => {
  const sampleSecret = [
    'Incident by alice.ops@example.com from 10.24.8.15.',
    'AWS=AKIAIOSFODNN7EXAMPLE',
    'GH=ghp_1234567890abcdef1234567890abcdef1234',
    'DB=postgres://admin:S3cretPass!@db.internal.prod:5432/vault',
    'JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzQ0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
    'IBAN=DE89370400440532013000',
    'CARD=4532 0151 1283 0366',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');

  const res = scanAndRedact(sampleSecret);

  assert.equal(res.containsCriticalSecrets, true);
  assert.equal(res.riskLevel, 'CRITICAL');
  assert.ok(res.entities.length >= 8, `Expected >= 8 entities, got ${res.entities.length}`);

  // Verify raw secrets never appear in redactedText
  assert.equal(res.redactedText.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(res.redactedText.includes('ghp_1234567890abcdef1234567890abcdef1234'), false);
  assert.equal(res.redactedText.includes('S3cretPass!'), false);
  assert.equal(res.redactedText.includes('alice.ops@example.com'), false);
  assert.equal(res.redactedText.includes('DE89370400440532013000'), false);
  assert.equal(res.redactedText.includes('4532 0151 1283 0366'), false);
  assert.equal(res.redactedText.includes('MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M'), false);

  // Verify reversible local restoration
  const restored = restoreTokens(res.redactedText, res.tokenMap);
  assert.equal(restored, sampleSecret);
});

test('ONLY_ON_DEVICE blocks cloud execution when Chrome Built-in AI is unavailable', async () => {
  const result = await runHybridInference(
    {
      prompt: 'Rotate key ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa for bob@company.org',
      mode: InferenceMode.ONLY_ON_DEVICE,
    },
    {
      getChromeLanguageModelProvider: () => null,
    }
  );

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.inferenceSource, 'BLOCKED');
  assert.equal(result.policyDecision, 'BLOCKED_ONLY_ON_DEVICE_UNAVAILABLE');
  assert.equal(result.cloudBytesTransmitted, 0);
  assert.equal(result.redaction.entities.length, 2);
});

test('PREFER_ON_DEVICE executes ON_DEVICE with 0 cloud bytes when Gemini Nano LanguageModel is available', async () => {
  const mockProvider: LanguageModelProviderLike = {
    availability: async () => 'available',
    create: async () => ({
      prompt: async (sanitizedInput: string) => {
        assert.equal(sanitizedInput.includes('bob@company.org'), false);
        const tokenMatch = sanitizedInput.match(/\{\{NV_EMAIL_\d+\}\}/);
        assert.ok(tokenMatch, 'Expected tokenized email placeholder in sanitized prompt');
        return `Local Nano handled ticket for ${tokenMatch[0]} safely.`;
      },
      destroy: () => {},
    }),
  };

  const caps = await detectOnDeviceCapabilities(mockProvider);
  assert.equal(caps.availability, 'available');

  const result = await runHybridInference(
    {
      prompt: 'Customer email bob@company.org requested password reset.',
      mode: InferenceMode.PREFER_ON_DEVICE,
    },
    {
      getChromeLanguageModelProvider: () => mockProvider,
    }
  );

  assert.equal(result.status, 'SUCCESS');
  assert.equal(result.inferenceSource, InferenceSource.ON_DEVICE);
  assert.equal(result.executionKind, 'CHROME_BUILTIN_AI');
  assert.equal(result.policyDecision, 'ON_DEVICE_EXECUTED');
  assert.equal(result.cloudBytesTransmitted, 0);
  assert.equal(result.rawModelOutput.includes('bob@company.org'), false);
  assert.equal(result.restoredOutput.includes('bob@company.org'), true);
});

test('PREFER_ON_DEVICE falls back to Zero-Key Cloud Demo with full secret redaction when permitted', async () => {
  const syntheticStripeKey = ['sk', 'live', '51N9xYzAbCdEfGhIjKlMnOpQrStUvWx'].join('_');
  const result = await runHybridInference(
    {
      prompt: `Check Stripe key ${syntheticStripeKey} and email dev@fin.io`,
      mode: InferenceMode.PREFER_ON_DEVICE,
      blockCloudOnCriticalSecrets: false,
    },
    {
      getChromeLanguageModelProvider: () => null,
    }
  );

  assert.equal(result.status, 'SUCCESS');
  assert.equal(result.inferenceSource, InferenceSource.IN_CLOUD);
  assert.equal(result.executionKind, 'ZERO_KEY_DEMO');
  assert.equal(result.policyDecision, 'CLOUD_FALLBACK_WITH_REDACTION');
  assert.ok(result.cloudBytesTransmitted > 0);
  assert.ok(result.latencyMs > 0);
  assert.equal(result.sdkPackage, 'firebase@13.4.0 (firebase/ai)');
  assert.equal(result.wirePayload.includes(syntheticStripeKey), false);
  assert.equal(result.wirePayload.includes('dev@fin.io'), false);
  assert.equal(result.restoredOutput.includes(syntheticStripeKey), true);
});

test('Strict Critical-Secret Firewall blocks cloud egress when critical secrets are present', async () => {
  const result = await runHybridInference(
    {
      prompt: 'Leaky Firebase key AIzaSyD-9xYz1234567890AbCdEfGhIjKlMnOpQrS',
      mode: InferenceMode.PREFER_ON_DEVICE,
      blockCloudOnCriticalSecrets: true,
    },
    {
      getChromeLanguageModelProvider: () => null,
    }
  );

  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.policyDecision, 'BLOCKED_CRITICAL_SECRET_POLICY');
  assert.equal(result.cloudBytesTransmitted, 0);
});

test('Firebase Hybrid SDK adapter receives HybridParams and restores local vault tokens', async () => {
  let capturedMode: string | undefined;
  let capturedCloudModel: string | undefined;
  let capturedWirePrompt = '';

  const result = await runHybridInference(
    {
      prompt: 'Audit JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
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
      createFirebaseModel: (_cfg, params) => {
        capturedMode = params.mode;
        capturedCloudModel = params.inCloudParams?.model;
        return {
          generateContent: async (prompt: string) => {
            capturedWirePrompt = prompt;
            const jwtToken = prompt.match(/\{\{NV_JWT_\d+\}\}/)?.[0] ?? '';
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

  assert.equal(capturedMode, InferenceMode.PREFER_ON_DEVICE);
  assert.equal(capturedCloudModel, 'gemini-2.5-flash');
  assert.equal(capturedWirePrompt.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), false);
  assert.equal(result.status, 'SUCCESS');
  assert.equal(result.executionKind, 'FIREBASE_HYBRID_SDK');
  assert.equal(result.inferenceSource, InferenceSource.IN_CLOUD);
  assert.equal(result.restoredOutput.includes('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'), true);
});

test('Chrome Extension MV3 pii-guard.js produces identical redaction & restoration as core TypeScript engine', async () => {
  const extGuard = await import('../extension/pii-guard.js');
  const sample = 'User dev@acme.io leaked ghp_1234567890abcdef1234567890abcdef1234 from 192.168.10.55';
  const tsRes = scanAndRedact(sample);
  const jsRes = extGuard.scanAndRedact(sample);

  assert.equal(jsRes.redactedText, tsRes.redactedText);
  assert.deepEqual(jsRes.tokenMap, tsRes.tokenMap);
  assert.equal(jsRes.riskScore, tsRes.riskScore);
  assert.equal(extGuard.restoreTokens(jsRes.redactedText, jsRes.tokenMap), sample);
});

