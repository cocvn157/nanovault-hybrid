import { describe, it, expect } from 'vitest';
import {
  DEFAULT_PRIVACY_POLICY,
  buildRedactionDiff,
  computeRiskSummary,
  restoreTokens,
  scanAndRedact,
  searchVaultEntities,
  verifyZeroRawLeaks,
} from '../src/pii-guard.ts';

describe('NanoVault Zero-Trust PII & Secret Guard', () => {
  it('redacts PEM keys, DB URIs, JWTs, API keys, IBAN, Visa Luhn, SSN, emails, phones, and IPv4s losslessly', () => {
    const sampleSecret = [
      'Incident by alice.ops@example.com (+1-415-555-0194) from 10.24.8.15.',
      'SSN=412-88-9041',
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

    expect(res.containsCriticalSecrets).toBe(true);
    expect(res.riskLevel).toBe('CRITICAL');
    expect(res.riskScore).toBe(100);
    expect(res.entities.length).toBeGreaterThanOrEqual(10);
    expect(res.maskStyle).toBe('redacted');
    expect(res.redactedText).toContain('<REDACTED_SSN_');

    // Verify raw secrets never appear in redactedText
    for (const secret of [
      'AKIAIOSFODNN7EXAMPLE',
      'ghp_1234567890abcdef1234567890abcdef1234',
      'S3cretPass!',
      'alice.ops@example.com',
      '412-88-9041',
      'DE89370400440532013000',
      '4532 0151 1283 0366',
      'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M',
    ]) {
      expect(res.redactedText.includes(secret)).toBe(false);
    }

    expect(verifyZeroRawLeaks(res.redactedText, res).zeroLeaks).toBe(true);
    expect(restoreTokens(res.redactedText, res.tokenMap)).toBe(sampleSecret);
  });

  it('detects OpenAI, Anthropic, Slack, HuggingFace, and Firebase API keys', () => {
    const keys = [
      ['sk', 'proj', 'AbCdEfGhIjKlMnOpQrStUvWxYz123456'].join('-'),
      ['sk', 'ant', 'api03-AbCdEfGhIjKlMnOpQrStUvWxYz12'].join('-'),
      ['xoxb', '901234567890', '987654321098', 'DemoSyntheticToken26'].join('-'),
      'hf_' + 'AbCdEfGhIjKlMnOpQrStUvWxYz',
      'AIzaSyD-9xYz1234567890AbCdEfGhIjKlMnOpQrS',
    ].join(' | ');

    const res = scanAndRedact(keys);
    expect(res.entities.filter((e) => e.category === 'API_KEY').length).toBe(5);
    expect(verifyZeroRawLeaks(res.redactedText, res).zeroLeaks).toBe(true);
  });

  it('classifies opaque Bearer tokens as BEARER_TOKEN while keeping Bearer JWTs as JWT', () => {
    const opaqueBearer = 'Authorization: Bearer opaque_token_value_1234567890abcdef';
    const jwtBearer =
      'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

    const opaqueRes = scanAndRedact(opaqueBearer);
    expect(opaqueRes.entities.map((e) => e.category)).toEqual(['BEARER_TOKEN']);

    const jwtRes = scanAndRedact(jwtBearer);
    expect(jwtRes.entities.map((e) => e.category)).toEqual(['JWT']);
  });

  it('rejects invalid SSN area/group/serial patterns and avoids phone false positives', () => {
    const text = 'Invalid SSNs: 000-12-3456, 666-12-3456, 912-12-3456, 123-00-3456, 123-45-0000. Phone: +1-415-555-0194';
    const res = scanAndRedact(text);
    const ssns = res.entities.filter((e) => e.category === 'SSN');
    const phones = res.entities.filter((e) => e.category === 'PHONE');
    expect(ssns.length).toBe(0);
    expect(phones.length).toBe(1);
  });

  it('validates Luhn credit cards and rejects invalid check digits', () => {
    const res = scanAndRedact('Valid=4532 0151 1283 0366 Invalid=4532 0151 1283 0367 NonCard=1234 5678 9012 3456');
    const cards = res.entities.filter((e) => e.category === 'CREDIT_CARD');
    expect(cards.length).toBe(1);
    expect(cards[0].original).toBe('4532 0151 1283 0366');
  });

  it('validates ISO 13616 mod-97 IBANs and rejects invalid IBAN checksums', () => {
    const res = scanAndRedact('Valid=DE89370400440532013000 Invalid=DE00370400440532013000');
    const ibans = res.entities.filter((e) => e.category === 'IBAN');
    expect(ibans.length).toBe(1);
    expect(ibans[0].original).toBe('DE89370400440532013000');
  });

  it('ignores localhost and unspecified IPs while redacting routable IPv4s', () => {
    const res = scanAndRedact('Local 127.0.0.1 and 0.0.0.0 skipped, worker 10.42.19.88 masked.');
    const ips = res.entities.filter((e) => e.category === 'IPV4');
    expect(ips.length).toBe(1);
    expect(ips[0].original).toBe('10.42.19.88');
  });

  it('assigns identical deterministic tokens when the same secret repeats', () => {
    const res = scanAndRedact('First a@b.co then again a@b.co and second c@d.co');
    expect(res.entities.length).toBe(3);
    expect(res.entities[0].token).toBe('<REDACTED_EMAIL_1>');
    expect(res.entities[1].token).toBe('<REDACTED_EMAIL_1>');
    expect(res.entities[2].token).toBe('<REDACTED_EMAIL_2>');
    expect(restoreTokens(res.redactedText, res.tokenMap)).toBe('First a@b.co then again a@b.co and second c@d.co');
  });

  it('supports both <REDACTED_*> and {{NV_*}} mask formats cleanly', () => {
    const sample = 'Mail dev@acme.io SSN 412-88-9041';
    const redactedStyle = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, maskStyle: 'redacted' });
    const vaultStyle = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, maskStyle: 'vault' });

    expect(redactedStyle.redactedText).toContain('<REDACTED_EMAIL_1>');
    expect(redactedStyle.redactedText).toContain('<REDACTED_SSN_2>');
    expect(vaultStyle.redactedText).toContain('{{NV_EMAIL_1}}');
    expect(vaultStyle.redactedText).toContain('{{NV_SSN_2}}');
  });

  it('honors granular toggleable policy rules (secrets, pii, ssn, network)', () => {
    const sample = 'Key AKIAIOSFODNN7EXAMPLE SSN 412-88-9041 Mail dev@acme.io IP 10.0.0.5';

    const noSsn = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, redactSsn: false });
    expect(noSsn.entities.some((e) => e.category === 'SSN')).toBe(false);
    expect(noSsn.entities.some((e) => e.category === 'EMAIL')).toBe(true);

    const noSecrets = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, redactSecrets: false });
    expect(noSecrets.entities.some((e) => e.category === 'API_KEY')).toBe(false);

    const noNet = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, redactNetwork: false });
    expect(noNet.entities.some((e) => e.category === 'IPV4')).toBe(false);
  });

  it('builds lossless Before/After diff segments for the Diff Gate inspector', () => {
    const input = 'Contact sec@acme.io on 10.1.2.3 ASAP';
    const res = scanAndRedact(input);
    const segments = buildRedactionDiff(res);

    expect(segments.filter((s) => s.kind === 'redacted').length).toBe(2);
    expect(segments.map((s) => s.text).join('')).toBe(input);
    expect(buildRedactionDiff(scanAndRedact('')).length).toBe(0);
  });

  it('detects raw secret leakage if unmasked text slips into wire payload', () => {
    const res = scanAndRedact('Secret AKIAIOSFODNN7EXAMPLE leaked');
    expect(verifyZeroRawLeaks(res.redactedText, res).zeroLeaks).toBe(true);
    const leak = verifyZeroRawLeaks('Oops AKIAIOSFODNN7EXAMPLE raw', res);
    expect(leak.zeroLeaks).toBe(false);
    expect(leak.leakedValues).toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('supports offline vault search across tokens, categories, and severities', () => {
    const res = scanAndRedact('SSN 412-88-9041 mail dev@acme.io key AKIAIOSFODNN7EXAMPLE ip 10.1.2.3');
    expect(searchVaultEntities(res.entities, '').length).toBe(4);
    expect(searchVaultEntities(res.entities, 'ssn').length).toBe(1);
    expect(searchVaultEntities(res.entities, 'critical').length).toBe(1);
    expect(searchVaultEntities(res.entities, 'nonexistent').length).toBe(0);
  });

  it('computes accurate risk levels across SAFE, LOW, MEDIUM, HIGH, and CRITICAL', () => {
    expect(computeRiskSummary([]).riskLevel).toBe('SAFE');
    expect(scanAndRedact('IP 10.1.1.1').riskLevel).toBe('LOW');
    expect(scanAndRedact('Mail a@b.co and b@c.co').riskLevel).toBe('MEDIUM');
    expect(scanAndRedact('SSN 412-88-9041').riskLevel).toBe('HIGH');
    expect(scanAndRedact('Key AKIAIOSFODNN7EXAMPLE').riskLevel).toBe('CRITICAL');
  });

  it('maintains 100% parity with Chrome Extension MV3 extension/pii-guard.js', async () => {
    const extGuard = await import('../extension/pii-guard.js');
    const sample =
      'User dev@acme.io SSN 412-88-9041 leaked ghp_1234567890abcdef1234567890abcdef1234 from 192.168.10.55';

    const tsRedacted = scanAndRedact(sample);
    const jsRedacted = extGuard.scanAndRedact(sample);
    expect(jsRedacted.redactedText).toBe(tsRedacted.redactedText);
    expect(jsRedacted.tokenMap).toEqual(tsRedacted.tokenMap);
    expect(jsRedacted.riskScore).toBe(tsRedacted.riskScore);
    expect(extGuard.restoreTokens(jsRedacted.redactedText, jsRedacted.tokenMap)).toBe(sample);

    const tsVault = scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, maskStyle: 'vault' });
    const jsVault = extGuard.scanAndRedact(sample, { ...DEFAULT_PRIVACY_POLICY, maskStyle: 'vault' });
    expect(jsVault.redactedText).toBe(tsVault.redactedText);
  });

  it('redacts MongoDB SRV and Redis URIs with embedded credentials', () => {
    const uris =
      'MONGO=mongodb+srv://svc:TopSecret99@cluster0.example.net/prod REDIS=redis://default:r3d1sPass@cache.internal:6379/0';
    const res = scanAndRedact(uris);
    expect(res.entities.filter((e) => e.category === 'CONNECTION_STRING').length).toBe(2);
    expect(verifyZeroRawLeaks(res.redactedText, res).zeroLeaks).toBe(true);
    expect(restoreTokens(res.redactedText, res.tokenMap)).toBe(uris);
  });

  it('redacts Luhn-valid MasterCard while ignoring short order numbers', () => {
    const sample = 'Order #88419201 paid with MC 5425 2334 3010 9903';
    const res = scanAndRedact(sample);
    const cards = res.entities.filter((e) => e.category === 'CREDIT_CARD');
    expect(cards.length).toBe(1);
    expect(res.redactedText).toContain('Order #88419201');
  });

  it('handles 10+ tokens without prefix replacement collision during restoration', () => {
    const emails = Array.from({ length: 12 }, (_, i) => `user${i + 1}@example.org`).join(' ');
    const res = scanAndRedact(emails);
    expect(res.entities.length).toBe(12);
    expect(restoreTokens(res.redactedText, res.tokenMap)).toBe(emails);
  });
});
