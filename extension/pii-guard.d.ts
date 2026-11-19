import type { PrivacyPolicy } from '../src/pii-guard.ts';

export function scanAndRedact(
  input: string,
  policy?: PrivacyPolicy
): {
  originalText: string;
  redactedText: string;
  entities: Array<{ token: string; category: string; severity: string }>;
  tokenMap: Record<string, string>;
  riskScore: number;
  containsCriticalSecrets: boolean;
};

export function restoreTokens(text: string, tokenMap: Record<string, string>): string;
