import type { EntityCategory } from './pii-guard.ts';

export type JudgePresetId = 'outage' | 'hr_ssn' | 'fintech' | 'ssh' | 'clean';

export interface JudgePreset {
  id: JudgePresetId;
  label: string;
  shortLabel: string;
  description: string;
  recommendedMode: 'prefer_on_device' | 'only_on_device' | 'prefer_in_cloud' | 'only_in_cloud';
  expectedCategories: EntityCategory[];
  prompt: string;
}

export const JUDGE_PRESETS: readonly JudgePreset[] = [
  {
    id: 'outage',
    label: 'Production Outage Leak',
    shortLabel: 'Outage Leak',
    description: 'Crash dump containing AWS IAM key, GitHub PAT, Postgres URI, JWT, SRE email, and internal IP.',
    recommendedMode: 'prefer_on_device',
    expectedCategories: ['IPV4', 'EMAIL', 'API_KEY', 'CONNECTION_STRING', 'JWT'],
    prompt: [
      'ALERT: Checkout worker crashed on 10.42.19.88 during deploy by lead.sre@acme-fin.io.',
      'Leaked AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and GitHub token ghp_9182736455abcdef1234567890abcdef1234.',
      'DB URL: postgres://deploy_bot:UltraS3cretPass!@prod-db.internal:5432/payments',
      'Session JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcmVfMDEiLCJzY29wZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    ].join('\n'),
  },
  {
    id: 'hr_ssn',
    label: 'HR SSN & Slack Bot Leak',
    shortLabel: 'HR SSN & Token',
    description: 'Support escalation containing US SSN, employee email, phone number, and Slack bot token.',
    recommendedMode: 'only_on_device',
    expectedCategories: ['EMAIL', 'PHONE', 'SSN', 'API_KEY'],
    prompt: [
      'Payroll support ticket for Marcus Chen (marcus.chen@northstar-hr.org, +1-415-555-0194).',
      'Tax filing mismatch on SSN 412-88-9041 for Q4 W-2 batch.',
      `Integration log accidentally dumped bot credential: ${['xoxb', '901234567890', '987654321098', 'DemoSyntheticToken26'].join('-')}`,
    ].join('\n'),
  },
  {
    id: 'fintech',
    label: 'FinTech IBAN & Card',
    shortLabel: 'FinTech IBAN/Card',
    description: 'Payment dispute with mod-97 IBAN, Luhn-validated Visa card, contact PII, and Stripe key.',
    recommendedMode: 'prefer_on_device',
    expectedCategories: ['EMAIL', 'PHONE', 'IBAN', 'CREDIT_CARD', 'API_KEY'],
    prompt: [
      'Customer Elena Vance (elena.vance@nordicmail.eu, +49 170 5550192) opened dispute #8841.',
      'Refund target IBAN: DE89370400440532013000',
      'Masked card trace still visible in log: 4532 0151 1283 0366',
      `Internal webhook key: ${['sk', 'live', '51N9xYzAbCdEfGhIjKlMnOpQrStUvWx'].join('_')}`,
    ].join('\n'),
  },
  {
    id: 'ssh',
    label: 'RSA Private Key Leak',
    shortLabel: 'RSA Private Key',
    description: 'Emergency rotation ticket containing Firebase Web API key and multi-line PEM RSA private key.',
    recommendedMode: 'only_on_device',
    expectedCategories: ['API_KEY', 'PRIVATE_KEY'],
    prompt: [
      'Emergency rotation ticket for Firebase web key AIzaSyD-9xYz1234567890AbCdEfGhIjKlMnOpQrS.',
      'Developer accidentally pasted private key into crash log:',
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7M',
      '9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/==',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n'),
  },
  {
    id: 'clean',
    label: 'Clean Safe Prompt',
    shortLabel: 'Clean Prompt',
    description: 'Zero-secret architectural prompt validating SAFE (0/100) risk score and zero-overhead pass-through.',
    recommendedMode: 'prefer_on_device',
    expectedCategories: [],
    prompt:
      'Summarize best practices for running Gemini Nano on-device via Firebase AI Logic Hybrid Inference in Chrome.',
  },
];

export const PRESET_MAP: Record<JudgePresetId, JudgePreset> = {
  outage: JUDGE_PRESETS[0],
  hr_ssn: JUDGE_PRESETS[1],
  fintech: JUDGE_PRESETS[2],
  ssh: JUDGE_PRESETS[3],
  clean: JUDGE_PRESETS[4],
};

export function getPresetById(id: string): JudgePreset {
  return PRESET_MAP[(id as JudgePresetId) in PRESET_MAP ? (id as JudgePresetId) : 'outage'];
}
