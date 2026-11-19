export type EntityCategory =
  | 'PRIVATE_KEY'
  | 'API_KEY'
  | 'JWT'
  | 'CONNECTION_STRING'
  | 'CREDIT_CARD'
  | 'IBAN'
  | 'EMAIL'
  | 'PHONE'
  | 'IPV4';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RedactedEntity {
  id: string;
  token: string;
  category: EntityCategory;
  severity: SeverityLevel;
  original: string;
  maskedPreview: string;
  start: number;
  end: number;
}

export interface PrivacyPolicy {
  redactSecrets: boolean;
  redactPii: boolean;
  redactNetwork: boolean;
}

export interface RedactionResult {
  originalText: string;
  redactedText: string;
  entities: RedactedEntity[];
  tokenMap: Record<string, string>;
  riskScore: number;
  riskLevel: RiskLevel;
  containsCriticalSecrets: boolean;
  scanDurationMs: number;
}

export const DEFAULT_PRIVACY_POLICY: PrivacyPolicy = {
  redactSecrets: true,
  redactPii: true,
  redactNetwork: true,
};

interface PatternRule {
  category: EntityCategory;
  severity: SeverityLevel;
  group: 'secrets' | 'pii' | 'network';
  regex: RegExp;
  validate?: (match: string) => boolean;
}

function luhnCheck(raw: string): boolean {
  const digits = raw.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = Number(digits[i]);
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function isValidIbanFormat(raw: string): boolean {
  const clean = raw.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(clean)) return false;
  // ISO 13616 mod-97 check
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    const expanded = code >= 65 && code <= 90 ? String(code - 55) : rearranged[i];
    for (let j = 0; j < expanded.length; j++) {
      remainder = (remainder * 10 + Number(expanded[j])) % 97;
    }
  }
  return remainder === 1;
}

function maskPreview(value: string, category: EntityCategory): string {
  if (category === 'PRIVATE_KEY') {
    return '-----BEGIN PRIVATE KEY----- [REDACTED]';
  }
  const trimmed = value.trim();
  if (trimmed.length <= 8) return '****';
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;
}

const PATTERN_RULES: PatternRule[] = [
  {
    category: 'PRIVATE_KEY',
    severity: 'CRITICAL',
    group: 'secrets',
    regex: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
  },
  {
    category: 'CONNECTION_STRING',
    severity: 'CRITICAL',
    group: 'secrets',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'`<>]+/gi,
  },
  {
    category: 'JWT',
    severity: 'HIGH',
    group: 'secrets',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    category: 'API_KEY',
    severity: 'CRITICAL',
    group: 'secrets',
    regex: /\b(?:sk(?:-(?:proj-|live-|test-)?|_(?:live|test)_)[A-Za-z0-9_-]{20,}|rk_(?:live|test)_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{32,45}|xox[baprs]-[0-9A-Za-z-]{16,})\b/g,
  },
  {
    category: 'CREDIT_CARD',
    severity: 'HIGH',
    group: 'pii',
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: (match) => {
      const digitsOnly = match.replace(/\D/g, '');
      if (digitsOnly.length < 13 || digitsOnly.length > 19) return false;
      // Require separator formatting or standard card prefix (Visa/MC/Amex/Discover)
      const hasCardPrefix = /^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))/.test(digitsOnly);
      return hasCardPrefix && luhnCheck(digitsOnly);
    },
  },
  {
    category: 'IBAN',
    severity: 'HIGH',
    group: 'pii',
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g,
    validate: isValidIbanFormat,
  },
  {
    category: 'EMAIL',
    severity: 'MEDIUM',
    group: 'pii',
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  },
  {
    category: 'PHONE',
    severity: 'MEDIUM',
    group: 'pii',
    regex: /(?:\+\d{1,3}[-.\s]?)\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g,
    validate: (match) => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 9 && digits.length <= 15;
    },
  },
  {
    category: 'IPV4',
    severity: 'LOW',
    group: 'network',
    regex: /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,
    validate: (ip) => ip !== '127.0.0.1' && ip !== '0.0.0.0',
  },
];

const SEVERITY_WEIGHT: Record<SeverityLevel, number> = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 12,
  LOW: 5,
};

export function computeRiskSummary(entities: RedactedEntity[]): {
  riskScore: number;
  riskLevel: RiskLevel;
  containsCriticalSecrets: boolean;
} {
  if (entities.length === 0) {
    return { riskScore: 0, riskLevel: 'SAFE', containsCriticalSecrets: false };
  }

  let score = 0;
  let hasCritical = false;
  let hasHigh = false;

  for (const entity of entities) {
    score += SEVERITY_WEIGHT[entity.severity];
    if (entity.severity === 'CRITICAL') hasCritical = true;
    if (entity.severity === 'HIGH') hasHigh = true;
  }

  const capped = Math.min(100, score);
  let riskLevel: RiskLevel = 'LOW';
  if (hasCritical || capped >= 70) riskLevel = 'CRITICAL';
  else if (hasHigh || capped >= 40) riskLevel = 'HIGH';
  else if (capped >= 20) riskLevel = 'MEDIUM';

  return {
    riskScore: capped,
    riskLevel,
    containsCriticalSecrets: hasCritical,
  };
}

function isRuleEnabled(group: PatternRule['group'], policy: PrivacyPolicy): boolean {
  if (group === 'secrets') return policy.redactSecrets;
  if (group === 'pii') return policy.redactPii;
  return policy.redactNetwork;
}

export function scanAndRedact(
  input: string,
  policy: PrivacyPolicy = DEFAULT_PRIVACY_POLICY
): RedactionResult {
  const startNs = performance.now();
  const candidates: Array<{
    start: number;
    end: number;
    category: EntityCategory;
    severity: SeverityLevel;
    original: string;
  }> = [];

  for (const rule of PATTERN_RULES) {
    if (!isRuleEnabled(rule.group, policy)) continue;
    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(input)) !== null) {
      const value = match[0];
      if (!value) {
        regex.lastIndex += 1;
        continue;
      }
      if (rule.validate && !rule.validate(value)) continue;
      candidates.push({
        start: match.index,
        end: match.index + value.length,
        category: rule.category,
        severity: rule.severity,
        original: value,
      });
    }
  }

  // Sort by start offset ascending, then longest match first so broad matches (e.g., private keys, URIs) win
  candidates.sort((a, b) => a.start - b.start || b.end - a.end);

  const accepted: typeof candidates = [];
  let cursor = 0;
  for (const cand of candidates) {
    if (cand.start >= cursor) {
      accepted.push(cand);
      cursor = cand.end;
    }
  }

  const valueToToken = new Map<string, string>();
  const tokenMap: Record<string, string> = {};
  const entities: RedactedEntity[] = [];
  let counter = 0;

  let redactedText = '';
  let lastIndex = 0;

  for (const item of accepted) {
    let token = valueToToken.get(item.original);
    if (!token) {
      counter += 1;
      token = `{{NV_${item.category}_${counter}}}`;
      valueToToken.set(item.original, token);
      tokenMap[token] = item.original;
    }

    redactedText += input.slice(lastIndex, item.start) + token;
    lastIndex = item.end;

    entities.push({
      id: `ent_${entities.length + 1}`,
      token,
      category: item.category,
      severity: item.severity,
      original: item.original,
      maskedPreview: maskPreview(item.original, item.category),
      start: item.start,
      end: item.end,
    });
  }

  redactedText += input.slice(lastIndex);

  const risk = computeRiskSummary(entities);
  const scanDurationMs = Math.max(0.01, Number((performance.now() - startNs).toFixed(2)));

  return {
    originalText: input,
    redactedText,
    entities,
    tokenMap,
    riskScore: risk.riskScore,
    riskLevel: risk.riskLevel,
    containsCriticalSecrets: risk.containsCriticalSecrets,
    scanDurationMs,
  };
}

export function restoreTokens(text: string, tokenMap: Record<string, string>): string {
  let restored = text;
  for (const [token, original] of Object.entries(tokenMap)) {
    if (restored.includes(token)) {
      restored = restored.split(token).join(original);
    }
  }
  return restored;
}
