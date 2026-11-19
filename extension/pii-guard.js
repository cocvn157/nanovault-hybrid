// Shared Zero-Trust Local PII & Secret Guard for Chrome Extension MV3 Side Panel
// Mirrors src/pii-guard.ts regex rules, Luhn/IBAN validators, and reversible token map.

export const DEFAULT_PRIVACY_POLICY = {
  redactSecrets: true,
  redactPii: true,
  redactNetwork: true,
};

function luhnCheck(raw) {
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

function isValidIbanFormat(raw) {
  const clean = raw.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15 || clean.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(clean)) return false;
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

const PATTERN_RULES = [
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

const SEVERITY_WEIGHT = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 5 };

export function scanAndRedact(input, policy = DEFAULT_PRIVACY_POLICY) {
  const candidates = [];
  for (const rule of PATTERN_RULES) {
    const enabled =
      rule.group === 'secrets'
        ? policy.redactSecrets
        : rule.group === 'pii'
          ? policy.redactPii
          : policy.redactNetwork;
    if (!enabled) continue;

    const regex = new RegExp(rule.regex.source, rule.regex.flags);
    let match;
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

  candidates.sort((a, b) => a.start - b.start || b.end - a.end);
  const accepted = [];
  let cursor = 0;
  for (const cand of candidates) {
    if (cand.start >= cursor) {
      accepted.push(cand);
      cursor = cand.end;
    }
  }

  const valueToToken = new Map();
  const tokenMap = {};
  const entities = [];
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
    entities.push({ token, category: item.category, severity: item.severity });
  }
  redactedText += input.slice(lastIndex);

  let score = 0;
  let hasCritical = false;
  for (const ent of entities) {
    score += SEVERITY_WEIGHT[ent.severity] || 5;
    if (ent.severity === 'CRITICAL') hasCritical = true;
  }

  return {
    originalText: input,
    redactedText,
    entities,
    tokenMap,
    riskScore: Math.min(100, score),
    containsCriticalSecrets: hasCritical,
  };
}

export function restoreTokens(text, tokenMap) {
  let out = text;
  for (const [token, original] of Object.entries(tokenMap)) {
    out = out.split(token).join(original);
  }
  return out;
}
