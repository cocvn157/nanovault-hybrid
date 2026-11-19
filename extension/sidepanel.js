import { scanAndRedact, restoreTokens } from './pii-guard.js';

const spNanoBadge = document.getElementById('spNanoBadge');
const spInput = document.getElementById('spInput');
const spMode = document.getElementById('spMode');
const spOutput = document.getElementById('spOutput');
const spTelemetry = document.getElementById('spTelemetry');
const grabSelectionBtn = document.getElementById('grabSelectionBtn');
const spAnalyzeBtn = document.getElementById('spAnalyzeBtn');
const spCopyBtn = document.getElementById('spCopyBtn');

async function probeChromeNano() {
  const provider = globalThis.LanguageModel || globalThis.ai?.languageModel;
  if (!provider) {
    spNanoBadge.textContent = 'Nano: Unavailable';
    return null;
  }
  try {
    const status = provider.availability
      ? await provider.availability()
      : (await provider.capabilities?.())?.available || 'unavailable';
    spNanoBadge.textContent = `Nano: ${status}`;
    return status === 'available' || status === 'readily' ? provider : null;
  } catch {
    spNanoBadge.textContent = 'Nano: Unavailable';
    return null;
  }
}

grabSelectionBtn.addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.getSelection()?.toString() || document.body.innerText.slice(0, 1200),
    });
    const text = results?.[0]?.result || '';
    if (text) spInput.value = text;
  } catch (err) {
    spOutput.textContent = `Tab capture blocked on restricted page: ${err?.message || err}`;
  }
});

spCopyBtn.addEventListener('click', async () => {
  const redacted = scanAndRedact(spInput.value);
  await navigator.clipboard.writeText(redacted.redactedText);
  spTelemetry.textContent = `${redacted.entities.length} entities masked · Copied safe prompt`;
});

spAnalyzeBtn.addEventListener('click', async () => {
  const started = performance.now();
  const redaction = scanAndRedact(spInput.value);
  const mode = spMode.value;
  const provider = await probeChromeNano();

  if (provider) {
    const session = await provider.create({
      initialPrompts: [
        {
          role: 'system',
          content: 'Summarize security risks concisely and keep {{NV_*}} tokens verbatim.',
        },
      ],
    });
    try {
      const raw = await session.prompt(redaction.redactedText);
      const ms = (performance.now() - started).toFixed(1);
      spTelemetry.textContent = `ON_DEVICE (Nano) · ${ms} ms · ${redaction.entities.length} masked · 0 B cloud`;
      spOutput.textContent = restoreTokens(raw, redaction.tokenMap);
      return;
    } finally {
      session.destroy?.();
    }
  }

  if (mode === 'only_on_device') {
    const ms = (performance.now() - started).toFixed(1);
    spTelemetry.textContent = `BLOCKED (ONLY_ON_DEVICE) · ${ms} ms · ${redaction.entities.length} masked · 0 B cloud`;
    spOutput.textContent =
      'ONLY_ON_DEVICE blocked execution because Gemini Nano is unavailable in this Chrome profile.\n\nSafe Redacted Preview:\n' +
      redaction.redactedText;
    return;
  }

  const ms = (performance.now() - started).toFixed(1);
  spTelemetry.textContent = `SANITIZED PREVIEW · ${ms} ms · ${redaction.entities.length} masked`;
  spOutput.textContent = `Safe Sanitized Prompt Ready for Hybrid Cloud:\n\n${redaction.redactedText}`;
});

void probeChromeNano();
