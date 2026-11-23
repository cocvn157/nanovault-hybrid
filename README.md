# NanoVault Hybrid

**Privacy-First Hybrid AI Security, Zero-Leak PII Diff Gate & Offline-Proof Router — Web App + Chrome Extension MV3**  
Built for **Google #BuildHybridAI 2026** using **Firebase AI Logic Hybrid Inference (`firebase@13.4.0` / `firebase/ai`)** and **Chrome Built-in AI (`Gemini Nano` / `window.LanguageModel`)**.

- **Live Web App:** https://cocvn157.github.io/nanovault-hybrid/
- **Repository:** https://github.com/cocvn157/nanovault-hybrid
- **Submission Details:** [DEVPOST_SUBMISSION.md](./DEVPOST_SUBMISSION.md)

---

## Why NanoVault Hybrid?

Developers, SREs, and HR/FinTech support engineers routinely paste stack traces, `.env` snippets, SSNs, JWTs, IBANs, and customer PII into AI assistants. Even when an app intends to run locally, hybrid setups silently fall back to the cloud when on-device models are unavailable or still downloading.

**NanoVault Hybrid** ensures raw secrets **never leave the browser**:

1. **Zero-Trust Local PII Guard (`src/pii-guard.ts` & `extension/pii-guard.js`):**
   - Runs in browser memory (`< 1 ms`) before any AI call or cloud escalation.
   - Detects and masks **PEM Private Keys**, **DB Connection Strings**, **API Keys** (AWS `AKIA...`, GitHub `ghp_`/`github_pat_`, Stripe `sk_live_`, Firebase `AIza...`, OpenAI `sk-proj-`, Anthropic `sk-ant-`, Slack `xox...`, HuggingFace `hf_`), **Bearer Tokens**, **JWTs**, **Luhn-validated Credit Cards**, **ISO 13616 mod-97 IBANs**, **US SSNs**, **Emails**, **Phones**, and **IPv4s** with deterministic reversible tokens (`<REDACTED_CATEGORY_N>` or `{{NV_CATEGORY_N}}`).
   - Toggleable granular policy switches (`Secrets`, `PII`, `SSNs`, `IPs`, `Block Cloud on Critical`) and offline searchable Ephemeral Local Vault.
2. **Zero-Leak Gate & Live Before/After Diff Inspector:**
   - Pre-flight `verifyZeroRawLeaks()` mathematically guarantees **0 raw secret bytes** appear in any outgoing wire packet before cloud escalation.
   - Side-by-side **Diff Gate** highlights raw browser-only secrets against `<REDACTED_*>` wire replacements in real time.
3. **Runtime Capability Probe & Firebase Hybrid Router (`src/hybrid-engine.ts`):**
   - Probes **Chrome Built-in AI Prompt API** (`window.LanguageModel` & `window.ai.languageModel`), **WebGPU adapter readiness**, **WASM support**, and **network status**.
   - Integrates `firebase/app` and `firebase/ai` (`getAI`, `getGenerativeModel`, `GoogleAIBackend`, `InferenceMode`, `InferenceSource`).
   - Supports all four hybrid modes (`PREFER_ON_DEVICE`, `ONLY_ON_DEVICE`, `PREFER_IN_CLOUD`, `ONLY_IN_CLOUD`), plus automatic deterministic fallback when Chrome Built-in AI is unavailable so every judge browser runs seamlessly out of the box.
4. **Offline / Airplane-Mode Proof & Cost/Latency Economics (`src/telemetry.ts`):**
   - Interactive **Airplane Mode (Offline $0)** toggle enforces `0 B` cloud egress while keeping local scanning, vault search, diff inspection, and local triage 100% operational at **`$0.00` token cost**.
   - Real-time latency & cost comparison chart contrasting Local/On-Device (`$0.00`) vs estimated Cloud Flash/Pro escalations and 1,000-request projections.
5. **Chrome Extension MV3 Companion (`extension/`):**
   - Manifest V3 Side Panel (`sidePanel`, `activeTab`, `scripting`) using the parity-tested `extension/pii-guard.js` engine.

---

## Architecture

```text
Raw Prompt / Crash Log / HR Ticket (5 Curated Presets)
  │
  ▼  [1. Local PII Guard + Diff Gate — Browser Memory (<1 ms)]
  ├── Tokenizes Secrets, SSNs & PII ──► Ephemeral Local Vault (Offline Searchable)
  ├── Before / After Diff Inspector ──► Highlights Raw vs <REDACTED_*>
  └── Pre-Flight Zero-Leak Check   ──► Verifies 0 raw secret bytes in egress
        │
        ▼  [2. Runtime Probe + Firebase Hybrid Router — firebase@13.4.0]
        ├── Airplane Mode / Offline ──────────► ON_DEVICE / OFFLINE_LOCAL ($0.00, 0 B egress)
        ├── ONLY_ON_DEVICE + No Nano ─────────► BLOCKED (0 B cloud egress)
        ├── Critical Secret Firewall Active ──► BLOCKED (0 B cloud egress)
        ├── Gemini Nano Available ────────────► ON_DEVICE (0 B cloud egress, $0.00)
        └── Fallback Permitted ───────────────► IN_CLOUD (Sanitized Wire Packet Only)
              │
              ▼  [3. Local Vault Restoration & Economics Telemetry]
              └── Re-hydrates <REDACTED_*> / {{NV_*}} tokens locally + logs cost/latency
```

---

## Quick Start

```bash
npm install
npx tsc --noEmit
npm test
npm run build
npm run dev
```

### Load the Chrome Extension (MV3)

1. Open `chrome://extensions` and enable **Developer mode**.
2. Click **Load unpacked** and select the `extension/` folder.
3. Click the **NanoVault Hybrid** icon to open the Side Panel.

---

## Verification

- `npx tsc --noEmit` — 0 TypeScript errors
- `npm test` — 40/40 automated Vitest unit tests passing across `tests/pii-guard.test.ts`, `tests/hybrid-engine.test.ts`, and `tests/telemetry-presets.test.ts`
- `npm run build` — Vite production bundle built cleanly into `dist/`
- Headless Microsoft Edge (`1280x720`) live smoke verification — `0` console errors, `0` page errors, `0` failed network requests
