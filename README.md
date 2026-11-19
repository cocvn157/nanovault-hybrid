# NanoVault Hybrid

**Privacy-First Hybrid AI Security & PII Redactor — Web App + Chrome Extension MV3**  
Built for **Google #BuildHybridAI 2026** using **Firebase AI Logic Hybrid Inference (`firebase@13.4.0` / `firebase/ai`)** and **Chrome Built-in AI (`Gemini Nano` / `window.LanguageModel`)**.

- **Live Web App:** https://cocvn157.github.io/nanovault-hybrid/
- **Repository:** https://github.com/cocvn157/nanovault-hybrid

---

## Why NanoVault Hybrid?

Developers and support teams routinely paste stack traces, `.env` snippets, JWTs, IBANs, and customer PII into AI assistants. Even when an app intends to run locally, hybrid setups fall back to the cloud when on-device models are unavailable or downloading.

**NanoVault Hybrid** ensures raw secrets **never leave the browser**:

1. **Zero-Trust Local PII Guard (`src/pii-guard.ts` & `extension/pii-guard.js`):**
   - Runs instantaneously in browser memory (`< 1 ms`) before any AI call.
   - Detects and replaces **Private Keys (PEM)**, **API Keys** (AWS `AKIA...`, GitHub `ghp_...`, Stripe `sk_live_...`, Firebase `AIza...`, OpenAI `sk-...`, Slack `xox...`), **Connection Strings**, **JWTs**, **Luhn-validated Credit Cards**, **ISO 13616 mod-97 IBANs**, **Emails**, **Phones**, and **IPv4s** with deterministic reversible vault tokens (`{{NV_API_KEY_1}}`, `{{NV_JWT_2}}`, etc.).
2. **Firebase AI Logic Hybrid Router (`src/hybrid-engine.ts`):**
   - Integrates `firebase/app` and `firebase/ai` (`getAI`, `getGenerativeModel`, `GoogleAIBackend`, `InferenceMode`, `InferenceSource`).
   - Supports all four hybrid modes:
     - `PREFER_ON_DEVICE`: Runs on-device via Chrome Built-in AI (Gemini Nano) with `0 B` cloud egress; if unavailable, falls back to Cloud Gemini (`gemini-2.5-flash`) **sending only the sanitized `{{NV_*}}` wire payload**.
     - `ONLY_ON_DEVICE`: Hard security lock. If Gemini Nano is unavailable, blocks execution locally (`0 B` cloud egress).
     - `PREFER_IN_CLOUD` / `ONLY_IN_CLOUD`: Redacts before cloud inference, with an optional **Critical-Secret Firewall** toggle that blocks cloud egress whenever `CRITICAL` credentials are detected.
   - Works out of the box in **Zero-Key Demo + Chrome Built-in AI Mode**, or with session-only Firebase Web App credentials.
3. **Ephemeral Local Vault Restoration:**
   - Re-hydrates `{{NV_*}}` placeholders back to original values strictly in local browser memory after inference so the user receives an actionable response without exposing credentials to external servers.
4. **Chrome Extension MV3 Companion (`extension/`):**
   - Manifest V3 Side Panel (`sidePanel`, `activeTab`, `scripting`) that grabs text/selections from the active tab, masks secrets using the shared `extension/pii-guard.js` engine, and runs local Gemini Nano (`LanguageModel.create()`) or copies a safe sanitized prompt.

---

## Architecture

```text
Raw Prompt / Crash Log / Tab Snippet
  │
  ▼  [1. Local PII Guard — Browser Memory Only (<1 ms)]
  ├── Tokenizes Secrets & PII ──► Ephemeral Token Map (never leaves browser)
  └── Sanitized Wire Payload ({{NV_*}})
        │
        ▼  [2. Firebase Hybrid Router — firebase@13.4.0 (firebase/ai)]
        ├── ONLY_ON_DEVICE + No Nano ──────────► BLOCKED (0 B cloud egress)
        ├── Critical Secret Firewall Active ───► BLOCKED (0 B cloud egress)
        ├── Gemini Nano Available ─────────────► ON_DEVICE (0 B cloud egress)
        └── Fallback Permitted ────────────────► IN_CLOUD (Sanitized Payload Only)
              │
              ▼  [3. Local Vault Restoration]
              └── Re-hydrates {{NV_*}} tokens locally for the user
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
- `npm test` — 7/7 automated tests passing (`node --experimental-strip-types --test`)
- `npm run build` — Vite production bundle built cleanly into `dist/`
