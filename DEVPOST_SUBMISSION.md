# NanoVault Hybrid — Google #BuildHybridAI 2026 Submission

## Elevator Pitch
**NanoVault Hybrid** is a privacy-first hybrid AI security firewall, zero-leak PII/secret redactor, and offline-capable inference router built with **Firebase AI Logic Hybrid Inference (`firebase@13.4.0`)** and **Chrome Built-in AI (`Gemini Nano` / `window.LanguageModel`)**, paired with a **Chrome Extension MV3** side panel.

## Live Links
- **Live Web App (GitHub Pages):** https://cocvn157.github.io/nanovault-hybrid/
- **GitHub Repository:** https://github.com/cocvn157/nanovault-hybrid

---

## The Problem
Teams routinely paste stack traces, `.env` credentials, database URIs, customer SSNs, IBANs, and credit cards into AI tools. Even in hybrid architectures, silent cloud fallback leaks sensitive payloads whenever an on-device model is unavailable, downloading, or unsupported on a user's browser.

## How NanoVault Hybrid Solves It
1. **Zero-Trust Local PII & Secret Guard (`< 1 ms`):**
   - Scans raw prompts in browser memory before any AI call.
   - Masks PEM Private Keys, DB Connection Strings, API Keys (`AKIA`, `ghp_`, `sk_live_`, `AIza`, `sk-proj-`, `sk-ant-`, `xoxb-`, `hf_`), Bearer Tokens, JWTs, Luhn-valid Credit Cards, ISO 13616 mod-97 IBANs, US SSNs, Emails, Phones, and IPv4s into deterministic reversible placeholders (`<REDACTED_CATEGORY_N>` or `{{NV_CATEGORY_N}}`).
2. **Zero-Leak Gate & Live Before/After Diff Inspector:**
   - Displays a real-time side-by-side Before (Raw Browser Memory) vs After (Wire Packet) diff and executes `verifyZeroRawLeaks()` before any cloud escalation leaves the device.
3. **Firebase AI Logic Hybrid Inference + Runtime Hardware Probe:**
   - Probes `window.LanguageModel`, `window.ai.languageModel`, WebGPU adapter availability, WASM support, and network connectivity.
   - Routes across `PREFER_ON_DEVICE`, `ONLY_ON_DEVICE`, `PREFER_IN_CLOUD`, and `ONLY_IN_CLOUD` using `getAI`, `getGenerativeModel`, `GoogleAIBackend`, `InferenceMode`, and `InferenceSource`, plus a **Critical-Secret Firewall** toggle and automatic deterministic local fallback when Chrome Built-in AI is absent.
4. **Offline / Airplane-Mode Proof & Cost/Latency Economics:**
   - One-click **Airplane Mode (Offline $0)** toggle severs all cloud escalation (`0 B` egress), proving local PII scanning, offline vault search, diff inspection, and security triage continue operating at `$0.00` token cost.
   - Real-time benchmark chart contrasts local execution (`$0.00` / `<5 ms` local fallback) against estimated Gemini Cloud Flash/Pro latency and per-1k-request spend.
5. **Local Vault Token Restoration & Chrome Extension MV3:**
   - Re-hydrates `<REDACTED_*>` / `{{NV_*}}` placeholders strictly in local browser memory after inference.
   - Includes a Manifest V3 Side Panel (`extension/`) running the parity-tested `extension/pii-guard.js` engine directly on active browser tabs.

---

## Built With
- **Firebase AI Logic (`firebase@13.4.0` / `firebase/ai`)**
- **Chrome Built-in AI Prompt API (`Gemini Nano` / `window.LanguageModel`)**
- **TypeScript 5.8 & Vite 6**
- **Vitest 3.2** (40 passing unit tests)
- **Chrome Extension Manifest V3** (`sidePanel`, `activeTab`, `scripting`)

---

## Verification Summary
- `npx tsc --noEmit`: 0 errors
- `npm test` (`vitest run`): 40/40 tests passing across PII redaction edge cases, hybrid router policy decisions, offline fallback, cost/latency estimators, preset schemas, and MV3 extension parity
- `npm run build`: clean production bundle (`dist/`)
- Live headless Microsoft Edge (`1280x720`) smoke test on GitHub Pages: 0 console errors, 0 page errors, 0 failed network requests
