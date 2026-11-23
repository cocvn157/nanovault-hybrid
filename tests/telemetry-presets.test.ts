import { describe, it, expect } from 'vitest';
import { InferenceSource } from 'firebase/ai';
import { JUDGE_PRESETS, getPresetById } from '../src/presets.ts';
import { scanAndRedact, verifyZeroRawLeaks } from '../src/pii-guard.ts';
import {
  estimateHybridEconomics,
  estimateTokenCount,
  formatUsd,
  summarizeSessionTelemetry,
  type TelemetryEntryLike,
} from '../src/telemetry.ts';

describe('Benchmark Telemetry & Cost/Latency Estimators', () => {
  it('estimates token counts for empty and populated payloads', () => {
    expect(estimateTokenCount('')).toBe(0);
    expect(estimateTokenCount('   ')).toBe(0);
    expect(estimateTokenCount('abcd')).toBe(1);
    expect(estimateTokenCount('a'.repeat(400))).toBe(100);
  });

  it('computes $0.00 actual cost and full savings for on-device and offline runs', () => {
    const econ = estimateHybridEconomics({
      rawPrompt: 'Sensitive prompt '.repeat(40),
      wirePayload: 'Sanitized prompt '.repeat(40),
      outputText: 'Actionable remediation summary '.repeat(20),
      inferenceSource: InferenceSource.ON_DEVICE,
      measuredLatencyMs: 14.2,
      cloudBytesTransmitted: 0,
      offlineMode: true,
    });

    expect(econ.actualCostUsd).toBe(0);
    expect(econ.estimatedCloudFlashCostUsd).toBeGreaterThan(0);
    expect(econ.estimatedCloudProCostUsd).toBeGreaterThan(econ.estimatedCloudFlashCostUsd);
    expect(econ.usdSavedVsCloudFlash).toBe(econ.estimatedCloudFlashCostUsd);
    expect(econ.projected1kRequestsSavingsUsd).toBeGreaterThan(0);
    expect(econ.rawSecretBytesLeaked).toBe(0);
    expect(econ.estimatedCloudLatencyMs).toBeGreaterThan(econ.localLatencyMs);
    expect(econ.costBadgeText).toContain('$0.00');
  });

  it('computes positive cloud cost when cloud escalation transmits bytes', () => {
    const econ = estimateHybridEconomics({
      rawPrompt: 'Check ticket',
      wirePayload: 'Sanitized ticket '.repeat(30),
      outputText: 'Summary '.repeat(30),
      inferenceSource: InferenceSource.IN_CLOUD,
      measuredLatencyMs: 320,
      cloudBytesTransmitted: 510,
      offlineMode: false,
    });

    expect(econ.actualCostUsd).toBeGreaterThan(0);
    expect(econ.actualCostUsd).toBe(econ.estimatedCloudFlashCostUsd);
    expect(econ.usdSavedVsCloudFlash).toBe(0);
  });

  it('formats USD values consistently across zero, micro-dollar, and cent scales', () => {
    expect(formatUsd(0)).toBe('$0.0000');
    expect(formatUsd(0.00042)).toBe('$0.0004');
    expect(formatUsd(0.256)).toBe('$0.26');
  });

  it('aggregates cumulative session telemetry across mixed local, cloud, and blocked runs', () => {
    const localEcon = estimateHybridEconomics({
      rawPrompt: 'a',
      wirePayload: 'a'.repeat(400),
      outputText: 'b'.repeat(200),
      inferenceSource: InferenceSource.ON_DEVICE,
      measuredLatencyMs: 10,
      cloudBytesTransmitted: 0,
      offlineMode: true,
    });
    const cloudEcon = estimateHybridEconomics({
      rawPrompt: 'c',
      wirePayload: 'c'.repeat(400),
      outputText: 'd'.repeat(200),
      inferenceSource: InferenceSource.IN_CLOUD,
      measuredLatencyMs: 250,
      cloudBytesTransmitted: 400,
      offlineMode: false,
    });

    const entries: TelemetryEntryLike[] = [
      {
        status: 'SUCCESS',
        inferenceSource: InferenceSource.ON_DEVICE,
        offlineMode: true,
        latencyMs: 10,
        cloudBytesTransmitted: 0,
        redaction: { entities: [{}, {}] },
        economics: localEcon,
      },
      {
        status: 'SUCCESS',
        inferenceSource: InferenceSource.IN_CLOUD,
        offlineMode: false,
        latencyMs: 250,
        cloudBytesTransmitted: 400,
        redaction: { entities: [{}] },
        economics: cloudEcon,
      },
      {
        status: 'BLOCKED',
        inferenceSource: 'BLOCKED',
        offlineMode: false,
        latencyMs: 1,
        cloudBytesTransmitted: 0,
        redaction: { entities: [{}, {}, {}] },
        economics: { ...localEcon, usdSavedVsCloudFlash: localEcon.estimatedCloudFlashCostUsd },
      },
    ];

    const summary = summarizeSessionTelemetry(entries);
    expect(summary.totalRuns).toBe(3);
    expect(summary.onDeviceRuns).toBe(1);
    expect(summary.cloudRuns).toBe(1);
    expect(summary.blockedRuns).toBe(1);
    expect(summary.offlineRuns).toBe(1);
    expect(summary.totalEntitiesProtected).toBe(6);
    expect(summary.totalCloudBytesTransmitted).toBe(400);
    expect(summary.totalActualCostUsd).toBe(cloudEcon.actualCostUsd);
    expect(summary.totalEstimatedSavingsUsd).toBeGreaterThan(0);

    expect(summarizeSessionTelemetry([]).totalRuns).toBe(0);
  });
});

describe('Curated Judge Presets Schema & Coverage', () => {
  it('defines 5 unique curated presets with valid metadata', () => {
    expect(JUDGE_PRESETS.length).toBe(5);
    const ids = new Set(JUDGE_PRESETS.map((p) => p.id));
    expect(ids.size).toBe(5);
    for (const preset of JUDGE_PRESETS) {
      expect(preset.label.trim().length).toBeGreaterThan(3);
      expect(preset.description.trim().length).toBeGreaterThan(10);
      expect(preset.prompt.trim().length).toBeGreaterThan(10);
    }
  });

  it('redacts every expected category in every sensitive preset with zero raw leaks', () => {
    for (const preset of JUDGE_PRESETS) {
      if (preset.id === 'clean') continue;
      const res = scanAndRedact(preset.prompt);
      const foundCategories = new Set(res.entities.map((e) => e.category));
      for (const expected of preset.expectedCategories) {
        expect(foundCategories.has(expected)).toBe(true);
      }
      expect(verifyZeroRawLeaks(res.redactedText, res).zeroLeaks).toBe(true);
    }
  });

  it('validates clean preset yields SAFE (0/100) and zero redacted entities', () => {
    const clean = getPresetById('clean');
    const res = scanAndRedact(clean.prompt);
    expect(res.entities.length).toBe(0);
    expect(res.riskLevel).toBe('SAFE');
    expect(res.riskScore).toBe(0);
    expect(res.containsCriticalSecrets).toBe(false);
  });

  it('falls back to outage preset when unknown id is requested', () => {
    expect(getPresetById('unknown-preset').id).toBe('outage');
    expect(getPresetById('hr_ssn').id).toBe('hr_ssn');
  });
});
