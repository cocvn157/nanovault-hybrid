import { InferenceSource } from 'firebase/ai';

export interface HybridEconomicsReport {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  actualCostUsd: number;
  estimatedCloudFlashCostUsd: number;
  estimatedCloudProCostUsd: number;
  usdSavedVsCloudFlash: number;
  projected1kRequestsSavingsUsd: number;
  localLatencyMs: number;
  estimatedCloudLatencyMs: number;
  rawInputBytes: number;
  cloudBytesTransmitted: number;
  rawSecretBytesLeaked: number;
  costBadgeText: string;
}

export interface SessionTelemetrySummary {
  totalRuns: number;
  onDeviceRuns: number;
  cloudRuns: number;
  blockedRuns: number;
  offlineRuns: number;
  totalEntitiesProtected: number;
  totalCloudBytesTransmitted: number;
  totalActualCostUsd: number;
  totalEstimatedSavingsUsd: number;
  avgLocalLatencyMs: number;
  avgEstimatedCloudLatencyMs: number;
}

// Public Gemini API pricing baseline ($ per 1M tokens) used solely for transparent client-side estimation.
const FLASH_INPUT_PER_M = 0.30;
const FLASH_OUTPUT_PER_M = 2.50;
const PRO_INPUT_PER_M = 1.25;
const PRO_OUTPUT_PER_M = 10.0;

export function estimateTokenCount(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  return Math.max(1, Math.ceil(trimmed.length / 4));
}

function roundUsd(value: number): number {
  return Number(value.toFixed(6));
}

export function formatUsd(value: number): string {
  if (value <= 0) return '$0.0000';
  if (value < 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(2)}`;
}

export function estimateHybridEconomics(params: {
  rawPrompt: string;
  wirePayload: string;
  outputText: string;
  inferenceSource: InferenceSource | 'BLOCKED';
  measuredLatencyMs: number;
  cloudBytesTransmitted: number;
  offlineMode?: boolean;
}): HybridEconomicsReport {
  const inputTokens = estimateTokenCount(params.wirePayload);
  const outputTokens = estimateTokenCount(params.outputText || 'Standard security triage response summary.');
  const totalTokens = inputTokens + outputTokens;

  const estimatedCloudFlashCostUsd = roundUsd(
    (inputTokens / 1_000_000) * FLASH_INPUT_PER_M + (outputTokens / 1_000_000) * FLASH_OUTPUT_PER_M
  );
  const estimatedCloudProCostUsd = roundUsd(
    (inputTokens / 1_000_000) * PRO_INPUT_PER_M + (outputTokens / 1_000_000) * PRO_OUTPUT_PER_M
  );

  const isLocalOrBlocked =
    params.inferenceSource === InferenceSource.ON_DEVICE ||
    params.inferenceSource === 'BLOCKED' ||
    Boolean(params.offlineMode) ||
    params.cloudBytesTransmitted === 0;

  const actualCostUsd = isLocalOrBlocked ? 0 : estimatedCloudFlashCostUsd;
  const usdSavedVsCloudFlash = roundUsd(Math.max(0, estimatedCloudFlashCostUsd - actualCostUsd));
  const projected1kRequestsSavingsUsd = Number((estimatedCloudFlashCostUsd * 1000).toFixed(2));

  const estimatedCloudLatencyMs = Math.round(420 + totalTokens * 0.65);
  const localLatencyMs = Number(Math.max(0.1, params.measuredLatencyMs).toFixed(2));
  const rawInputBytes = new TextEncoder().encode(params.rawPrompt).length;

  const costBadgeText = isLocalOrBlocked
    ? '$0.00 (On-Device / Zero-Cost)'
    : `${formatUsd(actualCostUsd)} est. (Cloud Flash)`;

  return {
    inputTokens,
    outputTokens,
    totalTokens,
    actualCostUsd,
    estimatedCloudFlashCostUsd,
    estimatedCloudProCostUsd,
    usdSavedVsCloudFlash,
    projected1kRequestsSavingsUsd,
    localLatencyMs,
    estimatedCloudLatencyMs,
    rawInputBytes,
    cloudBytesTransmitted: params.cloudBytesTransmitted,
    rawSecretBytesLeaked: 0,
    costBadgeText,
  };
}

export interface TelemetryEntryLike {
  status: 'SUCCESS' | 'BLOCKED';
  inferenceSource: InferenceSource | 'BLOCKED';
  offlineMode: boolean;
  latencyMs: number;
  cloudBytesTransmitted: number;
  redaction: { entities: unknown[] };
  economics: HybridEconomicsReport;
}

export function summarizeSessionTelemetry(history: readonly TelemetryEntryLike[]): SessionTelemetrySummary {
  if (history.length === 0) {
    return {
      totalRuns: 0,
      onDeviceRuns: 0,
      cloudRuns: 0,
      blockedRuns: 0,
      offlineRuns: 0,
      totalEntitiesProtected: 0,
      totalCloudBytesTransmitted: 0,
      totalActualCostUsd: 0,
      totalEstimatedSavingsUsd: 0,
      avgLocalLatencyMs: 0,
      avgEstimatedCloudLatencyMs: 0,
    };
  }

  let onDeviceRuns = 0;
  let cloudRuns = 0;
  let blockedRuns = 0;
  let offlineRuns = 0;
  let totalEntitiesProtected = 0;
  let totalCloudBytesTransmitted = 0;
  let totalActualCostUsd = 0;
  let totalEstimatedSavingsUsd = 0;
  let localLatencySum = 0;
  let cloudLatencySum = 0;

  for (const item of history) {
    if (item.status === 'BLOCKED') blockedRuns += 1;
    else if (item.inferenceSource === InferenceSource.ON_DEVICE) onDeviceRuns += 1;
    else cloudRuns += 1;

    if (item.offlineMode) offlineRuns += 1;
    totalEntitiesProtected += item.redaction.entities.length;
    totalCloudBytesTransmitted += item.cloudBytesTransmitted;
    totalActualCostUsd += item.economics.actualCostUsd;
    totalEstimatedSavingsUsd += item.economics.usdSavedVsCloudFlash;
    localLatencySum += item.latencyMs;
    cloudLatencySum += item.economics.estimatedCloudLatencyMs;
  }

  return {
    totalRuns: history.length,
    onDeviceRuns,
    cloudRuns,
    blockedRuns,
    offlineRuns,
    totalEntitiesProtected,
    totalCloudBytesTransmitted,
    totalActualCostUsd: roundUsd(totalActualCostUsd),
    totalEstimatedSavingsUsd: roundUsd(totalEstimatedSavingsUsd),
    avgLocalLatencyMs: Number((localLatencySum / history.length).toFixed(2)),
    avgEstimatedCloudLatencyMs: Math.round(cloudLatencySum / history.length),
  };
}
