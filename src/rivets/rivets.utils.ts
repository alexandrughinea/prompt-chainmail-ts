import { ChainmailContext } from "../types";
import { ThreatLevel } from "./rivets.types";

/**
 * @description
 * Simple penalty system that reduces confidence based on security threats:
 *
 * Steps:
 * 1. Get base penalty from threat type and current confidence
 * 2. Reduce penalty if content is long (less strict for longer text)
 * 3. Reduce penalty if many flags found (avoids over-penalizing)
 * 4. Apply final penalty and keep confidence above 0.0
 *
 * - Long content: up to 50% less penalty (reduces false positives)
 * - Multiple flags: up to 70% less penalty per extra flag
 */
export function applyThreatPenalty(
  context: ChainmailContext,
  level: ThreatLevel
): void {
  const confidence = Number.isFinite(context.confidence)
    ? context.confidence
    : 1.0;
  const basePenalty = Number.isFinite(level) ? level : 0;
  const globalSeverityMultiplier = 1.0;

  let adjustedPenalty = basePenalty * globalSeverityMultiplier;

  const flagCount = context.flags.size;
  const flagScaling = Math.max(0.3, 1 - flagCount * 0.1);
  adjustedPenalty *= flagScaling;

  const contentLength = context.sanitized?.length || 0;
  if (contentLength > 1000) {
    const lengthScaling = Math.max(0.5, 1 - contentLength / 10000);
    adjustedPenalty *= lengthScaling;
  }

  const result = Math.max(0, confidence - adjustedPenalty);

  context.confidence = Math.round(result * 1000) / 1000;
}
