import { ChainmailRivet } from "../../index";

/**
 * @description
 * - Blocks requests based on confidence thresholds.
 * - When only minThreshold is provided,
 *   blocks content with confidence below the threshold (low confidence = suspicious).
 * - When both thresholds are provided, blocks content within the range (confidence
 *   between min and max is considered risky).
 *
 * - Sets `context.blocked` = true when blocking conditions are met.
 *
 * @param minThreshold Minimum confidence threshold (default: 0.5)
 * @param maxThreshold Optional maximum confidence threshold for range filtering
 */
export function confidenceFilter(
  minThreshold = 0.5,
  maxThreshold?: number
): ChainmailRivet {
  return async (context, next) => {
    const shouldBlock = maxThreshold
      ? context.confidence >= minThreshold && context.confidence <= maxThreshold
      : context.confidence < minThreshold;

    if (shouldBlock) {
      context.blocked = true;
    }

    return next();
  };
}
