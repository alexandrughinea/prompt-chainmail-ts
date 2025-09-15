import { ChainmailRivet } from "../../index";
import { SecurityFlags } from "../rivets.types";

/**
 * @description
 * - Blocks requests based on confidence thresholds.
 * - When only minThreshold is provided,
 *   blocks content with confidence below the threshold (low confidence = suspicious).
 * - When both thresholds are provided, blocks content within the range (confidence
 *   between min and max is considered risky).
 *
 * - Sets `context.blocked` = true and adds
 *   appropriate security flag (`LOW_CONFIDENCE` or `CONFIDENCE_RANGE) when blocking conditions are met.
 *
 * @param minThreshold Minimum confidence threshold (default: 0.5)
 * @param maxThreshold Optional maximum confidence threshold for range filtering
 */
export function confidenceFilter(
  minThreshold = 0.5,
  maxThreshold?: number
): ChainmailRivet {
  return async (context, next) => {
    if (maxThreshold) {
      if (
        context.confidence >= minThreshold &&
        context.confidence <= maxThreshold
      ) {
        context.blocked = true;
        context.flags.add(SecurityFlags.CONFIDENCE_RANGE);
      }
    } else {
      if (context.confidence < minThreshold) {
        context.blocked = true;
        context.flags.add(SecurityFlags.LOW_CONFIDENCE);
      }
    }

    return next();
  };
}
