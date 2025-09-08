import { ChainmailRivet } from "../../index";
import { SecurityFlags } from "../rivets.types";

/**
 * @description
 * Filters requests based on confidence thresholds, flagging content
 * with confidence scores outside the specified range.
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
        context.flags.push(SecurityFlags.CONFIDENCE_RANGE);
      }
    } else {
      if (context.confidence < minThreshold) {
        context.blocked = true;
        context.flags.push(SecurityFlags.LOW_CONFIDENCE);
      }
    }

    return next();
  };
}
