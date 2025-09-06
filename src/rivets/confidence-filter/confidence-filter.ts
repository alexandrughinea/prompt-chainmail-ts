import { ChainmailRivet } from "../../index";
import { SecurityFlag } from "../rivets.types";

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
        context.flags.push(SecurityFlag.CONFIDENCE_RANGE);
      }
    } else {
      if (context.confidence < minThreshold) {
        context.blocked = true;
        context.flags.push(SecurityFlag.LOW_CONFIDENCE);
      }
    }

    return next();
  };
}
