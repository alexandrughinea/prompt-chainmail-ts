import { ChainmailRivet } from "../../index";
import { ThreatLevel } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ChainmailContext } from "../../types";

/**
 * @description
 * Creates a custom conditional rivet that applies flags and penalties
 * when a user-defined predicate function returns true.
 */
export function condition(
  predicate: (context: ChainmailContext) => boolean,
  flagName = "custom_condition",
  confidenceMultiplier = 0.8
): ChainmailRivet {
  return async (context, next) => {
    if (predicate(context)) {
      context.flags.add(flagName);
      const penalty =
        confidenceMultiplier <= 0.5
          ? ThreatLevel.HIGH
          : confidenceMultiplier <= 0.7
            ? ThreatLevel.MEDIUM
            : ThreatLevel.LOW;
      applyThreatPenalty(context, penalty);
    }
    return next();
  };
}
