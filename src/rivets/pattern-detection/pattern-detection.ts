import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { createPatternDetectionPatterns } from "./pattern-detection.utils";

export function patternDetection(customPatterns?: RegExp[]): ChainmailRivet {
  const patterns = [
    ...createPatternDetectionPatterns(),
    ...(customPatterns || []),
  ];

  return async (context, next) => {
    for (const pattern of patterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlag.INJECTION_PATTERN);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.matched_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
