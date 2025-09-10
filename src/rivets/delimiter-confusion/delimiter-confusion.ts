import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { DELIMITER_CONFUSION_REGEX } from "./delimiter-confusion.const";

/**
 * @description
 * Detects attempts to confuse or break prompt delimiters using
 * fake end tags, triple quotes, and other boundary manipulation techniques.
 */
export function delimiterConfusion(): ChainmailRivet {
  return async (context, next) => {
    for (const pattern of DELIMITER_CONFUSION_REGEX) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlags.DELIMITER_CONFUSION);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.delimiter_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
