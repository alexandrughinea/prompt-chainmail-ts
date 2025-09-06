import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function sanitize(maxLength = 8000): ChainmailRivet {
  return async (context, next) => {
    context.sanitized = context.sanitized
      .replace(/<[^>]*>/g, "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maxLength);

    if (context.sanitized.length < context.input.length) {
      context.flags.push(SecurityFlag.TRUNCATED);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    return next();
  };
}
