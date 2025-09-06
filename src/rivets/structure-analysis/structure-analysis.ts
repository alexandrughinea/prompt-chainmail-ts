import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function structureAnalysis(): ChainmailRivet {
  return async (context, next) => {
    const lines = context.sanitized.split("\n");

    if (lines.length > 50) {
      context.flags.push(SecurityFlag.EXCESSIVE_LINES);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    const nonAscii = (context.sanitized.match(/[^\x20-\x7E]/g) || [])
      .length;
    if (
      context.sanitized.length > 0 &&
      nonAscii / context.sanitized.length > 0.3
    ) {
      context.flags.push(SecurityFlag.NON_ASCII_HEAVY);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    const words = context.sanitized.toLowerCase().split(/\s+/);
    const uniqueWords = new Set(words);
    if (words.length > 10 && uniqueWords.size / words.length < 0.3) {
      context.flags.push(SecurityFlag.REPETITIVE_CONTENT);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    return next();
  };
}
