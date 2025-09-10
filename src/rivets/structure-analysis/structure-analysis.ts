import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { COMMON_PATTERNS } from "../../@shared/regex-patterns/common.const";

/**
 * @description
 * Analyzes input structure for suspicious patterns like excessive lines,
 * repeated characters, and unusual formatting that may indicate attacks.
 */
export function structureAnalysis(): ChainmailRivet {
  const excessiveLinesThreshold = 50;
  const nonAsciiThreshold = 0.3;
  const wordThreshold = 10;
  const uniqueWordsThreshold = 0.3;

  return async (context, next) => {
    const lines = context.sanitized.split("\n");

    if (lines.length > excessiveLinesThreshold) {
      context.flags.push(SecurityFlags.EXCESSIVE_LINES);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    const nonAscii = (context.sanitized.match(/[^\x20-\x7E]/g) || []).length;
    if (
      context.sanitized.length > 0 &&
      nonAscii / context.sanitized.length > nonAsciiThreshold
    ) {
      context.flags.push(SecurityFlags.NON_ASCII_HEAVY);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    const words = context.sanitized
      .toLowerCase()
      .split(COMMON_PATTERNS.WHITESPACE_MULTIPLE);
    const uniqueWords = new Set(words);
    if (
      words.length > wordThreshold &&
      uniqueWords.size / words.length < uniqueWordsThreshold
    ) {
      context.flags.push(SecurityFlags.REPETITIVE_CONTENT);
      applyThreatPenalty(context, ThreatLevel.LOW);
    }

    return next();
  };
}
