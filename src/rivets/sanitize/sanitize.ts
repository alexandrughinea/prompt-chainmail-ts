import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import {
  SANITIZE_HTML_TAG_PATTERN,
  SANITIZE_HTML_ENTITIES,
  SANITIZE_CONTROL_CHAR_PATTERN,
  SANITIZE_CONTROL_CHAR_REPLACEMENT,
} from "./sanitize.const";
import { COMMON_PATTERNS } from "../../@shared/regex-patterns/common.const";

/**
 * @description
 * Sanitizes input by removing HTML tags, normalizing whitespace,
 * removing control characters, and enforcing length limits to prevent processing abuse.
 */
export function sanitize(maxLength = 8000): ChainmailRivet {
  return async (context, next) => {
    let sanitized = context.sanitized;
    const originalLength = sanitized.length;

    // Remove HTML tags
    let sanitizedHTML = sanitized;
    while (SANITIZE_HTML_TAG_PATTERN.test(sanitizedHTML)) {
      sanitizedHTML = sanitizedHTML.replace(SANITIZE_HTML_TAG_PATTERN, "");
    }

    if (sanitizedHTML !== sanitized) {
      context.flags.add(SecurityFlags.SANITIZED_HTML_TAGS);
      sanitized = sanitizedHTML;
    }

    sanitized = sanitized
      .replace(SANITIZE_HTML_ENTITIES.AMP, "&")
      .replace(SANITIZE_HTML_ENTITIES.LT, "<")
      .replace(SANITIZE_HTML_ENTITIES.GT, ">")
      .replace(SANITIZE_HTML_ENTITIES.QUOT, '"')
      .replace(SANITIZE_HTML_ENTITIES.APOS, "'");

    let controlsRemoved = sanitized;
    while (SANITIZE_CONTROL_CHAR_PATTERN.test(controlsRemoved)) {
      controlsRemoved = controlsRemoved.replace(
        SANITIZE_CONTROL_CHAR_PATTERN,
        SANITIZE_CONTROL_CHAR_REPLACEMENT
      );
    }

    if (controlsRemoved !== sanitized) {
      context.flags.add(SecurityFlags.SANITIZED_CONTROL_CHARS);
      sanitized = controlsRemoved;
    }

    const beforeWhitespace = sanitized;

    let normalizedWhitespace = sanitized;
    let match;
    while (
      (match = normalizedWhitespace.match(
        COMMON_PATTERNS.WHITESPACE_MULTIPLE
      )) !== null &&
      match[0].length > 1
    ) {
      normalizedWhitespace = normalizedWhitespace.replace(
        COMMON_PATTERNS.WHITESPACE_MULTIPLE,
        " "
      );
    }
    sanitized = normalizedWhitespace.trim();

    if (sanitized !== beforeWhitespace) {
      context.flags.add(SecurityFlags.SANITIZED_WHITESPACE);
    }

    sanitized = sanitized.slice(0, maxLength);

    if (sanitized.length < originalLength) {
      if (sanitized.length < context.input.length) {
        context.flags.add(SecurityFlags.SANITIZED_CONTROL_CHARS);
      }

      const sanitizationRatio =
        (originalLength - sanitized.length) / originalLength;
      if (sanitizationRatio > 0.1) {
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
      } else {
        applyThreatPenalty(context, ThreatLevel.LOW);
      }
    }

    if (sanitized.length < context.input.length) {
      context.flags.add(SecurityFlags.TRUNCATED);
    }

    context.sanitized = sanitized;
    return next();
  };
}
