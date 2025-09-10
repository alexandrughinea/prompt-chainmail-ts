import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import {
  SANITIZE_HTML_TAG_PATTERN,
  SANITIZE_HTML_ENTITIES,
  SANITIZE_CONTROL_CHAR_PATTERN,
  SANITIZE_WHITESPACE_PATTERN,
  SANITIZE_CONTROL_CHAR_REPLACEMENT,
} from "./sanitize.const";

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
      context.flags.push(SecurityFlags.SANITIZED_HTML_TAGS);
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
      context.flags.push(SecurityFlags.SANITIZED_CONTROL_CHARS);
      sanitized = controlsRemoved;
    }

    const beforeWhitespace = sanitized;

    let normalizedWhitespace = sanitized;
    let match;
    while (
      (match = normalizedWhitespace.match(SANITIZE_WHITESPACE_PATTERN)) !==
        null &&
      match[0].length > 1
    ) {
      normalizedWhitespace = normalizedWhitespace.replace(
        SANITIZE_WHITESPACE_PATTERN,
        " "
      );
    }
    sanitized = normalizedWhitespace.trim();

    if (sanitized !== beforeWhitespace) {
      context.flags.push(SecurityFlags.SANITIZED_WHITESPACE);
    }

    sanitized = sanitized.slice(0, maxLength);

    if (sanitized.length < originalLength) {
      if (sanitized.length < context.input.length) {
        context.flags.push(SecurityFlags.TRUNCATED);
      }

      const sanitizationRatio =
        (originalLength - sanitized.length) / originalLength;
      if (sanitizationRatio > 0.1) {
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
      } else {
        applyThreatPenalty(context, ThreatLevel.LOW);
      }
    }

    context.sanitized = sanitized;
    return next();
  };
}
