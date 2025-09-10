import { ChainmailRivet, ChainmailContext, ChainmailResult } from "../../types";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import {
  COMMON_PATTERNS,
  HTML_ENTITIES,
  ENCODING_PATTERNS,
} from "../../@shared/regex-patterns/common.const";

/**
 * @description
 * Detects encoded malicious content including base64, URL encoding,
 * and other obfuscation techniques used to bypass security filters.
 */
export function encodingDetection(): ChainmailRivet {
  return async (
    context: ChainmailContext,
    next: () => Promise<ChainmailResult>
  ): Promise<ChainmailResult> => {
    // Base64 detection
    const base64Match = context.sanitized.match(ENCODING_PATTERNS.BASE64);

    if (base64Match && typeof Buffer !== "undefined") {
      try {
        const decoded = Buffer.from(base64Match[0], "base64").toString("utf-8");
        context.flags.push(SecurityFlags.BASE64_ENCODING);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.decoded_content = decoded.slice(0, 100);
      } catch {
        // Not valid base64
      }
    }

    // Hex encoding detection
    if (ENCODING_PATTERNS.HEX_ESCAPE.test(context.sanitized)) {
      context.flags.push(SecurityFlags.HEX_ENCODING);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
    }

    // URL encoding detection
    const urlEncodedMatch = context.sanitized.match(
      ENCODING_PATTERNS.URL_ESCAPE
    );
    if (urlEncodedMatch) {
      try {
        const decoded = decodeURIComponent(urlEncodedMatch[0]);
        context.flags.push(SecurityFlags.URL_ENCODING);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.url_decoded_content = decoded.slice(0, 100);
      } catch {
        // Invalid URL encoding
      }
    }

    // Unicode escape detection
    if (ENCODING_PATTERNS.UNICODE_ESCAPE_REGEX.test(context.sanitized)) {
      try {
        let decoded = context.sanitized;
        let match;
        while (
          (match = decoded.match(ENCODING_PATTERNS.UNICODE_ESCAPE)) !== null
        ) {
          decoded = decoded.replace(
            match[0],
            String.fromCharCode(parseInt(match[1], 16))
          );
        }
        context.flags.push(SecurityFlags.UNICODE_ENCODING);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.unicode_decoded_content = decoded.slice(0, 100);
      } catch {
        // Invalid unicode
      }
    }

    // HTML entity detection
    if (
      HTML_ENTITIES.NUMERIC_DETECTION.test(context.sanitized) ||
      HTML_ENTITIES.NAMED_DETECTION.test(context.sanitized)
    ) {
      let decoded = context.sanitized;
      let match;
      while ((match = decoded.match(HTML_ENTITIES.NUMERIC)) !== null) {
        decoded = decoded.replace(
          match[0],
          String.fromCharCode(parseInt(match[1], 10))
        );
      }
      decoded = decoded
        .replace(HTML_ENTITIES.LT, "<")
        .replace(HTML_ENTITIES.GT, ">")
        .replace(HTML_ENTITIES.AMP, "&")
        .replace(HTML_ENTITIES.QUOT, '"')
        .replace(HTML_ENTITIES.APOS, "'");

      context.flags.push(SecurityFlags.HTML_ENTITY_ENCODING);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
      context.metadata.html_decoded_content = decoded.slice(0, 100);
    }

    // Binary encoding detection
    if (ENCODING_PATTERNS.BINARY.test(context.sanitized.trim())) {
      try {
        let binaryString = context.sanitized;
        while (COMMON_PATTERNS.WHITESPACE.test(binaryString)) {
          binaryString = binaryString.replace(COMMON_PATTERNS.WHITESPACE, "");
        }
        const chunks = [];
        for (let i = 0; i < binaryString.length; i += 8) {
          chunks.push(binaryString.substr(i, 8));
        }
        const decoded = chunks
          .filter((chunk) => chunk.length === 8)
          .map((byte) => String.fromCharCode(parseInt(byte, 2)))
          .join("");

        context.flags.push(SecurityFlags.BINARY_ENCODING);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.binary_decoded_content = decoded.slice(0, 100);
      } catch {
        // Invalid binary
      }
    }

    // Octal encoding detection
    if (ENCODING_PATTERNS.OCTAL.test(context.sanitized)) {
      try {
        let decoded = context.sanitized;
        let match;
        while (
          (match = decoded.match(ENCODING_PATTERNS.OCTAL_ESCAPE)) !== null
        ) {
          decoded = decoded.replace(
            match[0],
            String.fromCharCode(parseInt(match[1], 8))
          );
        }
        context.flags.push(SecurityFlags.OCTAL_ENCODING);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.octal_decoded_content = decoded.slice(0, 100);
      } catch {
        // Invalid octal
      }
    }

    // ROT13 detection - only flag if input appears to be intentionally encoded
    let rot13Decoded = "";
    for (let i = 0; i < context.sanitized.length; i++) {
      const char = context.sanitized[i];
      if (COMMON_PATTERNS.ALPHABETIC.test(char)) {
        const start = char <= "Z" ? 65 : 97;
        rot13Decoded += String.fromCharCode(
          ((char.charCodeAt(0) - start + 13) % 26) + start
        );
      } else {
        rot13Decoded += char;
      }
    }

    // Only flag if the original text contains suspicious patterns that suggest intentional encoding
    const hasNonWords = /[^\p{L}\p{N}\s]/u.test(context.sanitized);
    const hasConsecutiveConsonants =
      /[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{4,}/.test(
        context.sanitized
      );
    const isLikelyEncoded =
      hasNonWords || hasConsecutiveConsonants || context.sanitized.length > 50;

    if (rot13Decoded !== context.sanitized && isLikelyEncoded) {
      context.flags.push(SecurityFlags.ROT13_ENCODING);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
      context.metadata.rot13_decoded_content = rot13Decoded.slice(0, 100);
    }

    // Mixed case obfuscation detection
    const words = context.sanitized.split(
      new RegExp(COMMON_PATTERNS.WHITESPACE_MULTIPLE.source, "g")
    );
    const mixedCaseWords = words.filter((word) => {
      if (word.length < 4) return false;
      const upperMatches = word.match(
        new RegExp(COMMON_PATTERNS.UPPERCASE.source, "g")
      );
      const lowerMatches = word.match(
        new RegExp(COMMON_PATTERNS.LOWERCASE.source, "g")
      );
      const upperCount = upperMatches ? upperMatches.length : 0;
      const lowerCount = lowerMatches ? lowerMatches.length : 0;
      return upperCount > 0 && lowerCount > 0 && upperCount / word.length > 0.3;
    });

    if (mixedCaseWords.length > 2) {
      context.flags.push(SecurityFlags.MIXED_CASE_OBFUSCATION);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
      context.metadata.mixed_case_words = mixedCaseWords.slice(0, 5);
    }

    return await next();
  };
}
