import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { SECURITY_COMPONENTS } from "../rivets.const";

export function encodingDetection(): ChainmailRivet {
  return async (context, next) => {
    const suspiciousKeywords = new RegExp(
      SECURITY_COMPONENTS.SUSPICIOUS,
      "i"
    );

    // Base64 detection
    const base64Match = context.sanitized.match(/[A-Za-z0-9+/=]{20,}/);
    if (base64Match && typeof Buffer !== "undefined") {
      try {
        const decoded = Buffer.from(base64Match[0], "base64").toString(
          "utf-8"
        );
        if (suspiciousKeywords.test(decoded)) {
          context.flags.push(SecurityFlag.BASE64_ENCODING);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.decodedContent = decoded.slice(0, 100);
        }
      } catch {
        // Not valid base64
      }
    }

    // Hex encoding detection
    if (/(?:0x)?[0-9a-fA-F\s]{20,}/.test(context.sanitized)) {
      context.flags.push(SecurityFlag.HEX_ENCODING);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
    }

    // URL encoding detection
    const urlEncodedMatch = context.sanitized.match(
      /(%[0-9a-fA-F]{2}){4,}/g
    );
    if (urlEncodedMatch) {
      try {
        const decoded = decodeURIComponent(urlEncodedMatch[0]);
        if (suspiciousKeywords.test(decoded)) {
          context.flags.push(SecurityFlag.URL_ENCODING);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.urlDecodedContent = decoded.slice(0, 100);
        }
      } catch {
        // Invalid URL encoding
      }
    }

    // Unicode escape detection
    if (/\\u[0-9a-fA-F]{4}/.test(context.sanitized)) {
      try {
        const decoded = context.sanitized.replace(
          /\\u([0-9a-fA-F]{4})/g,
          (_, code) => String.fromCharCode(parseInt(code, 16))
        );
        if (suspiciousKeywords.test(decoded)) {
          context.flags.push(SecurityFlag.UNICODE_ENCODING);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.unicodeDecodedContent = decoded.slice(0, 100);
        }
      } catch {
        // Invalid unicode
      }
    }

    // HTML entity detection
    if (
      /&#\d{2,3};/.test(context.sanitized) ||
      /&[a-zA-Z]+;/.test(context.sanitized)
    ) {
      const decoded = context.sanitized
        .replace(/&#(\d+);/g, (_, code) =>
          String.fromCharCode(parseInt(code, 10))
        )
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#x27;/g, "'");

      if (suspiciousKeywords.test(decoded)) {
        context.flags.push(SecurityFlag.HTML_ENTITY_ENCODING);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.htmlDecodedContent = decoded.slice(0, 100);
      }
    }

    // Binary encoding detection
    if (/^[01\s]{32,}$/.test(context.sanitized.trim())) {
      try {
        const binaryString = context.sanitized.replace(/\s/g, "");
        const decoded =
          binaryString
            .match(/.{8}/g)
            ?.map((byte) => String.fromCharCode(parseInt(byte, 2)))
            .join("") || "";

        if (suspiciousKeywords.test(decoded)) {
          context.flags.push(SecurityFlag.BINARY_ENCODING);
          applyThreatPenalty(context, ThreatLevel.HIGH);
          context.metadata.binaryDecodedContent = decoded.slice(0, 100);
        }
      } catch {
        // Invalid binary
      }
    }

    // Octal encoding detection
    if (/\\[0-7]{3}/.test(context.sanitized)) {
      try {
        const decoded = context.sanitized.replace(
          /\\([0-7]{3})/g,
          (_, octal) => String.fromCharCode(parseInt(octal, 8))
        );
        if (suspiciousKeywords.test(decoded)) {
          context.flags.push(SecurityFlag.OCTAL_ENCODING);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.octalDecodedContent = decoded.slice(0, 100);
        }
      } catch {
        // Invalid octal
      }
    }

    // ROT13 detection
    const rot13Decoded = context.sanitized.replace(
      /[a-zA-Z]/g,
      (char) => {
        const start = char <= "Z" ? 65 : 97;
        return String.fromCharCode(
          ((char.charCodeAt(0) - start + 13) % 26) + start
        );
      }
    );
    if (
      rot13Decoded !== context.sanitized &&
      suspiciousKeywords.test(rot13Decoded)
    ) {
      context.flags.push(SecurityFlag.ROT13_ENCODING);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
      context.metadata.rot13DecodedContent = rot13Decoded.slice(0, 100);
    }

    // Mixed case obfuscation detection
    const words = context.sanitized.split(/\s+/);
    const mixedCaseWords = words.filter((word) => {
      if (word.length < 4) return false;
      const upperCount = (word.match(/[A-Z]/g) || []).length;
      const lowerCount = (word.match(/[a-z]/g) || []).length;
      return (
        upperCount > 0 && lowerCount > 0 && upperCount / word.length > 0.3
      );
    });

    if (mixedCaseWords.length > 2) {
      context.flags.push(SecurityFlag.MIXED_CASE_OBFUSCATION);
      applyThreatPenalty(context, ThreatLevel.MEDIUM);
      context.metadata.mixedCaseWords = mixedCaseWords.slice(0, 5);
    }

    return next();
  };
}
