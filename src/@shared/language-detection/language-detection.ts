import { francAll } from "franc";
import {
  LANGUAGE_DETECTION_COMBINING_DIACRITICS_REGEX,
  LANGUAGE_DETECTION_COMMON_PUNCTUATION_REGEX,
  LANGUAGE_DETECTION_LOOKALIKE_CHARS,
  LANGUAGE_DETECTION_MULTIPLE_SPACES_REGEX,
  LANGUAGE_DETECTION_OBFUSCATION_PATTERN_REGEX,
  LANGUAGE_DETECTION_OPERATORS_AND_PIPES_REGEX,
  LANGUAGE_DETECTION_SEPARATORS_REGEX,
} from "./language-detection.const";

/**
 * @description
 * - Normalizes the input text by removing diacritics, converting to lowercase, and removing obfuscation patterns.
 * - Handles Cyrillic characters and lookalike character replacements.
 */
export function normalizeText(text: string): string {
  const spaceChar = " ";
  const emptyChar = "";

  let normalized = text
    .toLowerCase()
    .normalize("NFD")
    .replace(LANGUAGE_DETECTION_COMBINING_DIACRITICS_REGEX, emptyChar) // Remove combining diacritics
    .replace(LANGUAGE_DETECTION_COMMON_PUNCTUATION_REGEX, spaceChar) // Common punctuation
    .replace(LANGUAGE_DETECTION_OPERATORS_AND_PIPES_REGEX, spaceChar) // Operators and pipes
    .replace(
      new RegExp(LANGUAGE_DETECTION_MULTIPLE_SPACES_REGEX.source, "g"),
      spaceChar
    ) // Space normalization
    .replace(LANGUAGE_DETECTION_OBFUSCATION_PATTERN_REGEX, (match) => {
      return match.replace(LANGUAGE_DETECTION_SEPARATORS_REGEX, emptyChar); // Remove obfuscation patterns
    })
    .trim();

  const hasCyrillic = /[\u0400-\u04FF]/.test(normalized);

  if (!hasCyrillic) {
    for (const [lookalike, replacement] of LANGUAGE_DETECTION_LOOKALIKE_CHARS) {
      normalized = normalized.replace(new RegExp(lookalike, "g"), replacement);
    }
  }

  return normalized;
}

export function hasLanguageScriptMixing(text: string): boolean {
  const scripts = new Set<string>();

  for (const char of text) {
    const code = char.codePointAt(0);
    if (!code) continue;

    if (code >= 0x0000 && code <= 0x007f) scripts.add("Latin");
    else if (code >= 0x0400 && code <= 0x04ff) scripts.add("Cyrillic");
    else if (code >= 0x0370 && code <= 0x03ff) scripts.add("Greek");
    else if (code >= 0x0590 && code <= 0x05ff) scripts.add("Hebrew");
    else if (code >= 0x0600 && code <= 0x06ff) scripts.add("Arabic");
    else if (code >= 0x4e00 && code <= 0x9fff) scripts.add("CJK");
    else if (code >= 0x3040 && code <= 0x309f) scripts.add("Hiragana");
    else if (code >= 0x30a0 && code <= 0x30ff) scripts.add("Katakana");
    else if (code >= 0x0900 && code <= 0x097f) scripts.add("Devanagari");
  }

  return scripts.size > 1;
}

export function detectLookalikeChars(text: string): boolean {
  for (const [lookalike] of LANGUAGE_DETECTION_LOOKALIKE_CHARS) {
    if (text.includes(lookalike)) {
      return true;
    }
  }
  return false;
}

export class LanguageDetector {
  detect(
    text: string,
    options?: { only?: string[]; ignore?: string[] }
  ): Array<[string, number]> {
    const normalizedText = normalizeText(text);
    return francAll(normalizedText, options);
  }
}
