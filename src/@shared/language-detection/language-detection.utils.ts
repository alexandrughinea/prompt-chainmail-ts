import { CYBERCRIME_INDEX_BY_LANGUAGE } from "../../rivets/rivets.const";
import { LanguageDetector } from "./language-detection";
import { LanguageDetectionResult } from "./language-detection.types";
import {
  LANGUAGE_DETECTION_SCRIPT_RANGES,
  LANGUAGE_DETECTION_LOOKALIKE_CHARS,
} from "./language-detection.const";

export function detectLanguages(
  text: string
): Array<{ code: string; confidence: number }> {
  const detector = new LanguageDetector({
    enableMultipleDetection: true,
    minConfidence: 0.1,
  });

  const results = detector.detectMultiple(text);

  return results.map((result: LanguageDetectionResult) => ({
    code: result.language.toLowerCase(),
    confidence: result.confidence,
  }));
}

export function detectScriptMixing(text: string): boolean {
  const scripts = new Set<string>();

  for (const char of text) {
    const codePoint = char.codePointAt(0) || 0;

    for (const [script, ranges] of Object.entries(
      LANGUAGE_DETECTION_SCRIPT_RANGES
    )) {
      for (const [start, end] of ranges) {
        if (codePoint >= start && codePoint <= end) {
          scripts.add(script);
          break;
        }
      }
    }
  }

  return scripts.size > 1;
}

export function detectLookalikeChars(text: string): boolean {
  for (const char of text) {
    if (LANGUAGE_DETECTION_LOOKALIKE_CHARS.has(char)) {
      return true;
    }
  }
  return false;
}


export function normalizeText(text: string): string {
  let normalized = text.toLowerCase();

  for (const [lookalike, normal] of LANGUAGE_DETECTION_LOOKALIKE_CHARS) {
    normalized = normalized.replace(new RegExp(lookalike, "g"), normal);
  }

  return normalized.replace(/\s+/g, " ").trim();
}

export function calculateWeightedConfidence(
  baseConfidence: number,
  languages: Array<{ code: string; confidence: number }>,
  hasScriptMixing: boolean,
  hasLookalikes: boolean
): number {
  let riskMultiplier = 1.0;
  let cybercrimeScore = 0;

  if (hasScriptMixing) riskMultiplier += 0.3;
  if (hasLookalikes) riskMultiplier += 0.2;
  if (languages.length > 1) riskMultiplier += 0.1;

  const cyberCrimeValues = Object.values(CYBERCRIME_INDEX_BY_LANGUAGE);
  const maxScore = Math.max(...cyberCrimeValues);
  const minScore = Math.min(...cyberCrimeValues);

  for (const lang of languages) {
    const score =
      CYBERCRIME_INDEX_BY_LANGUAGE[lang.code as keyof typeof CYBERCRIME_INDEX_BY_LANGUAGE] || minScore;
    cybercrimeScore = Math.max(cybercrimeScore, score);
  }

  const normalizedRisk = cybercrimeScore / maxScore;
  riskMultiplier += normalizedRisk * 0.4;

  return Math.min(baseConfidence * riskMultiplier, 1.0);
}
