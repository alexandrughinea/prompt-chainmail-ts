export { LanguageDetector } from "./language-detection";
export type {
  LanguageDetectionResult,
  LanguageDetectionOptions,
} from "./language-detection.types";
export {
  LANGUAGE_PATTERNS,
} from "./language-detection.const";
export {
  detectLanguages,
  detectScriptMixing,
  detectLookalikeChars,
  scriptToLanguage,
  normalizeText,
  calculateWeightedConfidence,
} from "./language-detection.utils";
