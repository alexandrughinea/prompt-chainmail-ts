export enum SupportedLanguages {
  EN = 'en', // English
  FR = 'fr', // French
  DE = 'de', // Deutsch
  ES = 'es', // Spanish
  IT = 'it', // Italian
  JA = 'ja', // Japanese
  KO = 'ko', // Korean
  PT = 'pt', // Portuguese
  RU = 'ru', // Russian
  ZH = 'zh', // Chinese
  AR = 'ar', // Arabic
  UK = 'uk', // Ukrainian
  RO = 'ro', // Romanian
  HI = 'hi', // Hindi
  FA = 'fa', // Persian/Farsi
  BE = 'be', // Belarusian
  HE = 'he', // Hebrew
  PL = 'pl', // Polish
  NL = 'nl', // Dutch
  LV = 'lv', // Latvian
}

export interface LanguageDetectionResult {
  language: SupportedLanguages;
  confidence: number;
  detectionMethod: DetectionMethod;
}

export enum DetectionMethod {
  PATTERN_MATCHING = 'pattern_matching',
  CHARACTER_FREQUENCY = 'character_frequency',
  WORD_FREQUENCY = 'word_frequency',
  SCRIPT_DETECTION = 'script_detection',
  COMBINED = 'combined',
}

export interface LanguageDetectionOptions {
  minConfidence?: number;
  fallbackLanguage?: SupportedLanguages;
  enableMultipleDetection?: boolean;
  maxTextLength?: number;
}

export interface LanguagePattern {
  language: SupportedLanguages;
  patterns: RegExp[];
  commonWords: string[];
  characterRanges: Array<[number, number]>;
  weight: number;
}
