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
  SCRIPT_DETECTION = 'script',
  PATTERN_MATCHING = 'pattern',
  WORD_FREQUENCY = 'word',
  CHARACTER_FREQUENCY = 'character',
  NGRAM_ANALYSIS = 'ngram',
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
  bigrams?: string[];
  trigrams?: string[];
}
