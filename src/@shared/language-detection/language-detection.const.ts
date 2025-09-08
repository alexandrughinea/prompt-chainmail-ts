import languagePatternsData from '../../@configs/language_patterns.json';
import { SupportedLanguages, LanguagePattern } from './language-detection.types';

const createLanguagePatterns = (): Record<SupportedLanguages, LanguagePattern> => {
  const patterns: Record<string, LanguagePattern> = {};
  
  Object.entries(languagePatternsData).forEach(([key, value]) => {
    const langKey = SupportedLanguages[key as keyof typeof SupportedLanguages];
    
    patterns[langKey] = {
      language: langKey,
      patterns: value.patterns.map(pattern => new RegExp(pattern, 'gi')),
      commonWords: value.commonWords,
      characterRanges: value.characterRanges as [number, number][],
      bigrams: (value as any).bigrams || [],
      trigrams: (value as any).trigrams || []
    };
  });
  
  return patterns as Record<SupportedLanguages, LanguagePattern>;
};

export const LANGUAGE_PATTERNS = createLanguagePatterns();

export const LANGUAGE_DETECTION_SCRIPT_RANGES = {
  latin: [
    [0x0041, 0x005a],
    [0x0061, 0x007a],
    [0x00c0, 0x024f],
  ],
  cyrillic: [
    [0x0400, 0x04ff],
    [0x0500, 0x052f],
  ],
  chinese: [
    [0x4e00, 0x9fff],
    [0x3400, 0x4dbf],
  ],
  arabic: [
    [0x0600, 0x06ff],
    [0x0750, 0x077f],
  ],
  japanese: [
    [0x3040, 0x309f],
    [0x30a0, 0x30ff],
  ],
  korean: [
    [0xac00, 0xd7af],
    [0x1100, 0x11ff],
  ],
  hebrew: [[0x0590, 0x05ff]],
  greek: [[0x0370, 0x03ff]],
} as const;

export const LANGUAGE_DETECTION_DEFAULT_DETECTION_OPTIONS = {
  minConfidence: 0.3,
  fallbackLanguage: SupportedLanguages.EN,
  enableMultipleDetection: false,
  maxTextLength: 10000,
};


export const CYBERCRIME_INDEX = {
  [SupportedLanguages.RU]: 58.39,
  "uk": 36.44,
  "zh": 27.86,
  "en": 25.01,
  "ro": 14.83,
  "ko": 10.61,
  "pt": 8.93,
  "hi": 6.13,
  "fa": 4.78,
  "be": 3.87,
  "he": 2.51,
  "pl": 2.22,
  "de": 2.17,
  "nl": 1.92,
  "lv": 1.68
} as const;

export const LANGUAGE_DETECTION_LOOKALIKE_CHARS = new Map([
  ["а", "a"],
  ["е", "e"],
  ["о", "o"],
  ["р", "p"],
  ["с", "c"],
  ["х", "x"],
  ["А", "A"],
  ["В", "B"],
  ["Е", "E"],
  ["К", "K"],
  ["М", "M"],
  ["О", "O"],
  ["α", "a"],
  ["ο", "o"],
  ["ρ", "p"],
  ["Α", "A"],
  ["Β", "B"],
  ["Ο", "O"],
]);
