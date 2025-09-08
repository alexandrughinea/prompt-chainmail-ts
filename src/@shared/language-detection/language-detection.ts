import {
  SupportedLanguages,
  LanguageDetectionResult,
  LanguageDetectionOptions,
  DetectionMethod,
  LanguagePattern,
} from "./language-detection.types";
import {
  LANGUAGE_PATTERNS,
  LANGUAGE_DETECTION_DEFAULT_DETECTION_OPTIONS,
  CYBERCRIME_INDEX,
} from "./language-detection.const";
import { normalizeText } from './language-detection.utils';

export class LanguageDetector {
  private options: Required<LanguageDetectionOptions>;

  constructor(options?: LanguageDetectionOptions) {
    this.options = {
      ...LANGUAGE_DETECTION_DEFAULT_DETECTION_OPTIONS,
      ...options,
    };
  }

  detect(text: string): LanguageDetectionResult | LanguageDetectionResult[] {
    if (text.trim().length <= 2) {
      const fallbackResult = {
        language: this.options.fallbackLanguage,
        confidence: 0,
        detectionMethod: DetectionMethod.COMBINED,
      };
      return this.options.enableMultipleDetection ? [fallbackResult] : fallbackResult;
    }

    let processedText = text;
    if (processedText.length > this.options.maxTextLength) {
      processedText = processedText.substring(0, this.options.maxTextLength);
    }
    const normalizedText = normalizeText(processedText);
    const results = this.runAllDetectionMethods(normalizedText);

    if (this.options.enableMultipleDetection) {
      return Object.values(results)
        .filter((result) => result.confidence >= this.options.minConfidence)
        .sort((a, b) => b.confidence - a.confidence)
        .slice(0, 3);
    }

    const combinedResult = this.combineResults(results);

    if (combinedResult.confidence < this.options.minConfidence) {
      return {
        language: this.options.fallbackLanguage,
        confidence: combinedResult.confidence,
        detectionMethod: DetectionMethod.COMBINED,
      };
    }

    return combinedResult;
  }

  getCybercrimeRisk(language: SupportedLanguages): number {
    return (CYBERCRIME_INDEX as Record<string, number>)[language] || 0;
  }


  private runAllDetectionMethods(
    text: string
  ): Record<DetectionMethod, LanguageDetectionResult> {
    return {
      [DetectionMethod.SCRIPT_DETECTION]: this.detectByScript(text),
      [DetectionMethod.PATTERN_MATCHING]: this.detectByPatterns(text),
      [DetectionMethod.WORD_FREQUENCY]: this.detectByWordFrequency(text),
      [DetectionMethod.CHARACTER_FREQUENCY]:
        this.detectByCharacterFrequency(text),
      [DetectionMethod.NGRAM_ANALYSIS]: this.detectByNgrams(text),
      [DetectionMethod.COMBINED]: this.detectByCombined(text),
    };
  }

  private detectByScript(text: string): LanguageDetectionResult {
    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let score = 0;

      for (const [start, end] of pattern.characterRanges) {
        for (let i = 0; i < text.length; i++) {
          const charCode = text.charCodeAt(i);
          if (charCode >= start && charCode <= end) {
            score++;
          }
        }
      }

      scores[language] = text.length > 0 ? score / text.length : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.SCRIPT_DETECTION,
    };
  }

  private detectByPatterns(text: string): LanguageDetectionResult {
    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let matches = 0;

      for (const regex of pattern.patterns) {
        const patternMatches = text.match(regex);
        if (patternMatches) {
          matches += patternMatches.length;
        }
      }

      const words = text.split(/\s+/);
      scores[language] = words.length > 0 ? matches / words.length : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.PATTERN_MATCHING,
    };
  }

  private detectByWordFrequency(text: string): LanguageDetectionResult {
    const words = text.toLowerCase().split(/\s+/);
    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let matches = 0;

      for (const word of words) {
        if (pattern.commonWords.includes(word)) {
          matches++;
        }
      }

      scores[language] = words.length > 0 ? matches / words.length : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.WORD_FREQUENCY,
    };
  }

  private detectByCharacterFrequency(text: string): LanguageDetectionResult {
    const charFreq: Record<string, number> = {};

    for (const char of text.toLowerCase()) {
      charFreq[char] = (charFreq[char] || 0) + 1;
    }

    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let score = 0;

      for (const word of pattern.commonWords) {
        for (const char of word) {
          if (charFreq[char]) {
            score += charFreq[char];
          }
        }
      }

      scores[language] = text.length > 0 ? score / text.length : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score * 0.5, 1.0),
      detectionMethod: DetectionMethod.CHARACTER_FREQUENCY,
    };
  }

  private detectByNgrams(text: string): LanguageDetectionResult {
    const normalizedText = text
      .toLowerCase()
      .replace(
        /[^a-zA-ZÀ-ÿĀ-žА-я\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]/g,
        ""
      );
    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let bigramScore = 0;
      let trigramScore = 0;
      let totalBigrams = 0;
      let totalTrigrams = 0;

      if (pattern.bigrams && normalizedText.length >= 2) {
        for (let i = 0; i < normalizedText.length - 1; i++) {
          const bigram = normalizedText.substring(i, i + 2);
          totalBigrams++;
          if (pattern.bigrams.includes(bigram)) {
            bigramScore++;
          }
        }
      }

      if (pattern.trigrams && normalizedText.length >= 3) {
        for (let i = 0; i < normalizedText.length - 2; i++) {
          const trigram = normalizedText.substring(i, i + 3);
          totalTrigrams++;
          if (pattern.trigrams.includes(trigram)) {
            trigramScore++;
          }
        }
      }

      const bigramConfidence =
        totalBigrams > 0 ? bigramScore / totalBigrams : 0;
      const trigramConfidence =
        totalTrigrams > 0 ? trigramScore / totalTrigrams : 0;
      const combinedScore = bigramConfidence * 0.4 + trigramConfidence * 0.6;

      scores[language] = combinedScore;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.NGRAM_ANALYSIS,
    };
  }

  private detectByCombined(text: string): LanguageDetectionResult {
    const combinedScores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    for (const lang of Object.values(SupportedLanguages)) {
      combinedScores[lang] = 0;
    }

    const scriptScores = this.getAllScores(
      text,
      DetectionMethod.SCRIPT_DETECTION
    );
    const patternScores = this.getAllScores(
      text,
      DetectionMethod.PATTERN_MATCHING
    );
    const wordScores = this.getAllScores(text, DetectionMethod.WORD_FREQUENCY);
    const charScores = this.getAllScores(
      text,
      DetectionMethod.CHARACTER_FREQUENCY
    );
    const ngramScores = this.getAllScores(text, DetectionMethod.NGRAM_ANALYSIS);

    const weights = {
      [DetectionMethod.SCRIPT_DETECTION]: 0.15,
      [DetectionMethod.PATTERN_MATCHING]: 0.25,
      [DetectionMethod.WORD_FREQUENCY]: 0.2,
      [DetectionMethod.CHARACTER_FREQUENCY]: 0.05,
      [DetectionMethod.NGRAM_ANALYSIS]: 0.35,
    };

    for (const lang of Object.values(SupportedLanguages)) {
      const scriptScore = scriptScores[lang] || 0;
      const patternScore = patternScores[lang] || 0;
      const wordScore = wordScores[lang] || 0;
      const charScore = charScores[lang] || 0;
      const ngramScore = ngramScores[lang] || 0;

      // Only consider languages with some evidence, with lower threshold for very short text
      const totalEvidence = scriptScore + patternScore + wordScore + ngramScore;
      const minThreshold = text.trim().length <= 2 ? 0.001 : 0.01;
      if (totalEvidence > minThreshold) {
        combinedScores[lang] =
          scriptScore * weights[DetectionMethod.SCRIPT_DETECTION] +
          patternScore * weights[DetectionMethod.PATTERN_MATCHING] +
          wordScore * weights[DetectionMethod.WORD_FREQUENCY] +
          charScore * weights[DetectionMethod.CHARACTER_FREQUENCY] +
          ngramScore * weights[DetectionMethod.NGRAM_ANALYSIS];
      }
    }

    const bestMatch = this.getBestMatch(combinedScores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.COMBINED,
    };
  }

  private getAllScores(
    text: string,
    method: DetectionMethod
  ): Record<SupportedLanguages, number> {
    const scores: Record<SupportedLanguages, number> = {} as Record<
      SupportedLanguages,
      number
    >;

    switch (method) {
      case DetectionMethod.SCRIPT_DETECTION:
        for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
          const language = lang as SupportedLanguages;
          let score = 0;
          for (const [start, end] of pattern.characterRanges) {
            for (let i = 0; i < text.length; i++) {
              const charCode = text.charCodeAt(i);
              if (charCode >= start && charCode <= end) {
                score++;
              }
            }
          }
          scores[language] = text.length > 0 ? score / text.length : 0;
        }
        break;

      case DetectionMethod.PATTERN_MATCHING:
        for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
          const language = lang as SupportedLanguages;
          let matches = 0;
          for (const regex of pattern.patterns) {
            const patternMatches = text.match(regex);
            if (patternMatches) {
              matches += patternMatches.length;
            }
          }
          const words = text.split(/\s+/);
          scores[language] = words.length > 0 ? matches / words.length : 0;
        }
        break;

      case DetectionMethod.WORD_FREQUENCY: {
        const words = text.toLowerCase().split(/\s+/);
        for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
          const language = lang as SupportedLanguages;
          let matches = 0;
          for (const word of words) {
            if (pattern.commonWords.includes(word)) {
              matches++;
            }
          }
          scores[language] = words.length > 0 ? matches / words.length : 0;
        }
        break;
      }
      case DetectionMethod.CHARACTER_FREQUENCY: {
        const charFreq: Record<string, number> = {};
        for (const char of text.toLowerCase()) {
          charFreq[char] = (charFreq[char] || 0) + 1;
        }
        for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
          const language = lang as SupportedLanguages;
          let score = 0;
          for (const word of pattern.commonWords) {
            for (const char of word) {
              if (charFreq[char]) {
                score += charFreq[char];
              }
            }
          }
          scores[language] = text.length > 0 ? score / text.length : 0;
        }
        break;
      }
      case DetectionMethod.NGRAM_ANALYSIS: {
        const normalizedText = text
          .toLowerCase()
          .replace(
            /[^a-zA-ZÀ-ÿĀ-žА-я\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff]/g,
            ""
          );
        for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
          const language = lang as SupportedLanguages;
          let bigramScore = 0;
          let trigramScore = 0;
          let totalBigrams = 0;
          let totalTrigrams = 0;

          if (pattern.bigrams && normalizedText.length >= 2) {
            for (let i = 0; i < normalizedText.length - 1; i++) {
              const bigram = normalizedText.substring(i, i + 2);
              totalBigrams++;
              if (pattern.bigrams.includes(bigram)) {
                bigramScore++;
              }
            }
          }

          if (pattern.trigrams && normalizedText.length >= 3) {
            for (let i = 0; i < normalizedText.length - 2; i++) {
              const trigram = normalizedText.substring(i, i + 3);
              totalTrigrams++;
              if (pattern.trigrams.includes(trigram)) {
                trigramScore++;
              }
            }
          }

          const bigramConfidence =
            totalBigrams > 0 ? bigramScore / totalBigrams : 0;
          const trigramConfidence =
            totalTrigrams > 0 ? trigramScore / totalTrigrams : 0;
          const combinedScore =
            bigramConfidence * 0.4 + trigramConfidence * 0.6;

          scores[language] = combinedScore;
        }
        break;
      }
      default:
        for (const lang of Object.values(SupportedLanguages)) {
          scores[lang] = 0;
        }
    }

    return scores;
  }

  private combineResults(
    results: Record<DetectionMethod, LanguageDetectionResult>
  ): LanguageDetectionResult {
    return results[DetectionMethod.COMBINED];
  }

  private getBestMatch(scores: Record<SupportedLanguages, number>): {
    language: SupportedLanguages;
    score: number;
  } {
    let bestLanguage = this.options.fallbackLanguage;
    let bestScore = 0;

    for (const [lang, score] of Object.entries(scores)) {
      if (score > bestScore) {
        bestScore = score;
        bestLanguage = lang as SupportedLanguages;
      }
    }

    return { language: bestLanguage, score: bestScore };
  }
}

export function detectLanguage(
  text: string,
  options?: LanguageDetectionOptions
): LanguageDetectionResult {
  const detector = new LanguageDetector(options);
  const result = detector.detect(text);
  return Array.isArray(result) ? result[0] : result;
}

export function detectMultipleLanguages(
  text: string,
  options?: LanguageDetectionOptions
): LanguageDetectionResult[] {
  const detector = new LanguageDetector({
    ...options,
    enableMultipleDetection: true,
  });
  const result = detector.detect(text);
  return Array.isArray(result) ? result : [result];
}

export function getCybercrimeRisk(language: SupportedLanguages): number {
  return (CYBERCRIME_INDEX as Record<string, number>)[language] || 0;
}

export function isHighRiskLanguage(
  language: SupportedLanguages,
  threshold: number = 10
): boolean {
  return getCybercrimeRisk(language) > threshold;
}
