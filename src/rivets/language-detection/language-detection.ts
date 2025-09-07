import {
  SupportedLanguages,
  LanguageDetectionResult,
  LanguageDetectionOptions,
  DetectionMethod,
} from './language-detection.types';
import {
  LANGUAGE_PATTERNS,
  LANGUAGE_DETECTION_DEFAULT_DETECTION_OPTIONS,
  CYBERCRIME_INDEX,
} from './language-detection.const';

export class LanguageDetector {
  private options: Required<LanguageDetectionOptions>;

  constructor(options: LanguageDetectionOptions = {}) {
    this.options = { ...LANGUAGE_DETECTION_DEFAULT_DETECTION_OPTIONS, ...options };
  }

  detect(text: string): LanguageDetectionResult {
    if (!text || text.trim().length === 0) {
      return {
        language: this.options.fallbackLanguage,
        confidence: 0,
        detectionMethod: DetectionMethod.COMBINED,
      };
    }

    const normalizedText = this.normalizeText(text);
    const results = this.runAllDetectionMethods(normalizedText);
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

  detectMultiple(text: string): LanguageDetectionResult[] {
    if (!this.options.enableMultipleDetection) {
      return [this.detect(text)];
    }

    const normalizedText = this.normalizeText(text);
    const results = this.runAllDetectionMethods(normalizedText);
    
    return Object.values(results)
      .filter(result => result.confidence >= this.options.minConfidence)
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 3);
  }

  getCybercrimeRisk(language: SupportedLanguages): number {
    return (CYBERCRIME_INDEX as Record<string, number>)[language] || 0;
  }

  private normalizeText(text: string): string {
    let normalized = text.trim();
    if (normalized.length > this.options.maxTextLength) {
      normalized = normalized.substring(0, this.options.maxTextLength);
    }
    return normalized;
  }

  private runAllDetectionMethods(text: string): Record<DetectionMethod, LanguageDetectionResult> {
    return {
      [DetectionMethod.SCRIPT_DETECTION]: this.detectByScript(text),
      [DetectionMethod.PATTERN_MATCHING]: this.detectByPatterns(text),
      [DetectionMethod.WORD_FREQUENCY]: this.detectByWordFrequency(text),
      [DetectionMethod.CHARACTER_FREQUENCY]: this.detectByCharacterFrequency(text),
      [DetectionMethod.COMBINED]: this.detectByCombined(text),
    };
  }

  private detectByScript(text: string): LanguageDetectionResult {
    const scores: Record<SupportedLanguages, number> = {} as Record<SupportedLanguages, number>;
    
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
      
      scores[language] = text.length > 0 ? (score / text.length) * pattern.weight : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.SCRIPT_DETECTION,
    };
  }

  private detectByPatterns(text: string): LanguageDetectionResult {
    const scores: Record<SupportedLanguages, number> = {} as Record<SupportedLanguages, number>;
    
    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let matches = 0;
      
      for (const regex of pattern.patterns) {
        const patternMatches = text.match(regex);
        if (patternMatches) {
          matches += patternMatches.length;
        }
      }
      
      const words = text.split(/\s+/).length;
      scores[language] = words > 0 ? (matches / words) * pattern.weight : 0;
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
    const scores: Record<SupportedLanguages, number> = {} as Record<SupportedLanguages, number>;
    
    for (const [lang, pattern] of Object.entries(LANGUAGE_PATTERNS)) {
      const language = lang as SupportedLanguages;
      let matches = 0;
      
      for (const word of words) {
        if (pattern.commonWords.includes(word)) {
          matches++;
        }
      }
      
      scores[language] = words.length > 0 ? (matches / words.length) * pattern.weight : 0;
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

    const scores: Record<SupportedLanguages, number> = {} as Record<SupportedLanguages, number>;
    
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
      
      scores[language] = text.length > 0 ? (score / text.length) * pattern.weight : 0;
    }

    const bestMatch = this.getBestMatch(scores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score * 0.5, 1.0),
      detectionMethod: DetectionMethod.CHARACTER_FREQUENCY,
    };
  }

  private detectByCombined(text: string): LanguageDetectionResult {
    const scriptResult = this.detectByScript(text);
    const patternResult = this.detectByPatterns(text);
    const wordResult = this.detectByWordFrequency(text);
    const charResult = this.detectByCharacterFrequency(text);

    const combinedScores: Record<SupportedLanguages, number> = {} as Record<SupportedLanguages, number>;
    
    // Initialize all scores to 0
    for (const lang of Object.values(SupportedLanguages)) {
      combinedScores[lang] = 0;
    }

    // Weight the results from each detection method
    const weights = {
      script: 0.4,
      pattern: 0.25,
      word: 0.25,
      char: 0.1,
    };

    // Add weighted scores for each language
    combinedScores[scriptResult.language] += scriptResult.confidence * weights.script;
    combinedScores[patternResult.language] += patternResult.confidence * weights.pattern;
    combinedScores[wordResult.language] += wordResult.confidence * weights.word;
    combinedScores[charResult.language] += charResult.confidence * weights.char;

    const bestMatch = this.getBestMatch(combinedScores);
    return {
      language: bestMatch.language,
      confidence: Math.min(bestMatch.score, 1.0),
      detectionMethod: DetectionMethod.COMBINED,
    };
  }

  private combineResults(results: Record<DetectionMethod, LanguageDetectionResult>): LanguageDetectionResult {
    return results[DetectionMethod.COMBINED];
  }

  private getBestMatch(scores: Record<SupportedLanguages, number>): { language: SupportedLanguages; score: number } {
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

export function detectLanguage(text: string, options?: LanguageDetectionOptions): LanguageDetectionResult {
  const detector = new LanguageDetector(options);
  return detector.detect(text);
}

export function detectMultipleLanguages(text: string, options?: LanguageDetectionOptions): LanguageDetectionResult[] {
  const detector = new LanguageDetector({ ...options, enableMultipleDetection: true });
  return detector.detectMultiple(text);
}

export function getCybercrimeRisk(language: SupportedLanguages): number {
  return (CYBERCRIME_INDEX as Record<string, number>)[language] || 0;
}

export function isHighRiskLanguage(language: SupportedLanguages, threshold: number = 10): boolean {
  return getCybercrimeRisk(language) > threshold;
}
