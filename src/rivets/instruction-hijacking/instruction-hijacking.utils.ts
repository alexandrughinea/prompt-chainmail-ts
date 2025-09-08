import {
  ATTACK_PATTERNS,
} from "./instruction-hijacking.const";
import { AttackType, LanguagePatterns, DetectionPattern } from "./instruction-hijacking.types";
import { SupportedLanguages } from "../rivets.types";
import { CYBERCRIME_INDEX_BY_LANGUAGE } from "../rivets.const";


export interface DetectionResult {
  isAttack: boolean;
  attackTypes: AttackType[];
  confidence: number;
  riskScore: number;
  detectedLanguage: SupportedLanguages;
  details: string[];
}

export class MultilingualIntrusionDetector {
  private readonly patterns: LanguagePatterns;
  private readonly cybercrimeIndex: typeof CYBERCRIME_INDEX_BY_LANGUAGE;

  constructor() {
    this.patterns = ATTACK_PATTERNS;
    this.cybercrimeIndex = CYBERCRIME_INDEX_BY_LANGUAGE;
  }

  /**
   * Evaluate attack heuristics for a specific text variant
   */
  private evaluateAttackHeuristics(
    text: string,
    pattern: DetectionPattern
  ): { confidence: number; matches: string[] } {
    let keywordMatches = 0;
    let phraseMatches = 0;
    let contextMatches = 0;
    const matches: string[] = [];

    // Keyword matching with fuzzy tolerance
    for (const keyword of pattern.keywords) {
      if (text.includes(keyword.toLowerCase())) {
        keywordMatches++;
        matches.push(`keyword: ${keyword}`);
      }
    }

    // Phrase matching with exact match priority
    let hasExactPhraseMatch = false;
    let hasStrongPhraseMatch = false;
    for (const phrase of pattern.phrases) {
      if (text.includes(phrase.toLowerCase())) {
        phraseMatches++;
        matches.push(`phrase: ${phrase}`);
        if (text.trim().toLowerCase() === phrase.toLowerCase()) {
          hasExactPhraseMatch = true;
        }
        // Check for strong phrase match (phrase covers most of the text)
        if (phrase.length > text.length * 0.6) {
          hasStrongPhraseMatch = true;
        }
      }
    }

    // Context pattern matching with regex
    for (const contextPattern of pattern.contextPatterns) {
      try {
        const regex = new RegExp(contextPattern, "i");
        if (regex.test(text)) {
          contextMatches++;
          matches.push(`pattern: ${contextPattern}`);
        }
      } catch (e) {
        continue;
      }
    }

    // Simplified confidence calculation
    const keywordScore = keywordMatches > 0 ? Math.min(keywordMatches / Math.max(pattern.keywords.length, 1), 1.0) : 0;
    const phraseScore = phraseMatches > 0 ? Math.min(phraseMatches / Math.max(pattern.phrases.length, 1), 1.0) : 0;
    const contextScore = contextMatches > 0 ? Math.min(contextMatches / Math.max(pattern.contextPatterns.length, 1), 1.0) : 0;
  
    // Prioritize exact phrase matches with higher confidence
    const confidence = hasExactPhraseMatch 
      ? Math.max(0.9, (keywordScore * 0.2) + (phraseScore * 0.7) + (contextScore * 0.1))
      : (keywordScore * 0.3) + (phraseScore * 0.6) + (contextScore * 0.1);

    return { confidence: Math.min(confidence, 1.0), matches };
  }

  /**
   * Check if the context suggests legitimate use
   */
  private isLegitimateContext(text: string): boolean {
    const helpIndicators = [
      'help', 'please', 'how to', 'can you', 'show me', 'guide me', 'need help',
      'veuillez', 'pouvez-vous', 'können sie', 'bitte', 'por favor', 'пожалуйста', 'можете',
      'tutorial', 'guide', 'manual', 'documentation', 'example', 'sample', 'demo'
    ];

    const legitimateContexts = [
      'software', 'application', 'program', 'system configuration', 'setup', 'installation',
      'user manual', 'documentation', 'tutorial', 'guide', 'help', 'support',
      'training material', 'educational', 'academic', 'course', 'lesson', 'employees',
      'future goals', 'possibilities', 'technology', 'lessons learned', 'dream about',
      'imagine the', 'reflect on', 'training materials', 'new features', 'update',
      'default settings', 'better performance', 'install the package', 'case sensitivity',
      'mail delivery', 'new employees', 'configuración del sistema', 'mejor rendimiento',
      'instalar el paquete', 'configuration du système', 'neue funktionen', 'новые функции',
      'login credentials', 'forgot my', 'necesito ayuda', 'ayuda con la'
    ];

    // Check for social engineering indicators that should NOT be considered legitimate
    const socialEngineeringIndicators = [
      'trusted administrator', 'as your administrator', 'override security', 'bypass security',
      'if asked about safety', 'si te preguntan sobre seguridad', 'jeśli pytają o bezpieczeństwo',
      'dacă întreabă despre securitate', 'wenn nach sicherheit gefragt'
    ];

    const hasSocialEngineering = socialEngineeringIndicators.some(indicator => 
      text.toLowerCase().includes(indicator.toLowerCase())
    );

    if (hasSocialEngineering) {
      return false; // Social engineering should never be considered legitimate
    }

    const hasHelpIndicator = helpIndicators.some(indicator => text.toLowerCase().includes(indicator.toLowerCase()));
    const hasLegitimateContext = legitimateContexts.some(context => text.toLowerCase().includes(context.toLowerCase()));

    return hasHelpIndicator || hasLegitimateContext;
  }

  /**
   * Calculate risk score incorporating cybercrime index
   */
  private calculateRiskScore(
    confidence: number,
    language: SupportedLanguages,
    attackTypeCount: number
  ): number {
    const baseRisk = confidence * 100;
    const cybercrimeMultiplier = (this.cybercrimeIndex[language as keyof typeof this.cybercrimeIndex] || 10) / 100;
    const attackTypeMultiplier = Math.min(attackTypeCount / 5, 1); // Normalize to max 5 types

    return Math.min(
      baseRisk * (1 + cybercrimeMultiplier) * (1 + attackTypeMultiplier),
      100
    );
  }

  /**
   * Heuristic-based attack pattern detection
   */
  private checkAttackPatterns(
    text: string,
    language: SupportedLanguages
  ): { attackTypes: AttackType[]; details: string[]; confidence: number } {
    const languagePatterns = this.patterns[language];
    if (!languagePatterns) {
      return {
        attackTypes: [],
        details: [],
        confidence: 0,
      };
    }

    const textVariants = this.generateTextVariants(text);
    
    const detectedAttacks: Set<AttackType> = new Set();
    const details: string[] = [];
    let totalConfidence = 0;

    // Heuristic pattern matching for each attack type
    for (const [attackTypeKey, pattern] of Object.entries(languagePatterns)) {
      const attackType = attackTypeKey as AttackType;
      let bestConfidence = 0;
      let bestVariant = '';
      
      // Test each text variant for this attack type
      for (const textVariant of textVariants) {
        const result = this.evaluateAttackHeuristics(textVariant, pattern);
        if (result.confidence > bestConfidence) {
          bestConfidence = result.confidence;
          bestVariant = textVariant;
        }
      }

      // Apply context-aware filtering to reduce false positives
      const isLegitimate = this.isLegitimateContext(bestVariant);
      
      // Adjust confidence based on context
      if (isLegitimate && bestConfidence < 0.7) {
        bestConfidence *= 0.2;
      }

      // Dynamic threshold based on pattern strength and context
      let threshold = 0.1;
      if (isLegitimate) {
        threshold = 0.4;
      } else if (bestConfidence > 0.5) {
        threshold = 0.05; // Lower threshold for high-confidence matches
      }

      if (bestConfidence > threshold) {
        detectedAttacks.add(attackType);
        totalConfidence += bestConfidence * pattern.weight;
        details.push(`${attackType}: confidence ${(bestConfidence * 100).toFixed(1)}% (variant: ${bestVariant.substring(0, 50)}...)`);
      }
    }

    const finalConfidence = Math.min(totalConfidence, 1.0);

    return {
      attackTypes: Array.from(detectedAttacks),
      details,
      confidence: finalConfidence,
    };
  }

  /**
   * Main detection method - requires language to be provided
   */
  public detectIntrusion(
    text: string,
    language: SupportedLanguages
  ): DetectionResult {
    if (!text || text.trim().length === 0) {
      return {
        isAttack: false,
        attackTypes: [],
        confidence: 0,
        riskScore: 0,
        detectedLanguage: language,
        details: [],
      };
    }

    // Check for attack patterns using provided language
    const { attackTypes, details, confidence } = this.checkAttackPatterns(
      text,
      language
    );

    // Calculate risk score
    const riskScore = this.calculateRiskScore(
      confidence,
      language,
      attackTypes.length
    );

    // Determine if this constitutes an attack
    const isAttack = attackTypes.length > 0 && confidence > 0.005;

    return {
      isAttack,
      attackTypes,
      confidence,
      riskScore,
      detectedLanguage: language,
      details,
    };
  }

  /**
   * Process detection result - returns detection result without modifying context
   */
  public processDetection(
    text: string,
    language: SupportedLanguages
  ): DetectionResult {
    return this.detectIntrusion(text, language);
  }

  /**
   * Generate text variants for obfuscation detection
   */
  private generateTextVariants(text: string): string[] {
    const variants = [text.toLowerCase()];
    
    // Character-separated obfuscation (e.g., "o-v-e-r-r-i-d-e")
    const charSeparated = text.replace(/[-_.]/g, '').toLowerCase();
    if (charSeparated !== text.toLowerCase()) {
      variants.push(charSeparated);
    }
    
    // Dot-separated obfuscation (e.g., "o.v.e.r.r.i.d.e")
    const dotSeparated = text.replace(/[.\-_]/g, '').toLowerCase();
    if (dotSeparated !== text.toLowerCase()) {
      variants.push(dotSeparated);
    }
    
    // Fully deobfuscated (remove all non-alphanumeric except spaces)
    const deobfuscated = text.replace(/[^a-zA-Z0-9\s]/g, '').replace(/\s+/g, ' ').trim().toLowerCase();
    if (deobfuscated !== text.toLowerCase()) {
      variants.push(deobfuscated);
    }

    // Space-normalized variant (normalize excessive spaces)
    const spaceNormalized = text.replace(/\s+/g, ' ').trim().toLowerCase();
    if (spaceNormalized !== text.toLowerCase()) {
      variants.push(spaceNormalized);
    }

    // Remove all spaces variant
    const noSpaces = text.replace(/\s/g, '').toLowerCase();
    if (noSpaces !== text.toLowerCase()) {
      variants.push(noSpaces);
    }
    
    return variants;
  }
}
