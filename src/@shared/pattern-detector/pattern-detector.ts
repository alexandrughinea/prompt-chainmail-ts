import { COMMON_PATTERNS } from "../regex-patterns/common.const";
import { normalizeText } from "../language-detection";
import languageGroups from "../../@configs/language_iso3_to_language_groups.json" with { type: "json" };
import cybercrimeIndex from "../../@configs/language_region_cybercrime_index.json" with { type: "json" };
import { PatternLoader } from "./pattern-loader";
import {
  PatternDetectionConfig,
  PatternDetectionResult,
  PatternTemplate,
} from "./pattern-detector.types";

export abstract class PatternDetector {
  protected detectionConfig: PatternDetectionConfig;
  protected compiledPatterns: Map<string, RegExp> = new Map();
  private static cachedCybercrimeValues: number[] | null = null;
  private static cachedFifthHighestThreshold: number | null = null;
  private static languageCodeMap: Map<string, string> | null = null;

  protected constructor(config: PatternDetectionConfig) {
    this.detectionConfig = config;
    this.initializePatternCache();
    this.initializeCybercrimeCache();
    this.initializeLanguageGroupCache();
  }

  protected initializePatternCache() {
    this.compiledPatterns.set(
      "slot_pattern",
      new RegExp(COMMON_PATTERNS.SLOT_PATTERN.source, "g")
    );
    this.compiledPatterns.set("word_pattern", COMMON_PATTERNS.WORD_CHAR);
  }

  private initializeCybercrimeCache() {
    if (PatternDetector.cachedCybercrimeValues === null) {
      const cybercrimeIndexValues = Object.values(
        cybercrimeIndex.value
      ) as number[];
      PatternDetector.cachedCybercrimeValues = cybercrimeIndexValues.sort(
        (a, b) => b - a
      );
      PatternDetector.cachedFifthHighestThreshold =
        PatternDetector.cachedCybercrimeValues[4] || 0;
    }
  }

  private initializeLanguageGroupCache() {
    if (PatternDetector.languageCodeMap === null) {
      PatternDetector.languageCodeMap = new Map();
      for (const [key, value] of Object.entries(languageGroups.value)) {
        PatternDetector.languageCodeMap.set(key, value);
      }
    }
  }

  protected getCachedPattern(key: string): RegExp | undefined {
    return this.compiledPatterns.get(key);
  }

  public abstract detect(
    text: string,
    languageCode: string
  ): Promise<PatternDetectionResult>;

  protected createEmptyResult(languageCode: string): PatternDetectionResult {
    return {
      is_attack: false,
      attack_types: [],
      confidence: 0,
      risk_score: 0,
      detected_language: languageCode,
      details: [],
    };
  }

  protected async checkPatterns(
    text: string,
    languageCode: string,
    patternType: "instruction_hijacking" | "role_confusion"
  ) {
    const patterns = await PatternLoader.load(languageCode, patternType);
    const matches: Array<{
      attackType: string;
      confidence: number;
      details: string[];
    }> = [];
    const details: string[] = [];

    for (const attackType in patterns) {
      if (!Object.prototype.hasOwnProperty.call(patterns, attackType)) {
        continue;
      }

      const pattern = patterns[attackType];
      const result = this.evaluatePattern(text, pattern);

      if (result.isMatch) {
        matches.push({
          attackType,
          confidence: result.confidence,
          details: [
            `Matched ${attackType} with confidence ${result.confidence.toFixed(3)}`,
          ],
        });
        details.push(`${attackType}: ${result.confidence.toFixed(3)}`);
      }
    }

    if (matches.length === 0) {
      return {
        attack_types: [],
        confidence: 0,
        details,
      };
    }

    let maxConfidence = matches[0].confidence;
    for (let i = 1; i < matches.length; i++) {
      if (matches[i].confidence > maxConfidence) {
        maxConfidence = matches[i].confidence;
      }
    }
    const attackTypes = matches.map((m) => m.attackType);

    return {
      attack_types: attackTypes,
      confidence: maxConfidence,
      details,
    };
  }

  protected evaluatePattern(text: string, pattern: PatternTemplate) {
    const match_confidence_threshold =
      this.detectionConfig?.match_confidence_threshold;

    if (!pattern.templates) {
      return { isMatch: false, confidence: 0 };
    }

    let maxConfidence = 0;
    let matchedTemplates = 0;

    for (const template of pattern.templates) {
      const templateConfidence = this.evaluatePatternTemplate(
        text,
        template,
        pattern.slots
      );

      if (templateConfidence > 0) {
        matchedTemplates++;
        if (templateConfidence > maxConfidence) {
          maxConfidence = templateConfidence;
        }
      }
    }

    const confidence = maxConfidence;
    const hasStrongEvidence =
      matchedTemplates >= 1 && confidence >= (match_confidence_threshold || 0);

    return {
      isMatch: hasStrongEvidence,
      confidence,
    };
  }

  protected evaluatePatternTemplate(
    text: string,
    template: string,
    slots: Record<string, string[]>
  ): number {
    const slotPattern =
      this.getCachedPattern("slot_pattern") ||
      new RegExp(COMMON_PATTERNS.SLOT_PATTERN.source, "g");
    const wordPattern =
      this.getCachedPattern("word_pattern") || COMMON_PATTERNS.WORD_CHAR;
    const templateSlots = [...template.matchAll(slotPattern)].map(
      (match) => match[1]
    );

    if (templateSlots.length === 0) {
      const { exact_match_confidence = 0.9, substring_match_confidence = 0.7 } =
        this.detectionConfig.template_matching;

      if (text === template) {
        return exact_match_confidence;
      }

      return text.includes(template) ? substring_match_confidence : 0;
    }

    let totalMatches = 0;
    let slotMatches = 0;

    for (const slotName of templateSlots) {
      const slotTerms = slots[slotName];
      if (!slotTerms || slotTerms.length === 0) {
        continue;
      }

      totalMatches++; // Only count slots that are actually defined

      const slotMatched = slotTerms.some((term) => {
        let index = text.indexOf(term);
        let searchTerm = term;

        if (index === -1) {
          const normalizedTerm = this.normalizeText(term);
          index = text.indexOf(normalizedTerm);
          searchTerm = normalizedTerm;

          if (index === -1) {
            return false;
          }
        }

        const beforeChar = index > 0 ? text[index - 1] : " ";
        const afterChar =
          index + searchTerm.length < text.length
            ? text[index + searchTerm.length]
            : " ";

        return !wordPattern.test(beforeChar) && !wordPattern.test(afterChar);
      });

      if (slotMatched) {
        slotMatches++;
      }
    }

    if (totalMatches === 0) {
      return 0;
    }

    const slotCoverage = slotMatches / totalMatches;

    const {
      min_slot_coverage_ratio,
      slot_coverage_weight,
      perfect_match_bonus,
    } = this.detectionConfig?.template_matching ?? {};

    const minRequiredSlots = Math.max(
      1,
      Math.ceil(totalMatches * (min_slot_coverage_ratio || 0.6))
    );

    if (slotMatches < minRequiredSlots) {
      return 0;
    }

    const confidence =
      slotCoverage * (slot_coverage_weight || 0.8) +
      (slotMatches >= totalMatches ? perfect_match_bonus || 0.2 : 0);

    return confidence;
  }

  protected calculateLanguageCodeRiskScore(
    confidence: number,
    languageGroup: string,
    attackTypeCount: number
  ): number {
    const {
      cybercrime_index_base,
      max_attack_type_multiplier,
      attack_type_divisor,
      high_risk_boost,
      max_risk_score,
      fallback_threshold,
    } = this.detectionConfig.risk_calculation;

    const baseRisk = confidence * 100;

    const cybercrimeIndexValue =
      cybercrimeIndex.value[
        languageGroup as keyof typeof cybercrimeIndex.value
      ] || cybercrime_index_base;
    const cybercrimeMultiplier = cybercrimeIndexValue / cybercrime_index_base;
    const calculatedMultiplier = attackTypeCount / attack_type_divisor;
    const attackTypeMultiplier =
      calculatedMultiplier < max_attack_type_multiplier
        ? calculatedMultiplier
        : max_attack_type_multiplier;

    const fifthHighestThreshold =
      PatternDetector.cachedFifthHighestThreshold || fallback_threshold || 50;

    const riskBoost =
      attackTypeCount > 1 && cybercrimeIndexValue >= fifthHighestThreshold
        ? high_risk_boost
        : 1;

    const riskScore =
      baseRisk * cybercrimeMultiplier * (1 + attackTypeMultiplier) * riskBoost;
    return riskScore < max_risk_score ? riskScore : max_risk_score;
  }

  protected getPatternByLanguageCode(languageCode: string): string {
    return PatternDetector.languageCodeMap?.get(languageCode) || "eng";
  }

  protected normalizeText(text: string): string {
    return normalizeText(text);
  }
}
