import { COMMON_PATTERNS } from "../../@shared/regex-patterns/common.const";
import { normalizeText } from "../../@shared/language-detection";
import languageGroups from "../../@configs/language_iso3_to_language_groups.json";
import cybercrimeIndex from "../../@configs/language_region_cybercrime_index_index.json";
import instructionPatternsConfig from "../../@configs/instruction_patterns.json";

interface PatternTemplate {
  templates: string[];
  slots: Record<string, string[]>;
  weight?: number;
}

interface AttackPatterns {
  [attackType: string]: PatternTemplate;
}

export interface DetectionResult {
  isAttack: boolean;
  attack_types: string[];
  confidence: number;
  risk_score: number;
  detected_language: string;
  details: string[];
}

export class IntrusionDetector {
  private readonly patterns = instructionPatternsConfig;
  private readonly detectionConfig = this.patterns.config;

  public detect(text: string, languageCode: string): DetectionResult {
    if (!text?.trim()) {
      return this.createEmptyResult(languageCode);
    }

    const normalizedText = normalizeText(text);
    const patternGroup =
      languageGroups.value[languageCode as keyof typeof languageGroups.value];
    const attackPatterns = patternGroup
      ? this.patterns.value[patternGroup as keyof typeof this.patterns.value]
      : this.patterns.value.eng;

    if (!attackPatterns) {
      return this.createEmptyResult(languageCode);
    }

    const attackResults = this.checkAttackPatterns(
      normalizedText,
      attackPatterns
    );

    const risk_score = this.calculateLanguagerisk_score(
      attackResults.confidence,
      patternGroup || "eng",
      attackResults.attack_types.length
    );

    return {
      isAttack:
        attackResults.attack_types.length > 0 &&
        attackResults.confidence > this.detectionConfig.confidence_threshold,
      attack_types: attackResults.attack_types,
      confidence: attackResults.confidence,
      risk_score,
      detected_language: patternGroup || languageCode,
      details: attackResults.details,
    };
  }

  private checkAttackPatterns(text: string, patterns: AttackPatterns) {
    const attackTypes: string[] = [];
    const details: string[] = [];
    let totalConfidence = 0;
    let patternCount = 0;

    for (const [attackType, pattern] of Object.entries(patterns)) {
      const result = this.evaluatePattern(text, pattern);

      if (result.isMatch) {
        attackTypes.push(attackType);
        totalConfidence += result.confidence * (pattern.weight || 1);
        patternCount++;
        details.push(
          `${attackType}: ${(result.confidence * 100).toFixed(1)}% confidence`
        );
      }
    }

    return {
      attack_types: attackTypes,
      confidence:
        patternCount > 0 ? Math.min(totalConfidence / patternCount, 1) : 0,
      details,
    };
  }

  private evaluatePattern(text: string, pattern: PatternTemplate) {
    const { match_confidence_threshold } = this.detectionConfig;

    if (!pattern.templates || !pattern.slots) {
      return { isMatch: false, confidence: 0 };
    }

    let maxConfidence = 0;
    let matchedTemplates = 0;

    for (const template of pattern.templates) {
      const templateConfidence = this.evaluateTemplate(
        text,
        template,
        pattern.slots
      );
      if (templateConfidence > 0) {
        matchedTemplates++;
        maxConfidence = Math.max(maxConfidence, templateConfidence);
      }
    }

    const confidence = maxConfidence;
    const hasStrongEvidence =
      matchedTemplates >= 1 && confidence > match_confidence_threshold;

    return {
      isMatch: hasStrongEvidence,
      confidence,
    };
  }

  private evaluateTemplate(text: string, template: string, slots: Record<string, string[]>): number {
    const slotPattern = new RegExp(COMMON_PATTERNS.SLOT_PATTERN.source, 'g');
    const wordPattern = COMMON_PATTERNS.WORD_CHAR;
    const templateSlots = [...template.matchAll(slotPattern)].map(
      (match) => match[1]
    );

    if (templateSlots.length === 0) {
      return 0;
    }

    const emptyChar = " ";
    let totalMatches = 0;
    let slotMatches = 0;
    const lowerText = text.toLowerCase();

    for (const slotName of templateSlots) {
      const slotTerms = slots[slotName];

      if (!slotTerms || !Array.isArray(slotTerms)) {
        continue;
      }

      const slotMatched = slotTerms.some((term) => {
        const index = text.indexOf(term);

        if (index === -1) {
          return false;
        }

        const beforeChar = index > 0 ? lowerText[index - 1] : emptyChar;
        const afterChar =
          index + term.length < lowerText.length
            ? lowerText[index + term.length]
            : emptyChar;

        return !wordPattern.test(beforeChar) && !wordPattern.test(afterChar);
      });

      if (slotMatched) {
        slotMatches++;
      }
      totalMatches++;
    }

    if (totalMatches === 0) {
      return 0;
    }

    const slotCoverage = slotMatches / totalMatches;

    const {
      min_slot_coverage_ratio,
      slot_coverage_weight,
      perfect_match_bonus,
    } = instructionPatternsConfig.config.template_matching;
    const minRequiredSlots = Math.max(
      1,
      Math.ceil(templateSlots.length * min_slot_coverage_ratio)
    );
    if (slotMatches < minRequiredSlots) {
      return 0;
    }

    return (
      slotCoverage * slot_coverage_weight +
      (slotMatches >= templateSlots.length ? perfect_match_bonus : 0)
    );
  }

  private calculateLanguagerisk_score(
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
    } = instructionPatternsConfig.config.risk_calculation;

    const baseRisk = confidence * 100;
    const cybercrimeIndexValue =
      cybercrimeIndex.value[
        languageGroup as keyof typeof cybercrimeIndex.value
      ] || cybercrime_index_base;
    const cybercrimeMultiplier = cybercrimeIndexValue / cybercrime_index_base;
    const attackTypeMultiplier = Math.min(
      attackTypeCount / attack_type_divisor,
      max_attack_type_multiplier
    );

    const cybercrimeIndexValues = Object.values(
      cybercrimeIndex.value
    ) as number[];
    const sortedCybercrimeIndexValues = cybercrimeIndexValues.sort(
      (a, b) => b - a
    );
    const fifthHighestThreshold = sortedCybercrimeIndexValues[4];

    const riskBoost =
      attackTypeCount > 1 && cybercrimeIndexValue >= fifthHighestThreshold
        ? high_risk_boost
        : 1;

    return Math.min(
      baseRisk * cybercrimeMultiplier * (1 + attackTypeMultiplier) * riskBoost,
      max_risk_score
    );
  }

  private createEmptyResult(languageCode: string): DetectionResult {
    return {
      isAttack: false,
      attack_types: [],
      confidence: 0,
      risk_score: 0,
      detected_language: languageCode,
      details: [],
    };
  }
}
