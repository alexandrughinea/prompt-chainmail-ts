import { normalizeText } from "../../@shared/language-detection";
import { COMMON_PATTERNS } from "../../@shared/regex-patterns/common.const";
import languageGroups from "../../@configs/language_iso3_to_language_groups.json";
import cybercrimeIndex from "../../@configs/language_region_cybercrime_index_index.json";
import confusionPatternsConfig from "../../@configs/confusion_patterns.json";
import { RoleConfusionAttackType } from "./role-confusion.types";

interface TemplateMatching {
  exact_match_confidence: number;
  substring_match_confidence: number;
  min_slot_coverage_ratio: number;
  slot_coverage_weight: number;
  perfect_match_bonus: number;
}

interface RiskCalculation {
  cybercrime_index_base: number;
  max_attack_type_multiplier: number;
  attack_type_divisor: number;
  high_risk_boost: number;
  max_risk_score: number;
  fallback_threshold: number;
}

interface DetectionConfig {
  confidence_threshold: number;
  match_confidence_threshold: number;
  template_matching: TemplateMatching;
  risk_calculation: RiskCalculation;
}

interface PatternTemplate {
  templates: string[];
  slots: Record<string, string[]>;
  weight?: number;
}

interface ConfusionPatterns {
  [attackType: string]: PatternTemplate;
}

export interface ConfusionDetectionResult {
  isAttack: boolean;
  attack_types: string[];
  confidence: number;
  risk_score: number;
  detected_language: string;
  details: string[];
}

export class RoleConfusionDetector {
  private readonly patterns = confusionPatternsConfig;
  private readonly detectionConfig = (this.patterns as typeof confusionPatternsConfig).config as DetectionConfig;

  public detect(text: string, languageCode: string): ConfusionDetectionResult {
    if (!text?.trim()) {
      return this.createEmptyResult(languageCode);
    }

    const normalizedText = normalizeText(text);

    const patternGroup =
      languageGroups.value[languageCode as keyof typeof languageGroups.value] ||
      "eng";
    let confusionPatterns =
      this.patterns.value[patternGroup as keyof typeof this.patterns.value] ||
      this.patterns.value.eng;

    let attackResults = this.checkConfusionPatterns(
      normalizedText,
      confusionPatterns,
      patternGroup
    );

    if (attackResults.attack_types.length === 0 && patternGroup !== "eng") {
      const englishPatterns = this.patterns.value.eng;
      const englishResults = this.checkConfusionPatterns(
        normalizedText,
        englishPatterns,
        "eng-fallback"
      );
      if (englishResults.attack_types.length > 0) {
        attackResults = englishResults;
        confusionPatterns = englishPatterns;
      }
    }

    const risk_score = this.calculateLanguagerisk_score(
      attackResults.confidence,
      patternGroup || "eng",
      attackResults.attack_types.length
    );

    return {
      isAttack:
        attackResults.attack_types.length > 0 &&
        attackResults.confidence >
          (this.detectionConfig?.confidence_threshold || 0.1),
      attack_types: attackResults.attack_types,
      confidence: attackResults.confidence,
      risk_score,
      detected_language: patternGroup || languageCode,
      details: attackResults.details,
    };
  }

  private createEmptyResult(languageCode: string): ConfusionDetectionResult {
    return {
      isAttack: false,
      attack_types: [],
      confidence: 0,
      risk_score: 0,
      detected_language: languageCode,
      details: [],
    };
  }

  private checkConfusionPatterns(
    text: string,
    patterns: ConfusionPatterns,
    patternGroup?: string
  ) {
    const matches: Array<{
      attackType: string;
      confidence: number;
      weight: number;
    }> = [];
    const details: string[] = [];

    for (const [attackType, pattern] of Object.entries(patterns)) {
      const result = this.evaluatePattern(text, pattern);

      if (result.isMatch) {
        matches.push({
          attackType,
          confidence: result.confidence,
          weight: pattern.weight || 1,
        });
        details.push(
          `${attackType}: ${(result.confidence * 100).toFixed(1)}% confidence (weight: ${pattern.weight || 1}) [${patternGroup || "unknown"}]`
        );
      }
    }

    if (matches.length === 0) {
      return {
        attack_types: [],
        confidence: 0,
        details,
      };
    }

    const maxConfidence = Math.max(...matches.map((m) => m.confidence));
    const attackTypes = matches.map(
      (m) => m.attackType as RoleConfusionAttackType
    );

    return {
      attack_types: attackTypes,
      confidence: maxConfidence,
      details,
    };
  }

  private evaluatePattern(text: string, pattern: PatternTemplate) {
    const match_confidence_threshold =
      this.detectionConfig?.match_confidence_threshold;

    if (!pattern.templates) {
      return { isMatch: false, confidence: 0 };
    }

    let maxConfidence = 0;
    let matchedTemplates = 0;

    for (const template of pattern.templates) {
      const templateConfidence = this.evaluateTemplate(
        text,
        template,
        pattern.slots || {}
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
    const slotPattern = new RegExp(COMMON_PATTERNS.SLOT_PATTERN.source, "g");
    const wordPattern = COMMON_PATTERNS.WORD_CHAR;
    const templateSlots = [...template.matchAll(slotPattern)].map(
      (match) => match[1]
    );

    if (templateSlots.length === 0) {
      const lowerText = text.toLowerCase();
      const lowerTemplate = template.toLowerCase();

      const { exact_match_confidence, substring_match_confidence } =
        this.detectionConfig.template_matching || { exact_match_confidence: 0.9, substring_match_confidence: 0.6 };

      if (lowerText === lowerTemplate) {
        return exact_match_confidence;
      }

      return lowerText.includes(lowerTemplate) ? substring_match_confidence : 0;
    }

    let totalMatches = 0;
    let slotMatches = 0;
    const emptyChar = " ";

    const lowerText = text.toLowerCase();

    for (const slotName of templateSlots) {
      const slotTerms = slots[slotName];
      if (!slotTerms || !Array.isArray(slotTerms)) {
        continue;
      }

      const slotMatched = slotTerms.some((term) => {
        const index = lowerText.indexOf(term);

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
    } = this.detectionConfig?.template_matching ?? {};
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
      fallback_threshold,
    } = this.detectionConfig.risk_calculation;

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
    const fifthHighestThreshold =
      sortedCybercrimeIndexValues[4] || fallback_threshold;

    const riskBoost =
      attackTypeCount > 1 && cybercrimeIndexValue >= fifthHighestThreshold
        ? high_risk_boost
        : 1;

    return Math.min(
      baseRisk * cybercrimeMultiplier * (1 + attackTypeMultiplier) * riskBoost,
      max_risk_score
    );
  }
}
