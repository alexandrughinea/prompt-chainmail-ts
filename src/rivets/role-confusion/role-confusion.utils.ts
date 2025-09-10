import { PatternDetector } from "../../@shared/pattern-detector/pattern-detector";
import { PatternDetectionResult } from "../../@shared/pattern-detector/pattern-detector.types";
import { PatternLoader } from "../../@shared/pattern-detector/pattern-loader";

export interface ConfusionPatternDetectionResult
  extends PatternDetectionResult {}

export class RoleConfusionDetector extends PatternDetector {
  constructor() {
    super(PatternLoader.get("role_confusion"));
  }

  public getConfig() {
    return PatternLoader.get("role_confusion");
  }

  public async detect(
    text: string,
    languageCode: string
  ): Promise<ConfusionPatternDetectionResult> {
    if (!text?.trim()) {
      return this.createEmptyResult(languageCode);
    }

    const normalizedText = this.normalizeText(text);
    const patternGroup = this.getPatternByLanguageCode(languageCode);
    const attackPatterns = await this.checkPatterns(
      normalizedText,
      patternGroup || languageCode,
      "role_confusion"
    );
    const isAttack =
      attackPatterns.attack_types.length > 0 &&
      attackPatterns.confidence > this.detectionConfig.confidence_threshold;

    const riskScore = this.calculateLanguageCodeRiskScore(
      attackPatterns.confidence,
      patternGroup,
      attackPatterns.attack_types.length
    );

    return {
      is_attack: isAttack,
      attack_types: attackPatterns.attack_types,
      confidence: attackPatterns.confidence,
      risk_score: riskScore,
      detected_language: patternGroup || languageCode,
      details: attackPatterns.details,
    };
  }
}
