import { PatternDetector } from "../../@shared/pattern-detector/pattern-detector";
import { PatternDetectionResult } from "../../@shared/pattern-detector/pattern-detector.types";
import { PatternLoader } from "../../@shared/pattern-detector/pattern-loader";

export class IntrusionDetector extends PatternDetector {
  constructor() {
    super(PatternLoader.get("instruction_hijacking"));
  }

  public getConfig() {
    return PatternLoader.get("instruction_hijacking");
  }

  public async detect(
    text: string,
    languageCode: string
  ): Promise<PatternDetectionResult> {
    if (!text?.trim()) {
      return this.createEmptyResult(languageCode);
    }

    const normalizedText = this.normalizeText(text);
    const patternGroup = this.getPatternByLanguageCode(languageCode);

    const attackResults = await this.checkPatterns(
      normalizedText,
      patternGroup || languageCode,
      "instruction_hijacking"
    );
    const riskScore = this.calculateLanguageCodeRiskScore(
      attackResults.confidence,
      patternGroup || "eng",
      attackResults.attack_types.length
    );

    return {
      is_attack:
        attackResults.attack_types.length > 0 &&
        attackResults.confidence > this.detectionConfig.confidence_threshold,
      attack_types: attackResults.attack_types,
      confidence: attackResults.confidence,
      risk_score: riskScore,
      detected_language: patternGroup || languageCode,
      details: attackResults.details,
    };
  }
}
