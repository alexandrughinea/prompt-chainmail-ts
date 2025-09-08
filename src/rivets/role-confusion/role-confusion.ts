import { SecurityFlags } from "../rivets.types";
import {
  detectScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { RoleConfusionDetector } from "./role-confusion.utils";
import { ChainmailContext } from "../../types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import confusionPatternsConfig from "../../@configs/confusion_patterns.json";
import { RoleConfusionAttackType } from "./role-confusion.types";

/**
 * @description
 * This is a stub and will be implemented in the future to detect and flag more precisely with other strategies.
 */
export function roleConfusion() {
  const languageDetector = new LanguageDetector();
  const confusionDetector = new RoleConfusionDetector();

  return async (context: ChainmailContext, next: any) => {
    const relevantLanguages = languageDetector
      .detect(context.sanitized)
      .filter(([, confidence]) => confidence > 0.1);

    if (relevantLanguages.length === 0) {
      relevantLanguages.push(["eng", 0.3]);
    }

    const hasScriptMixing = detectScriptMixing(context.sanitized);
    const detectionResults = [];

    let maxRiskScore = 0;
    let maxConfidence = 0;

    const allAttackTypes = new Set<RoleConfusionAttackType>();

    for (const [iso3Code, confidence] of relevantLanguages) {
      try {
        const result = confusionDetector.detect(context.sanitized, iso3Code);

        detectionResults.push({
          language: iso3Code,
          result,
          detectionConfidence: confidence,
        });

        maxRiskScore = Math.max(maxRiskScore, result.risk_score);
        maxConfidence = Math.max(maxConfidence, result.confidence);

        result.attack_types.forEach((attackType: string) =>
          allAttackTypes.add(attackType as RoleConfusionAttackType)
        );
      } catch (error) {
        console.error(
          `Error detecting role confusion for language ${iso3Code}:`,
          error
        );
      }
    }

    const attackTypesArray = Array.from(allAttackTypes);
    const threshold = confusionPatternsConfig.config.confidence_threshold;
    const isAttack = attackTypesArray.length > 0 && maxConfidence > threshold;

    if (isAttack) {
      const flagSet = new Set(context.flags);
      flagSet.add(SecurityFlags.ROLE_CONFUSION);

      attackTypesArray.forEach((attackType: RoleConfusionAttackType) => {
        switch (attackType) {
          case RoleConfusionAttackType.ROLE_ASSUMPTION:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_ROLE_ASSUMPTION);
            break;
          case RoleConfusionAttackType.MODE_SWITCHING:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_MODE_SWITCHING);
            break;
          case RoleConfusionAttackType.PERMISSION_ASSERTION:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_PERMISSION_ASSERTION);
            break;
          case RoleConfusionAttackType.ROLE_INDICATOR:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_ROLE_INDICATOR);
            break;
        }
      });

      const highRiskThreshold = confusionPatternsConfig.config.high_risk_role_confidence_threshold;

      if (maxConfidence > highRiskThreshold && attackTypesArray.length > 1) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_HIGH_RISK_ROLE);
      }

      if (relevantLanguages.length > 1) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_SCRIPT_MIXING);
      }

      context.flags = Array.from(flagSet);

      const threatLevel =
        maxConfidence > highRiskThreshold
          ? ThreatLevel.CRITICAL
          : maxConfidence > 0.5
            ? ThreatLevel.HIGH
            : maxConfidence > 0.3
              ? ThreatLevel.MEDIUM
              : ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);

      context.metadata.role_confusion_detected = true;
      context.metadata.role_confusion_confidence = maxConfidence;
      context.metadata.role_confusion_risk_score = maxRiskScore;
      context.metadata.role_confusion_attack_types = attackTypesArray;
      context.metadata.role_confusion_detected_language =
        detectionResults.find((r) => r.result.confidence === maxConfidence)
          ?.language || "eng";
      context.metadata.role_confusion_detected_languages =
        relevantLanguages.map(([iso3]) => iso3);
    }

    return next();
  };
}
