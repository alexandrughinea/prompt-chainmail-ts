import { SecurityFlags } from "../rivets.types";
import {
  hasLanguageScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { RoleConfusionDetector } from "./role-confusion.utils";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import { PatternLoader } from "../../@shared/pattern-detector/pattern-loader";
import { RoleConfusionAttackType } from "./role-confusion.types";

/**
 * @description
 * Analyzes the content within the provided context to detect and mitigate possible role confusion attacks.
 * It tries to identify relevant languages in the content, evaluates potential role confusion risks, and applies
 * appropriate security flags and threat penalties based on the detection results.
 *
 * @param options Configuration options for role confusion detection
 * @param options.languagesLimit Maximum number of languages to process (default: 3)
 * @param options.languagesDetectionThreshold Minimum confidence threshold for language detection (default: 0.6)
 */
export function roleConfusion(
  options: {
    languagesLimit?: number;
    languagesDetectionThreshold?: number;
  } = {}
): ChainmailRivet {
  const languageDetector = new LanguageDetector();
  const detector = new RoleConfusionDetector();
  const defaultLanguage = "eng";
  const languagesDetectionThreshold =
    options.languagesDetectionThreshold ?? 0.6;
  const languagesLimit = options.languagesLimit ?? 3;
  const config = PatternLoader.get("role_confusion");

  return async (context: ChainmailContext, next) => {
    const { confidence_threshold, high_risk_role_confidence_threshold = 0.7 } =
      config;

    if (!context.input.trim()) {
      return next();
    }

    const languages = languageDetector
      .detect(context.input)
      .filter(([_, confidence]) => confidence > languagesDetectionThreshold);

    if (languages.length === 0) {
      languages.push([defaultLanguage, 0.1]);
    }

    const topLanguages = languages.slice(0, languagesLimit);
    const hasScriptMixing = hasLanguageScriptMixing(context.sanitized);
    const allAttackTypes = new Set<RoleConfusionAttackType>();

    let maxRiskScore = 0;
    let maxConfidence = 0;
    let maxConfidenceLanguage = defaultLanguage;

    for (const [iso3Code] of topLanguages) {
      try {
        const result = await detector.detect(context.sanitized, iso3Code);

        if (result.confidence > maxConfidence) {
          maxConfidence = result.confidence;
          maxConfidenceLanguage = iso3Code;
        }

        maxRiskScore = Math.max(maxRiskScore, result.risk_score);
        result.attack_types.forEach((attackType: string) =>
          allAttackTypes.add(attackType as RoleConfusionAttackType)
        );

        if (
          result.confidence > confidence_threshold &&
          result.attack_types.length > 0
        ) {
          break;
        }
      } catch (error) {
        console.error(
          `Error detecting role confusion for language ${iso3Code}:`,
          error
        );
      }
    }

    const attackTypesArray = Array.from(allAttackTypes);
    const isAttack =
      maxConfidence > confidence_threshold && attackTypesArray.length > 0;

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

      if (
        maxConfidence > high_risk_role_confidence_threshold &&
        attackTypesArray.length > 1
      ) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_HIGH_RISK_ROLE);
      }

      if (languages.length > 1) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_SCRIPT_MIXING);
      }

      context.flags = Array.from(flagSet);

      const threatLevel =
        maxConfidence > confidence_threshold
          ? ThreatLevel.CRITICAL
          : maxConfidence > 0.5
            ? ThreatLevel.HIGH
            : maxConfidence > 0.3
              ? ThreatLevel.MEDIUM
              : ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);

      context.metadata.role_confusion_detected = true;
      context.metadata.role_confusion_attack_types = attackTypesArray;
    } else {
      context.metadata.role_confusion_detected = false;
      context.metadata.role_confusion_attack_types = [];
    }

    context.metadata.role_confusion_confidence = maxConfidence;
    context.metadata.role_confusion_risk_score = maxRiskScore;
    context.metadata.role_confusion_dominant_language = maxConfidenceLanguage;
    context.metadata.role_confusion_detected_languages = topLanguages.map(
      ([iso3]) => iso3
    );

    return next();
  };
}
