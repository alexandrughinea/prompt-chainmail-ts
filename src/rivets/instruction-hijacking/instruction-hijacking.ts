import { SecurityFlags } from "../rivets.types";
import {
  detectLookalikeChars,
  hasLanguageScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { IntrusionDetector } from "./instruction-hijacking.utils";
import { AttackType } from "./instruction-hijacking.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";

/**
 * @description
 * Analyzes the content within the provided context to detect and mitigate possible instruction hijacking attacks.
 * It tries to identify relevant languages in the content, evaluates potential instruction hijacking risks, and applies
 * appropriate security flags and threat penalties based on the detection results.
 *
 * @param options Configuration options for instruction hijacking detection
 * @param options.languagesLimit Maximum number of languages to process (default: 3)
 * @param options.languagesDetectionThreshold Minimum confidence threshold for language detection (default: 0.1)
 */
export function instructionHijacking(
  options: {
    languagesLimit?: number;
    languagesDetectionThreshold?: number;
  } = {}
): ChainmailRivet {
  const languageDetector = new LanguageDetector();
  const intrusionDetector = new IntrusionDetector();
  const defaultLanguage = "eng";
  const languagesDetectionThreshold =
    options.languagesDetectionThreshold ?? 0.1;
  const languagesLimit = options.languagesLimit ?? 3;
  const config = intrusionDetector.getConfig();

  return async (context: ChainmailContext, next) => {
    const { instruction_hijacking_threshold } = config;

    if (!context.input.trim()) {
      return next();
    }
    const languages = languageDetector
      .detect(context.input)
      .filter(([, confidence]) => confidence > languagesDetectionThreshold);

    if (languages.length === 0) {
      languages.push([defaultLanguage, 0.1]);
    }

    const topLanguages = languages.slice(0, languagesLimit);
    const hasScriptMixing = hasLanguageScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);
    const allAttackTypes = new Set<AttackType>();

    let maxRiskScore = 0;
    let maxConfidence = 0;
    let maxConfidenceLanguage = defaultLanguage;

    for (const [iso3Code] of topLanguages) {
      try {
        const result = await intrusionDetector.detect(
          context.sanitized,
          iso3Code
        );

        if (result.confidence > maxConfidence) {
          maxConfidence = result.confidence;
          maxConfidenceLanguage = iso3Code;
        }

        maxRiskScore = Math.max(maxRiskScore, result.risk_score);
        result.attack_types.forEach((attackType) =>
          allAttackTypes.add(attackType as AttackType)
        );
      } catch (error) {
        console.error(
          `Error detecting instruction hijacking for language ${iso3Code}:`,
          error
        );
      }
    }

    const attackTypesArray = Array.from(allAttackTypes);
    const isAttack = attackTypesArray.length > 0;

    if (isAttack) {
      const flagSet = new Set<SecurityFlags>();

      flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING);

      attackTypesArray.forEach((attackType) => {
        switch (attackType) {
          case AttackType.INSTRUCTION_OVERRIDE:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_OVERRIDE);
            break;
          case AttackType.INSTRUCTION_FORGETTING:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_IGNORE);
            break;
          case AttackType.RESET_SYSTEM:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_RESET);
            break;
          case AttackType.BYPASS_SECURITY:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_BYPASS);
            break;
          case AttackType.INFORMATION_EXTRACTION:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_REVEAL);
            break;
          default:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_UNKNOWN);
        }
      });

      if (languages.length > 1) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_SCRIPT_MIXING);
      }

      if (hasLookalikes) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_LOOKALIKES);
      }

      flagSet.forEach((flag) => context.flags.add(flag));

      const threatLevel =
        maxConfidence > instruction_hijacking_threshold
          ? ThreatLevel.CRITICAL
          : maxConfidence > 0.5
            ? ThreatLevel.HIGH
            : maxConfidence > 0.3
              ? ThreatLevel.MEDIUM
              : ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);

      context.metadata.instruction_hijacking_detected = true;
      context.metadata.instruction_hijacking_confidence = maxConfidence;
      context.metadata.instruction_hijacking_risk_score = maxRiskScore;
      context.metadata.instruction_hijacking_attack_types = attackTypesArray;
      context.metadata.instruction_hijacking_detected_language =
        maxConfidenceLanguage;
      context.metadata.instruction_hijacking_detected_languages =
        topLanguages.map(([iso3]) => iso3);
    }

    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    return next();
  };
}
