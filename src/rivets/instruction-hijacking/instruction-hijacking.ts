import { ChainmailRivet } from "../../index";
import { SecurityFlags } from "../rivets.types";
import {
  detectLookalikeChars,
  detectScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext } from "../../types";
import { IntrusionDetector } from "./instruction-hijacking.utils";
import { AttackType } from "./instruction-hijacking.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import instructionPatternsConfig from "../../@configs/instruction_patterns.json";

/**
 * @description
 * Detects instruction hijacking attempts using multilingual pattern matching
 */
export function instructionHijacking(): ChainmailRivet {
  const languageDetector = new LanguageDetector();
  const intrusionDetector = new IntrusionDetector();

  return async (context: ChainmailContext, next) => {
    const relevantLanguages = languageDetector
      .detect(context.sanitized)
      .filter(([, confidence]) => confidence > 0.1);

    if (relevantLanguages.length === 0) {
      relevantLanguages.push(["eng", 0.3]);
    }

    // Prioritize high-confidence languages for better detection accuracy
    const prioritizeLanguages = (
      languages: [string, number][],
      priorities: Array<{ code: string; minConfidence: number }>
    ) => {
      const prioritized: [string, number][] = [];
      const remaining = [...languages];

      for (const { code, minConfidence } of priorities) {
        const index = remaining.findIndex(
          ([lang, conf]) => lang === code && conf >= minConfidence
        );
        if (index !== -1) {
          prioritized.push(remaining.splice(index, 1)[0]);
        }
      }

      return [...prioritized, ...remaining].slice(0, 5); // Limit to 5 total
    };

    // Apply prioritization for languages with strong attack patterns
    relevantLanguages.splice(
      0,
      relevantLanguages.length,
      ...prioritizeLanguages(relevantLanguages, [
        { code: "rus", minConfidence: 0.8 },
        { code: "deu", minConfidence: 0.7 },
      ])
    );

    const hasScriptMixing = detectScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);

    if (hasScriptMixing) {
      context.flags.push(SecurityFlags.INSTRUCTION_HIJACKING_SCRIPT_MIXING);
    }

    if (hasLookalikes) {
      context.flags.push(SecurityFlags.INSTRUCTION_HIJACKING_LOOKALIKES);
    }

    const detectionResults = [];
    let maxRiskScore = 0;
    let maxConfidence = 0;
    const allAttackTypes = new Set<AttackType>();

    for (const [iso3Code, confidence] of relevantLanguages) {
      try {
        const result = intrusionDetector.detect(context.sanitized, iso3Code);

        detectionResults.push({
          language: iso3Code,
          result,
          detectionConfidence: confidence,
        });

        maxRiskScore = Math.max(maxRiskScore, result.risk_score);
        maxConfidence = Math.max(maxConfidence, result.confidence);

        result.attack_types.forEach((attackType) =>
          allAttackTypes.add(attackType as AttackType)
        );
      } catch (error) {
        console.error(
          `Error detecting attacks for language ${iso3Code}:`,
          error
        );
      }
    }

    const attackTypesArray = Array.from(allAttackTypes);
    const threshold =
      instructionPatternsConfig.config.instruction_hijacking_threshold;
    const isAttack = attackTypesArray.length > 0 && maxConfidence > threshold;

    if (isAttack) {
      const flagSet = new Set(context.flags);
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

      if (relevantLanguages.length > 1) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK);
      }

      context.flags = Array.from(flagSet);

      const threatLevel =
        maxConfidence > 0.7
          ? ThreatLevel.CRITICAL
          : maxConfidence > 0.5
            ? ThreatLevel.HIGH
            : maxConfidence > 0.3
              ? ThreatLevel.MEDIUM
              : ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);
    }

    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;
    context.metadata.instruction_hijacking_attack_types = attackTypesArray;
    context.metadata.instruction_hijacking_risk_score = maxRiskScore / 100;
    context.metadata.instruction_hijacking_confidence = maxConfidence;
    context.metadata.instruction_hijacking_detected_languages =
      relevantLanguages.map(([iso3]) => iso3);

    return next();
  };
}
