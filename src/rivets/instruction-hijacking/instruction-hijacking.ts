import { ChainmailRivet } from "../../index";
import { SecurityFlag, SupportedLanguages } from "../rivets.types";
import {
  detectLanguages,
  detectScriptMixing,
  detectLookalikeChars,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext } from "../../types";
import { MultilingualIntrusionDetector } from "./instruction-hijacking.utils";
import { AttackType } from "./instruction-hijacking.types";

/**
 * @description
 * This is a stub and will be implemented in the future to detect and flag more precisely with other strategies.
 */
export function instructionHijacking(): ChainmailRivet {
  const languageDetector = new LanguageDetector({
    enableMultipleDetection: true,
    minConfidence: 0.1,
  });
  const intrusionDetector = new MultilingualIntrusionDetector();

  return async (context: ChainmailContext, next) => {
    const languages = languageDetector.detect(context.sanitized);
    const hasScriptMixing = detectScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);

    // Store script mixing and lookalike detection results
    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    // Add script mixing and lookalike character flags
    if (hasScriptMixing) {
      context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_SCRIPT_MIXING);
    }

    if (hasLookalikes) {
      context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_LOOKALIKES);
    }

    // Run intrusion detection for each detected language
    const detectionResults = [];
    let maxRiskScore = 0;
    let maxConfidence = 0;
    const allAttackTypes = new Set<AttackType>();

    // Use detected languages, but always include English as fallback
    const languagesToCheck = languages.length > 0 ? [...languages, SupportedLanguages.EN] : [SupportedLanguages.EN];

    for (const language of languagesToCheck) {
      try {
        const languageCode = typeof language === 'string' ? language : language.code;
        const result = intrusionDetector.processDetection(context.sanitized, languageCode as SupportedLanguages);
        detectionResults.push(result);

        // Track the highest risk score and confidence across all languages
        maxRiskScore = Math.max(maxRiskScore, result.riskScore);
        maxConfidence = Math.max(maxConfidence, result.confidence);

        // Collect all attack types
        result.attackTypes.forEach(attackType => allAttackTypes.add(attackType));

      } catch (error) {
        // Log error but don't break the chain
        console.warn(`Intrusion detection failed for language ${language}:`, error);
      }
    }

    // Convert attack types set to array
    const attackTypesArray = Array.from(allAttackTypes);

    // Store detection metadata
    context.metadata.instruction_hijacking_attack_types = attackTypesArray;
    context.metadata.instruction_hijacking_risk_score = maxRiskScore / 100; // Normalize to 0-1 range
    context.metadata.instruction_hijacking_confidence = maxConfidence;
    context.metadata.instruction_hijacking_detected_languages = languages;
    

    // Determine if this is an attack - simplified logic
    const isAttack = attackTypesArray.length > 0;

    if (isAttack) {
      // Add general instruction hijacking flag
      if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING)) {
        context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING);
      }
      
      // Remove lookalike flag if genuine attack is detected
      const lookalikeIndex = context.flags.indexOf(SecurityFlag.INSTRUCTION_HIJACKING_LOOKALIKES);
      if (lookalikeIndex > -1) {
        context.flags.splice(lookalikeIndex, 1);
      }

      // Add specific security flags based on detected attack types
      attackTypesArray.forEach(attackType => {
        switch (attackType) {
          case AttackType.INSTRUCTION_OVERRIDE:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_OVERRIDE)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_OVERRIDE);
            }
            break;
          case AttackType.INSTRUCTION_FORGETTING:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_IGNORE)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_IGNORE);
            }
            break;
          case AttackType.RESET_SYSTEM:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_RESET)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_RESET);
            }
            break;
          case AttackType.BYPASS_SECURITY:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_BYPASS)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_BYPASS);
            }
            break;
          case AttackType.INFORMATION_EXTRACTION:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_REVEAL)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_REVEAL);
            }
            break;
          default:
            if (!context.flags.includes(SecurityFlag.INSTRUCTION_HIJACKING_UNKNOWN)) {
              context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_UNKNOWN);
            }
        }
      });

      // Add multilingual attack flag if multiple languages detected
      if (languages.length > 1) {
        if (!context.flags.includes(SecurityFlag.MULTILINGUAL_ATTACK)) {
          context.flags.push(SecurityFlag.MULTILINGUAL_ATTACK);
        }
      }

      // Set overall confidence based on detection results
      context.confidence = Math.min(context.confidence || 1.0, 1.0 - maxConfidence);
    }

    return next();
  };
}