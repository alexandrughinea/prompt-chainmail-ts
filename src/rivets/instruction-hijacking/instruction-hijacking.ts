import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import {
  detectLanguages,
  detectScriptMixing,
  detectLookalikeChars,
  calculateWeightedConfidence,
} from "../language-detection";
import { applyThreatPenalty } from "../rivets.utils";
import { ChainmailContext } from "../../types";
import { detectInstructionHijackingAttackTypes } from "./instruction-hijacking.utils";

export function instructionHijacking(): ChainmailRivet {
  return async (context: ChainmailContext, next) => {
    const languages = detectLanguages(context.sanitized);
    const hasScriptMixing = detectScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);

    const detectedAttackTypes = detectInstructionHijackingAttackTypes(context.sanitized, languages);

    const attackingLanguages = new Set<string>();
    let totalMatches = 0;

    for (const lang of languages) {
      if (detectedAttackTypes.length > 0) {
        attackingLanguages.add(lang.code);
        totalMatches++;
      }
    }

    const baseConfidence = Math.min(totalMatches * 0.25, 1.0);
    const riskScore = calculateWeightedConfidence(
      baseConfidence,
      languages,
      hasScriptMixing,
      hasLookalikes
    );

    if (totalMatches > 0 || detectedAttackTypes.length > 0) {
      context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING);

      detectedAttackTypes.forEach(attackType => {
        switch (attackType) {
          case "INSTRUCTION_OVERRIDE":
            context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_OVERRIDE);
            break;
          case "INSTRUCTION_FORGETTING":
            context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_IGNORE);
            break;
          case "RESET_SYSTEM":
            context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_RESET);
            break;
          case "BYPASS_SECURITY":
            context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_BYPASS);
            break;
          case "INFORMATION_EXTRACTION":
            context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_REVEAL);
            break;
        }
      });

      if (attackingLanguages.size > 1) {
        context.flags.push(SecurityFlag.MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing || hasLookalikes) {
        context.flags.push(SecurityFlag.INSTRUCTION_HIJACKING_SCRIPT_MIXING);
      }

      let threatLevel: ThreatLevel;
      if (riskScore >= 0.8) threatLevel = ThreatLevel.CRITICAL;
      else if (riskScore >= 0.6) threatLevel = ThreatLevel.HIGH;
      else if (riskScore >= 0.4) threatLevel = ThreatLevel.MEDIUM;
      else threatLevel = ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);

      context.metadata.instruction_hijacking_attack_types = detectedAttackTypes;
      context.metadata.instruction_hijacking_detected_languages = languages.map(l => l.code);
      context.metadata.instruction_hijacking_confidence = baseConfidence;
      context.metadata.instruction_hijacking_risk_score = riskScore;
      context.metadata.has_script_mixing = hasScriptMixing;
      context.metadata.has_lookalikes = hasLookalikes;
      context.metadata.instruction_hijacking_threat_level = threatLevel;
    }

    return next();
  };
}
