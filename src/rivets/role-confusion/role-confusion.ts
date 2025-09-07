import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import {
  detectLanguages,
  detectScriptMixing,
  detectLookalikeChars,
  calculateWeightedConfidence,
} from "../language-detection";
import { applyThreatPenalty } from "../rivets.utils";
import { ROLE_CONFUSION_PATTERNS_BY_LANGUAGE, ROLE_INDICATORS, ROLE_CONFUSION_ATTACK_TYPE_MAP, PERMISSION_ASSERTION_KEYWORDS_BY_LANGUAGE } from "../rivets.const";
import { ChainmailContext } from "../../types";

export function roleConfusion(): ChainmailRivet {

  return async (context: ChainmailContext, next) => {
    const languages = detectLanguages(context.sanitized);
    const hasScriptMixing = detectScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);

    interface AttackDetection {
      type: string;
      language: string;
      patternIndex: number;
    }

    const detectedAttacks: AttackDetection[] = [];
    const attackingLanguages = new Set<string>();

    Object.entries(ROLE_CONFUSION_PATTERNS_BY_LANGUAGE).forEach(([langCode, patterns]) => {
      const attackTypes = ROLE_CONFUSION_ATTACK_TYPE_MAP;

      patterns.forEach((pattern, index) => {
        if (pattern.test(context.sanitized)) {
          let attackType = attackTypes[index] || 'UNKNOWN';

          if (index === 0 && attackType === 'ROLE_ASSUMPTION') {
            const match = pattern.exec(context.sanitized);
            if (match) {
              const keywords = PERMISSION_ASSERTION_KEYWORDS_BY_LANGUAGE[langCode as keyof typeof PERMISSION_ASSERTION_KEYWORDS_BY_LANGUAGE] || [];
              const hasPermissionKeyword = keywords.some((keyword: string) => 
                match[0].toLowerCase().includes(keyword.toLowerCase())
              );
              if (hasPermissionKeyword) {
                attackType = 'PERMISSION_ASSERTION';
              }
            }
          }

          detectedAttacks.push({
            type: attackType,
            language: langCode,
            patternIndex: index
          });
          attackingLanguages.add(langCode);
        }
      });
    });

    const totalMatches = detectedAttacks.length;
    const detectedAttackTypes = [...new Set(detectedAttacks.map(a => a.type))];

    const roleIndicatorRegex = new RegExp(ROLE_INDICATORS, 'i');
    const roleIndicatorMatch = roleIndicatorRegex.exec(context.sanitized);
    const baseConfidence = Math.max(totalMatches * 0.3, roleIndicatorMatch ? 0.3 : 0);

    const riskScore = calculateWeightedConfidence(
      baseConfidence,
      languages,
      hasScriptMixing,
      hasLookalikes
    );

    if (totalMatches > 0 || roleIndicatorMatch) {
      context.flags.push(SecurityFlag.ROLE_CONFUSION);

      // Add specific attack type flags
      if (detectedAttackTypes.includes('ROLE_ASSUMPTION')) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION_ROLE_ASSUMPTION);
      }
      if (detectedAttackTypes.includes('MODE_SWITCHING')) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION_MODE_SWITCHING);
      }
      if (detectedAttackTypes.includes('PERMISSION_ASSERTION')) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION_PERMISSION_ASSERTION);
      }

      if (attackingLanguages.size > 1) {
        context.flags.push(SecurityFlag.MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing || hasLookalikes) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION_SCRIPT_MIXING);
      }


      let threatLevel: ThreatLevel;
      if (riskScore >= 0.8) threatLevel = ThreatLevel.CRITICAL;
      else if (riskScore >= 0.6) threatLevel = ThreatLevel.HIGH;
      else if (riskScore >= 0.4) threatLevel = ThreatLevel.MEDIUM;
      else threatLevel = ThreatLevel.LOW;

      applyThreatPenalty(context, threatLevel);

      context.metadata.role_confusion_detected = true;
      context.metadata.role_confusion_confidence = riskScore;
      context.metadata.role_confusion_risk_score = riskScore;
      context.metadata.role_confusion_attack_types = detectedAttackTypes;
      context.metadata.role_confusion_detected_languages = languages.map(l => l.code);
      context.metadata.role_indicator = roleIndicatorMatch ? roleIndicatorMatch[0].toLowerCase() : undefined;
      context.metadata.attack_types = detectedAttackTypes;
      context.metadata.attacking_languages = Array.from(attackingLanguages);
      context.metadata.has_script_mixing = hasScriptMixing;
      context.metadata.has_lookalikes = hasLookalikes;

    }

    return next();
  };
}