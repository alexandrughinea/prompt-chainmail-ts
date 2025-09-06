import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { createRolePattern, applyThreatPenalty } from "../rivets.utils";
import { ROLE_INDICATORS, SECURITY_COMPONENTS } from "../rivets.const";

export function roleConfusion(): ChainmailRivet {
  return async (context, next) => {
    const lower = context.sanitized.toLowerCase();
    const roleIndicators = ROLE_INDICATORS.split("|");
    const roleActions = SECURITY_COMPONENTS.ROLE_ACTIONS.split("|");
    const roleConfusionPatterns = roleActions.map((action, index) => ({
      pattern: createRolePattern(action),
      name: `role_action_${index}`,
    }));

    const beRolePattern = new RegExp(
      SECURITY_COMPONENTS.ROLE_CHANGE,
      "i"
    );

    for (const indicator of roleIndicators) {
      if (lower.includes(indicator)) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.roleIndicator = indicator;
        return next();
      }
    }

    for (const { pattern, name } of roleConfusionPatterns) {
      if (pattern.test(context.sanitized)) {
        if (!context.flags.includes(SecurityFlag.ROLE_CONFUSION)) {
          context.flags.push(SecurityFlag.ROLE_CONFUSION);
        }
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.roleConfusionName = name;
        context.metadata.roleConfusionPattern = pattern.toString();
        break;
      }
    }

    if (beRolePattern.test(context.sanitized)) {
      if (!context.flags.includes(SecurityFlag.ROLE_CONFUSION)) {
        context.flags.push(SecurityFlag.ROLE_CONFUSION);
      }
      applyThreatPenalty(context, ThreatLevel.HIGH);
      context.metadata.roleConfusionName = "be_role_pattern";
      context.metadata.roleConfusionPattern = beRolePattern.toString();
    }

    return next();
  };
}
