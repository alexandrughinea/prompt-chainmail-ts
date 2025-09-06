import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function templateInjection(): ChainmailRivet {
  const templatePatterns = [
    /\{\{.*\}\}/g,
    /\$\{.*\}/g,
    /<%.*%>/g,
    /\[\[.*\]\]/g,
    /#{.*}/g,
    /{%.*%}/g,
    /{php}.*{\/php}/gi,
    /{literal}.*{\/literal}/gi,
    /{if.*}.*{\/if}/gi,
  ];

  return async (context, next) => {
    for (const pattern of templatePatterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlag.TEMPLATE_INJECTION);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.templatePattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
