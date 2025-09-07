import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function delimiterConfusion(): ChainmailRivet {
  const delimiterPatterns = [
    /"""|'''/g,
    /<\/prompt>|<\/system>|<\/instruction>/i,
    /\[END\]|\[STOP\]|\[DONE\]/i,
    /---END---|===END===/i,
    /\}\}\}|\{\{\{/g,
    /\$\$\$|###/g,
    /\[\/INST\]|\[INST\]/i,
    /<\|endoftext\|>|<\|im_end\|>/i,
    /```[\s\S]*?```/g,
    /<!--[\s\S]*?-->/g,
    /<system>[\s\S]*?<\/system>/i,
    /\[SYSTEM\][\s\S]*?\[\/SYSTEM\]/i,
  ];

  return async (context, next) => {
    for (const pattern of delimiterPatterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlag.DELIMITER_CONFUSION);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.delimiter_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
