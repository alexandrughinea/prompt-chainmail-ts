import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";

export function sqlInjection(): ChainmailRivet {
  const sqlPatterns = [
    new RegExp(
      `\\b(union\\s+select|drop\\s+table|insert\\s+into|delete\\s+from)\\b`,
      "i"
    ),
    new RegExp(
      `\\b(select|insert|update|delete|create|alter|drop)\\s+.*\\s+(from|into|table|set)\\b`,
      "i"
    ),
    /\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1)\b/i,
    new RegExp(
      `\\b(exec|execute|sp_executesql|xp_cmdshell)\\s*\\(`,
      "i"
    ),
    /\b(xp_cmdshell|sp_oacreate|sp_oamethod)\b/i,
    /\b(waitfor\s+delay|benchmark\s*\()\b/i,
    /\b(information_schema|sysobjects|syscolumns)\b/i,
    /\b(load_file\s*\(|into\s+outfile|into\s+dumpfile)\b/i,
    /\b(char\s*\(|concat\s*\(|substring\s*\()\b/i,
    /\b(ascii\s*\(|hex\s*\(|unhex\s*\()\b/i,
  ];

  return async (context, next) => {
    for (const pattern of sqlPatterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlag.SQL_INJECTION);
        applyThreatPenalty(context, ThreatLevel.CRITICAL);
        context.metadata.sql_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
