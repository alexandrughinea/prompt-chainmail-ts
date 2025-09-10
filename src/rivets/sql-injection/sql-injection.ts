import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { SQL_INJECTION_PATTERNS } from "./slq-injection.const";

/**
 * @description
 * Detects SQL injection attempts by scanning for malicious SQL keywords,
 * union queries, and database manipulation commands.
 */
export function sqlInjection(): ChainmailRivet {
  return async (context, next) => {
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlags.SQL_INJECTION);
        applyThreatPenalty(context, ThreatLevel.CRITICAL);
        context.metadata.sql_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
