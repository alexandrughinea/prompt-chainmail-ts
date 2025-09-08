import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { CODE_INJECTION_REGEX } from "./code-injection.const";

/**
 * @description
 * Detects code injection attempts by scanning for dangerous code patterns,
 * system commands, and script execution attempts across multiple languages.
 */
export function codeInjection(): ChainmailRivet {
  return async (context, next) => {
    for (const pattern of CODE_INJECTION_REGEX) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlags.CODE_INJECTION);
        applyThreatPenalty(context, ThreatLevel.CRITICAL);
        context.metadata.code_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
