import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { TEMPLATE_INJECTION_PATTERNS } from "./template-injection.const";

/**
 * @description
 * Detects template injection attacks using common template syntax patterns
 * like {{...}}, ${...}, <%...%>, and [[...]] that could execute code.
 */
export function templateInjection(): ChainmailRivet {
  return async (context, next) => {
    for (const pattern of TEMPLATE_INJECTION_PATTERNS) {
      if (pattern.test(context.sanitized)) {
        context.flags.push(SecurityFlags.TEMPLATE_INJECTION);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.template_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
