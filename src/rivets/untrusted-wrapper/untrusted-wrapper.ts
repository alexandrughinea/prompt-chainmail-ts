import { ChainmailRivet } from "../../index";
import { SecurityFlags } from "../rivets.types";

/**
 * @description
 * Wraps untrusted content with a specified tag for additional security handling and optionally preserves the original content.
 */
export function untrustedWrapper(
  tagName = "UNTRUSTED_CONTENT",
  preserveOriginal = false
): ChainmailRivet {
  return async (context, next) => {
    const wrappedContent = `<${tagName}>\n${context.sanitized}\n</${tagName}>`;

    if (preserveOriginal) {
      context.metadata.original_content = context.sanitized;
    }

    context.sanitized = wrappedContent;
    context.flags.push(SecurityFlags.UNTRUSTED_WRAPPED);

    return next();
  };
}
