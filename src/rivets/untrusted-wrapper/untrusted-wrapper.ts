import { ChainmailRivet } from "../../index";
import { SecurityFlag } from "../rivets.types";

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
    context.flags.push(SecurityFlag.UNTRUSTED_WRAPPED);

    return next();
  };
}
