import { ChainmailRivet } from "../../index";
import { ChainmailContext } from "../../types";

export function logger(logFn?: (context: ChainmailContext) => void): ChainmailRivet {
  return async (context, next) => {
    const start = Date.now();
    const result = await next();
    const duration = Date.now() - start;

    const logData = {
      flags: context.flags,
      confidence: context.confidence,
      blocked: context.blocked,
      duration,
      inputLength: context.input.length,
    };

    if (logFn) {
      logFn(context);
    } else {
      console.log("[PromptChainmail]", logData);
    }

    return result;
  };
}
