import { ChainmailRivet } from "../../index";
import { ChainmailContext } from "../../types";

type LogLevel = "log" | "warn" | "debug" | "info";

/**
 * @description
 * Logs processing details and performance metrics for debugging
 * and monitoring purposes with customizable logging functions.
 */
export function logger(
  level: LogLevel = "log",
  logFn?: (context: ChainmailContext) => void
): ChainmailRivet {
  return async (context, next) => {
    const start = Date.now();
    const result = await next();
    const duration = Date.now() - start;

    const logData = {
      flags: context.flags,
      confidence: context.confidence,
      blocked: context.blocked,
      duration,
      input_length: context.input?.length,
    };

    if (logFn) {
      logFn(context);
    } else {
      console[level]("[PromptChainmail]", logData);
    }

    return result;
  };
}
