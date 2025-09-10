import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ChainmailContext } from "../../types";
import { HTTP_FETCH_PRIVATE_RANGES } from "./http-fetch.const";

/**
 * @description
 * Makes HTTP requests to external services for content validation,
 * threat intelligence, or additional security checks.
 */
export function httpFetch(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
    validateResponse?: (response: Response, data: unknown) => boolean;
    onSuccess?: (context: ChainmailContext, data: unknown) => void;
    onError?: (context: ChainmailContext, error: Error) => void;
    allowedHosts?: string[];
    maxResponseSize?: number;
  } = {}
): ChainmailRivet {
  return async (context, next) => {
    const {
      method = "POST",
      headers = { "Content-Type": "application/json" },
      timeoutMs = 5000,
      validateResponse,
      onSuccess,
      onError,
      allowedHosts = [],
      maxResponseSize = 1024 * 1024,
    } = options;

    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();

      if (
        HTTP_FETCH_PRIVATE_RANGES.some((range) => hostname.startsWith(range))
      ) {
        context.flags.push(SecurityFlags.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error =
          "Private/local IP addresses are not allowed";
        return next();
      }

      if (allowedHosts.length > 0 && !allowedHosts.includes(hostname)) {
        context.flags.push(SecurityFlags.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error = `Host ${hostname} is not in allowlist`;
        return next();
      }

      if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        context.flags.push(SecurityFlags.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error = "Only HTTP/HTTPS protocols are allowed";
        return next();
      }
    } catch {
      context.flags.push(SecurityFlags.HTTP_ERROR);
      applyThreatPenalty(context, ThreatLevel.HIGH);
      context.metadata.http_error = "Invalid URL format";
      return next();
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: JSON.stringify({ input: context.sanitized }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const contentLength = response.headers.get("content-length");
      if (contentLength && parseInt(contentLength) > maxResponseSize) {
        context.flags.push(SecurityFlags.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.http_error = `Response size ${contentLength} exceeds limit ${maxResponseSize}`;
        return next();
      }

      const data = await response.json();

      if (validateResponse && !validateResponse(response, data)) {
        context.flags.push(SecurityFlags.HTTP_VALIDATION_FAILED);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_validation_error = "Response validation failed";
      } else {
        context.flags.push(SecurityFlags.HTTP_VALIDATED);
        context.metadata.http_response = data;

        if (onSuccess) {
          onSuccess(context, data);
        }
      }
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error) {
        if (error.name === "AbortError") {
          context.flags.push(SecurityFlags.HTTP_TIMEOUT);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.http_error = `Request timed out after ${timeoutMs}ms`;
        } else {
          context.flags.push(SecurityFlags.HTTP_ERROR);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.http_error = error.message;
        }

        if (onError) {
          onError(context, error);
        }
      }
    }

    return next();
  };
}
