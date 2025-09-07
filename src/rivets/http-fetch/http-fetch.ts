import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlag } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ChainmailContext } from "../../types";

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
      const privateRanges = [
        "127.",
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "localhost",
        "0.0.0.0",
        "::1",
        "fe80::",
      ];

      if (privateRanges.some((range) => hostname.startsWith(range))) {
        context.flags.push(SecurityFlag.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error =
          "Private/local IP addresses are not allowed";
        return next();
      }

      if (allowedHosts.length > 0 && !allowedHosts.includes(hostname)) {
        context.flags.push(SecurityFlag.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error = `Host ${hostname} is not in allowlist`;
        return next();
      }

      if (!["http:", "https:"].includes(parsedUrl.protocol)) {
        context.flags.push(SecurityFlag.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_error =
          "Only HTTP/HTTPS protocols are allowed";
        return next();
      }
    } catch (urlError) {
      context.flags.push(SecurityFlag.HTTP_ERROR);
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
        throw new Error(
          `HTTP ${response.status}: ${response.statusText}`
        );
      }

      const contentLength = response.headers.get("content-length");
      if (contentLength && parseInt(contentLength) > maxResponseSize) {
        context.flags.push(SecurityFlag.HTTP_ERROR);
        applyThreatPenalty(context, ThreatLevel.MEDIUM);
        context.metadata.http_error = `Response size ${contentLength} exceeds limit ${maxResponseSize}`;
        return next();
      }

      const data = await response.json();

      if (validateResponse && !validateResponse(response, data)) {
        context.flags.push(SecurityFlag.HTTP_VALIDATION_FAILED);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.http_validation_error =
          "Response validation failed";
      } else {
        context.flags.push(SecurityFlag.HTTP_VALIDATED);
        context.metadata.http_response = data;

        if (onSuccess) {
          onSuccess(context, data);
        }
      }
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error) {
        if (error.name === "AbortError") {
          context.flags.push(SecurityFlag.HTTP_TIMEOUT);
          applyThreatPenalty(context, ThreatLevel.MEDIUM);
          context.metadata.http_error = `Request timed out after ${timeoutMs}ms`;
        } else {
          context.flags.push(SecurityFlag.HTTP_ERROR);
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
