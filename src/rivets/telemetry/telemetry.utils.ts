import { TelemetryProvider } from "./telemetry.types";
import { ThreatLevel } from "../rivets.types";
import { LogLevel } from "vite";

export const createConsoleProvider = (): TelemetryProvider => ({
  logSecurityEvent: (event) =>
    console.warn(`[Security] ${event.type}:`, event.message, event.context),
  trackMetric: (name, value, tags) =>
    console.info(`[Metric] ${name}:`, value, tags),
  captureError: (error, context) =>
    console.error("[Error]", error.message, context),
  addBreadcrumb: (message, data) =>
    console.debug("[Breadcrumb]", message, data),
});

export const createSentryProvider = (sentry: {
  addBreadcrumb: (breadcrumb: Record<string, unknown>) => void;
  captureMessage: (message: string, level: string) => void;
  captureException: (error: Error, options?: Record<string, unknown>) => void;
}): TelemetryProvider => ({
  logSecurityEvent: (event) => {
    sentry.addBreadcrumb({
      category: "security",
      message: event.message,
      level: event.threat_level,
      data: event.context,
    });
    if (
      event.threat_level === ThreatLevel.HIGH ||
      event.threat_level === ThreatLevel.CRITICAL
    ) {
      sentry.captureMessage(`Security Event: ${event.message}`, "error");
    }
  },
  trackMetric: (name, value, tags) =>
    sentry.addBreadcrumb({
      category: "metric",
      message: `${name}: ${value}`,
      data: { value, ...tags },
    }),
  captureError: (error, context) =>
    sentry.captureException(error, { extra: context }),
  addBreadcrumb: (message, data) => sentry.addBreadcrumb({ message, data }),
});

export const createDatadogProvider = (
  tracer: {
    scope: () => {
      active: () => {
        setTag: (key: string, value: unknown) => void;
        log: (data: Record<string, unknown>) => void;
      } | null;
    };
    dogstatsd?: {
      increment: (name: string, value: number, tags?: string[]) => void;
      gauge: (name: string, value: number, tags?: string[]) => void;
    };
  },
  logger: {
    info?: (message: string, data?: Record<string, unknown>) => void;
    warn?: (message: string, data?: Record<string, unknown>) => void;
    error?: (message: string, data?: Record<string, unknown>) => void;
    debug?: (message: string, data?: Record<string, unknown>) => void;
  }
): TelemetryProvider => ({
  logSecurityEvent: (event) => {
    if (logger?.info)
      logger.info("Security Event", {
        type: event.type,
        threat_level: event.threat_level,
        message: event.message,
        context: event.context,
      });
    if (tracer) {
      const span = tracer.scope().active();
      if (span) {
        span.setTag("security.event.type", event.type);
        span.setTag("security.event.threat_level", event.threat_level);
        span.setTag("security.blocked", event.context.blocked);
      }
      if (tracer.dogstatsd) {
        tracer.dogstatsd.increment("chainmail.security.event", 1, [
          `type:${event.type}`,
          `threat_level:${event.threat_level}`,
          `blocked:${event.context.blocked}`,
        ]);
      }
    }
  },
  trackMetric: (name, value, tags) => {
    if (tracer?.dogstatsd) {
      const tagArray = tags
        ? Object.entries(tags).map(([k, v]) => `${k}:${v}`)
        : [];
      tracer.dogstatsd.gauge(`chainmail.${name}`, value, tagArray);
    }
    if (logger?.info) logger.info("Metric", { name, value, tags });
  },
  captureError: (error, context) => {
    if (logger?.error)
      logger.error("Error captured", {
        error: error.message,
        stack: error.stack,
        context,
      });
    if (tracer) {
      const span = tracer.scope().active();
      if (span) {
        span.setTag("error", true);
        span.setTag("error.message", error.message);
        span.setTag("error.kind", error.name);
      }
      if (tracer.dogstatsd) {
        tracer.dogstatsd.increment("chainmail.error", 1, [
          `error_type:${error.name}`,
        ]);
      }
    }
  },
  addBreadcrumb: (message, data) => {
    if (logger?.debug) logger.debug("Breadcrumb", { message, data });
    if (tracer) {
      const span = tracer.scope().active();
      if (span) {
        span.log({ event: "breadcrumb", message, ...data });
      }
    }
  },
});

export const createNewRelicProvider = (newrelic: {
  recordCustomEvent: (name: string, data: Record<string, unknown>) => void;
  recordMetric: (name: string, value: number) => void;
  noticeError?: (
    error: Error,
    customAttributes?: Record<string, unknown>
  ) => void;
  addCustomAttribute?: (key: string, value: unknown) => void;
}): TelemetryProvider => ({
  logSecurityEvent: (event) => {
    newrelic.recordCustomEvent("ChainmailSecurityEvent", {
      type: event.type,
      threat_level: event.threat_level,
      message: event.message,
      blocked: event.context.blocked,
      confidence: event.context.confidence,
      flags: event.context.flags.join(","),
      session_id: event.context.session_id,
    });
    if (
      event.threat_level === ThreatLevel.HIGH ||
      event.threat_level === ThreatLevel.CRITICAL
    ) {
      newrelic.noticeError?.(new Error(event.message), {
        customAttributes: {
          eventType: event.type,
          threat_level: event.threat_level,
        },
      });
    }
  },
  trackMetric: (name, value, tags) => {
    newrelic.recordMetric(`Custom/Chainmail/${name}`, value);
    if (tags) {
      Object.entries(tags).forEach(([key, val]) => {
        newrelic.addCustomAttribute?.(`chainmail.${key}`, String(val));
      });
    }
  },
  captureError: (error, context) => {
    newrelic.noticeError?.(error, {
      customAttributes: {
        chainmailContext: JSON.stringify(context),
        errorSource: "prompt-chainmail",
      },
    });
  },
  addBreadcrumb: (message, data) => {
    newrelic.addCustomAttribute?.("chainmail.lastAction", message);
    if (data && Object.keys(data).length > 0) {
      newrelic.addCustomAttribute?.(
        "chainmail.lastActionData",
        JSON.stringify(data)
      );
    }
  },
});

export function getThreatLevelFromConfidenceScore(
  confidence?: number
): ThreatLevel {
  if (!confidence) return ThreatLevel.LOW;
  if (confidence > 0.8) return ThreatLevel.CRITICAL;
  if (confidence > 0.6) return ThreatLevel.HIGH;
  if (confidence > 0.3) return ThreatLevel.MEDIUM;
  return ThreatLevel.LOW;
}

export function getLogLevelFromConfidence(confidence: number): LogLevel {
  if (confidence < 0.5) return "error";
  if (confidence < 0.7) return "warn";
  return "info";
}

export function validateProvider(
  provider: unknown
): provider is TelemetryProvider {
  return (
    !!provider &&
    typeof provider === "object" &&
    typeof (provider as Record<string, unknown>).logSecurityEvent ===
      "function" &&
    typeof (provider as Record<string, unknown>).trackMetric === "function" &&
    typeof (provider as Record<string, unknown>).captureError === "function" &&
    typeof (provider as Record<string, unknown>).addBreadcrumb === "function"
  );
}
