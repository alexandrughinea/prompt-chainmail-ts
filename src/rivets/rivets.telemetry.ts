import type { ChainmailRivet } from "../index";

type LogLevel = "debug" | "info" | "warn" | "error";
export type TelemetryData = {
  session_id: string;
  flags: string[];
  confidence: number;
  processing_time: number;
  input_length: number;
  blocked: boolean;
  success: boolean;
};

export type TelemetryOptions = {
  logFn?: (level: LogLevel, message: string, data: TelemetryData) => void;
  track_metrics?: boolean;
  logErrors?: boolean;
  provider?: "console" | "sentry" | "datadog" | "newrelic" | TelemetryProvider;
};

export interface TelemetryProvider {
  logSecurityEvent(event: SecurityEvent): void;
  trackMetric(name: string, value: number, tags?: Record<string, string>): void;
  captureError(error: Error, context?: Record<string, unknown>): void;
  addBreadcrumb(message: string, data?: Record<string, unknown>): void;
}

export interface SecurityEvent {
  type: "prompt_injection" | "security_violation" | "processing_error";
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  context: TelemetryData;
  metadata?: Record<string, unknown>;
}

const getSeverityFromConfidence = (
  confidence: number
): "low" | "medium" | "high" | "critical" => {
  if (confidence < 0.3) return "critical";
  if (confidence < 0.5) return "high";
  if (confidence < 0.7) return "medium";
  return "low";
};

const getLogLevelFromConfidence = (confidence: number): LogLevel => {
  if (confidence < 0.5) return "error";
  if (confidence < 0.7) return "warn";
  return "info";
};

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

const validateProvider = (provider: unknown): provider is TelemetryProvider => {
  return (
    !!provider &&
    typeof provider === "object" &&
    typeof (provider as Record<string, unknown>).logSecurityEvent ===
      "function" &&
    typeof (provider as Record<string, unknown>).trackMetric === "function" &&
    typeof (provider as Record<string, unknown>).captureError === "function" &&
    typeof (provider as Record<string, unknown>).addBreadcrumb === "function"
  );
};

export const createSentryProvider = (sentry: {
  addBreadcrumb: (breadcrumb: Record<string, unknown>) => void;
  captureMessage: (message: string, level: string) => void;
  captureException: (error: Error, options?: Record<string, unknown>) => void;
}): TelemetryProvider => ({
  logSecurityEvent: (event) => {
    sentry.addBreadcrumb({
      category: "security",
      message: event.message,
      level: event.severity,
      data: event.context,
    });
    if (event.severity === "high" || event.severity === "critical") {
      sentry.captureMessage(`Security Event: ${event.message}`, event.severity);
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
        severity: event.severity,
        message: event.message,
        context: event.context,
      });
    if (tracer) {
      const span = tracer.scope().active();
      if (span) {
        span.setTag("security.event.type", event.type);
        span.setTag("security.event.severity", event.severity);
        span.setTag("security.blocked", event.context.blocked);
      }
      // Use DogStatsD client if available
      if (tracer.dogstatsd) {
        tracer.dogstatsd.increment("chainmail.security.event", 1, [
          `type:${event.type}`,
          `severity:${event.severity}`,
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
      severity: event.severity,
      message: event.message,
      blocked: event.context.blocked,
      confidence: event.context.confidence,
      flags: event.context.flags.join(","),
      session_id: event.context.session_id,
    });
    if (event.severity === "high" || event.severity === "critical") {
      newrelic.noticeError?.(new Error(event.message), {
        customAttributes: {
          chainmailEvent: true,
          eventType: event.type,
          severity: event.severity,
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

export function telemetry(options: TelemetryOptions = {}): ChainmailRivet {
  const {
    logFn = (level, message, data) => {
      const logLevel =
        level === "error" ? "error" : level === "warn" ? "warn" : "info";
      console[logLevel]("[Chainmail]", message, data);
    },
    track_metrics = true,
    logErrors = true,
    provider,
  } = options;

  const telemetryProvider =
    provider && validateProvider(provider) ? provider : null;

  return async (context, next) => {
    const startTime = Date.now();

    telemetryProvider?.addBreadcrumb("Processing started", {
      sessionId: context.session_id,
      inputLength: context.input.length,
    });

    try {
      const result = await next();
      const processingTime = Date.now() - startTime;

      const telemetryData: TelemetryData = {
        session_id: context.session_id,
        flags: context.flags,
        confidence: context.confidence,
        processing_time: processingTime,
        input_length: context.input.length,
        blocked: context.blocked,
        success: result.success,
      };

      if (telemetryProvider) {
        telemetryProvider.trackMetric("processing_time", processingTime, {
          success: result.success.toString(),
          flags_count: context.flags.length.toString(),
        });

        if (!result.success || context.flags.length > 0) {
          const severity = getSeverityFromConfidence(context.confidence);

          telemetryProvider.logSecurityEvent({
            type: context.blocked ? "security_violation" : "prompt_injection",
            severity,
            message: `Security check ${result.success ? "passed" : "failed"}: ${context.flags.join(", ")}`,
            context: telemetryData,
          });
        }
      }

      if (!telemetryProvider && track_metrics) {
        logFn(
          "info",
          `Processing completed in ${processingTime}ms`,
          telemetryData
        );

        if (!result.success || context.flags.length > 0) {
          const level: LogLevel = getLogLevelFromConfidence(context.confidence);

          logFn(
            level,
            `Security flags detected: ${context.flags.join(", ")}`,
            telemetryData
          );
        }
      }

      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;

      const telemetryData: TelemetryData = {
        session_id: context.session_id,
        flags: context.flags,
        confidence: context.confidence,
        processing_time: processingTime,
        input_length: context.input.length,
        blocked: context.blocked,
        success: false,
      };

      if (telemetryProvider) {
        telemetryProvider.captureError(error as Error, telemetryData);
        telemetryProvider.logSecurityEvent({
          type: "processing_error",
          severity: "high",
          message: `Processing failed: ${(error as Error).message}`,
          context: telemetryData,
        });
      }

      if (!telemetryProvider && logErrors) {
        logFn(
          "error",
          `Processing failed: ${(error as Error).message}`,
          telemetryData
        );
      }

      throw error;
    }
  };
}
