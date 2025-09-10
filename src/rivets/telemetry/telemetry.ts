import type { ChainmailRivet } from "../../index";
import { LogLevel } from "vite";
import {
  TelemetryData,
  TelemetryEventType,
  TelemetryOptions,
  TelemetryProvider,
} from "./telemetry.types";
import { SecurityFlags, ThreatLevel } from "../rivets.types";

const getThreatLevelFromConfidenceScore = (confidence?: number): ThreatLevel => {
  if (!confidence) return ThreatLevel.LOW;
  if (confidence > 0.8) return ThreatLevel.CRITICAL;
  if (confidence > 0.6) return ThreatLevel.HIGH;
  if (confidence > 0.3) return ThreatLevel.MEDIUM;
  return ThreatLevel.LOW;
};

const getLogLevelFromConfidence = (confidence: number): LogLevel => {
  if (confidence < 0.5) return "error";
  if (confidence < 0.7) return "warn";
  return "info";
};


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
          const threatLevel = getThreatLevelFromConfidenceScore(context.confidence);
          const eventType = context.blocked 
            ? TelemetryEventType.THREAT_BLOCKED 
            : context.flags.length > 0 
              ? TelemetryEventType.THREAT_DETECTED 
              : TelemetryEventType.SECURITY_SCAN;
          
          telemetryProvider.logSecurityEvent({
            type: eventType,
            threat_level: threatLevel,
            message: `Security check ${result.success ? "passed" : "failed"}: ${context.flags.join(", ")}`,
            context: telemetryData,
            flags: context.flags as SecurityFlags[],
            risk_score: (context.metadata?.risk_score ?? undefined) as number,
            attack_types: (context.metadata?.attack_types ?? undefined) as string[],
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
        telemetryProvider.captureError(error as Error, telemetryData as Record<string, unknown>);
        telemetryProvider.logSecurityEvent({
          type: TelemetryEventType.PROCESSING_ERROR,
          threat_level: ThreatLevel.LOW,
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
