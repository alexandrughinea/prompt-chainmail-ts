import { SecurityFlags, ThreatLevel } from "../rivets.types";

type TelemetryLogLevel = "debug" | "info" | "warn" | "error" | "silent";

export enum TelemetryEventType {
  PROCESSING_ERROR = "processing_error",

  THREAT_DETECTED = "threat_detected",
  THREAT_BLOCKED = "threat_blocked",
  SECURITY_SCAN = "security_scan",
}

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
  logFn?: (
    level: TelemetryLogLevel,
    message: string,
    data: TelemetryData
  ) => void;
  track_metrics?: boolean;
  logErrors?: boolean;
  provider?: "console" | "sentry" | "datadog" | "newrelic" | TelemetryProvider;
};

export interface TelemetryProvider {
  logSecurityEvent(event: TelemetryEvent): void;
  trackMetric(name: string, value: number, tags?: Record<string, string>): void;
  captureError(error: Error, context?: Record<string, unknown>): void;
  addBreadcrumb(message: string, data?: Record<string, unknown>): void;
}

export interface TelemetryEvent {
  type: TelemetryEventType;
  threat_level: ThreatLevel;
  message: string;
  context: TelemetryData;
  metadata?: Record<string, unknown>;
  flags?: SecurityFlags[];
  risk_score?: number;
  attack_types?: string[];
}
