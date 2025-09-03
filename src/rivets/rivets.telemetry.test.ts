import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  telemetry,
  createSentryProvider,
  createDatadogProvider,
  createNewRelicProvider,
  createConsoleProvider,
  TelemetryData,
} from "./rivets.telemetry";
import type { ChainmailContext, ChainmailResult } from "../index";

const createMockContext = (
  overrides: Partial<ChainmailContext> = {}
): ChainmailContext => ({
  session_id: "test-session-123",
  input: "test input",
  sanitized: "test input",
  flags: [],
  confidence: 0.8,
  blocked: false,
  metadata: {},
  start_time: Date.now(),
  ...overrides,
});

const createMockResult = (
  overrides: Partial<ChainmailResult> = {}
): ChainmailResult => ({
  success: true,
  context: createMockContext(),
  processing_time: 10,
  memory_usage: 1024,
  ...overrides,
});

describe("Telemetry Rivet", () => {
  let mockNext: ReturnType<typeof vi.fn<[], Promise<ChainmailResult>>>;
  let consoleSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mockNext = vi.fn<[], Promise<ChainmailResult>>();
    consoleSpy = vi.spyOn(console, "info").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should process successful requests with default console provider", async () => {
    const rivet = telemetry();
    const context = createMockContext();
    const result = createMockResult();

    mockNext.mockResolvedValue(result);

    const actualResult = await rivet(context, mockNext);

    expect(mockNext).toHaveBeenCalledOnce();
    expect(actualResult).toBe(result);
    expect(consoleSpy).toHaveBeenCalled();
  });

  it("should use custom logFn when provided", async () => {
    const mockLogFn = vi.fn();
    const rivet = telemetry({
      logFn: mockLogFn,
      track_metrics: true,
      provider: undefined,
    });
    const context = createMockContext();
    const result = createMockResult();

    mockNext.mockResolvedValue(result);

    await rivet(context, mockNext);

    expect(mockLogFn).toHaveBeenCalledWith(
      "info",
      expect.stringContaining("Processing completed"),
      expect.any(Object)
    );
  });

  it("should handle errors and log them when logErrors is enabled", async () => {
    const mockLogFn = vi.fn();
    const rivet = telemetry({
      logFn: mockLogFn,
      logErrors: true,
      provider: undefined,
    });
    const context = createMockContext();
    const error = new Error("Test error");

    mockNext.mockRejectedValue(error);

    await expect(rivet(context, mockNext)).rejects.toThrow("Test error");

    expect(mockLogFn).toHaveBeenCalledWith(
      "error",
      expect.stringContaining("Processing failed"),
      expect.objectContaining({
        success: false,
      })
    );
  });

  describe("Telemetry Provider Integrations", () => {
    let mockSecurityEvent: {
      type: "prompt_injection" | "security_violation" | "processing_error";
      severity: "low" | "medium" | "high" | "critical";
      message: string;
      context: {
        session_id: string;
        flags: string[];
        confidence: number;
        processing_time: number;
        input_length: number;
        blocked: boolean;
        success: boolean;
      };
    };
    let mockTelemetryData: TelemetryData;

    beforeEach(() => {
      mockTelemetryData = {
        session_id: "test-session-123",
        flags: ["injection_pattern"],
        confidence: 0.4,
        processing_time: 150,
        input_length: 50,
        blocked: false,
        success: false,
      };

      mockSecurityEvent = {
        type: "prompt_injection",
        severity: "high",
        message: "Security check failed: injection_pattern",
        context: mockTelemetryData,
      };
    });

    describe("Sentry Provider", () => {
      it("should create provider with correct Sentry integration", () => {
        const mockSentry = {
          addBreadcrumb: vi.fn(),
          captureMessage: vi.fn(),
          captureException: vi.fn(),
        };

        const provider = createSentryProvider(mockSentry);

        provider.logSecurityEvent(mockSecurityEvent);

        expect(mockSentry.addBreadcrumb).toHaveBeenCalledWith({
          category: "security",
          message: mockSecurityEvent.message,
          level: mockSecurityEvent.severity,
          data: mockSecurityEvent.context,
        });
        expect(mockSentry.captureMessage).toHaveBeenCalledWith(
          `Security Event: ${mockSecurityEvent.message}`,
          mockSecurityEvent.severity
        );
      });

      it("should track metrics as breadcrumbs", () => {
        const mockSentry = {
          addBreadcrumb: vi.fn(),
          captureMessage: vi.fn(),
          captureException: vi.fn(),
        };

        const provider = createSentryProvider(mockSentry);

        provider.trackMetric("processing_time", 150, { success: "false" });

        expect(mockSentry.addBreadcrumb).toHaveBeenCalledWith({
          category: "metric",
          message: "processing_time: 150",
          data: { value: 150, success: "false" },
        });
      });

      it("should capture errors with context", () => {
        const mockSentry = {
          addBreadcrumb: vi.fn(),
          captureMessage: vi.fn(),
          captureException: vi.fn(),
        };

        const provider = createSentryProvider(mockSentry);
        const error = new Error("Test error");

        provider.captureError(error, mockTelemetryData);

        expect(mockSentry.captureException).toHaveBeenCalledWith(error, {
          extra: mockTelemetryData,
        });
      });
    });

    describe("Datadog Provider", () => {
      it("should create provider with tracer and logger integration", () => {
        const mockSpan = {
          setTag: vi.fn(),
        };
        const mockTracer = {
          scope: () => ({ active: () => mockSpan }),
          dogstatsd: {
            increment: vi.fn(),
          },
        };
        const mockLogger = {
          info: vi.fn(),
          error: vi.fn(),
          debug: vi.fn(),
        };

        const provider = createDatadogProvider(mockTracer, mockLogger);

        provider.logSecurityEvent(mockSecurityEvent);

        expect(mockLogger.info).toHaveBeenCalledWith("Security Event", {
          type: mockSecurityEvent.type,
          severity: mockSecurityEvent.severity,
          message: mockSecurityEvent.message,
          context: mockSecurityEvent.context,
        });
        expect(mockSpan.setTag).toHaveBeenCalledWith(
          "security.event.type",
          mockSecurityEvent.type
        );
        expect(mockSpan.setTag).toHaveBeenCalledWith(
          "security.event.severity",
          mockSecurityEvent.severity
        );
        expect(mockSpan.setTag).toHaveBeenCalledWith(
          "security.blocked",
          mockSecurityEvent.context.blocked
        );
        expect(mockTracer.dogstatsd.increment).toHaveBeenCalledWith(
          "chainmail.security.event",
          1,
          [
            `type:${mockSecurityEvent.type}`,
            `severity:${mockSecurityEvent.severity}`,
            `blocked:${mockSecurityEvent.context.blocked}`,
          ]
        );
      });

      it("should track metrics via DogStatsD", () => {
        const mockTracer = {
          scope: () => ({ active: () => null }),
          dogstatsd: {
            gauge: vi.fn(),
          },
        };
        const mockLogger = {
          info: vi.fn(),
        };

        const provider = createDatadogProvider(mockTracer, mockLogger);

        provider.trackMetric("processing_time", 150, { success: "false" });

        expect(mockTracer.dogstatsd.gauge).toHaveBeenCalledWith(
          "chainmail.processing_time",
          150,
          ["success:false"]
        );
        expect(mockLogger.info).toHaveBeenCalledWith("Metric", {
          name: "processing_time",
          value: 150,
          tags: { success: "false" },
        });
      });

      it("should handle missing tracer gracefully", () => {
        const mockLogger = {
          info: vi.fn(),
          error: vi.fn(),
          debug: vi.fn(),
        };

        const provider = createDatadogProvider(undefined, mockLogger);

        expect(() => {
          provider.logSecurityEvent(mockSecurityEvent);
          provider.trackMetric("test", 100);
          provider.captureError(new Error("test"), {});
          provider.addBreadcrumb("test", {});
        }).not.toThrow();

        expect(mockLogger.info).toHaveBeenCalled();
      });
    });

    describe("New Relic Provider", () => {
      it("should create provider with New Relic integration", () => {
        const mockNewRelic = {
          recordCustomEvent: vi.fn(),
          noticeError: vi.fn(),
          recordMetric: vi.fn(),
          addCustomAttribute: vi.fn(),
        };

        const provider = createNewRelicProvider(mockNewRelic);

        provider.logSecurityEvent(mockSecurityEvent);

        expect(mockNewRelic.recordCustomEvent).toHaveBeenCalledWith(
          "ChainmailSecurityEvent",
          {
            type: mockSecurityEvent.type,
            severity: mockSecurityEvent.severity,
            message: mockSecurityEvent.message,
            blocked: mockSecurityEvent.context.blocked,
            confidence: mockSecurityEvent.context.confidence,
            flags: mockSecurityEvent.context.flags.join(","),
            session_id: mockSecurityEvent.context.session_id,
          }
        );
        expect(mockNewRelic.noticeError).toHaveBeenCalledWith(
          expect.any(Error),
          {
            customAttributes: {
              chainmailEvent: true,
              eventType: mockSecurityEvent.type,
              severity: mockSecurityEvent.severity,
            },
          }
        );
      });

      it("should record metrics correctly", () => {
        const mockNewRelic = {
          recordCustomEvent: vi.fn(),
          noticeError: vi.fn(),
          recordMetric: vi.fn(),
          addCustomAttribute: vi.fn(),
        };

        const provider = createNewRelicProvider(mockNewRelic);

        provider.trackMetric("processing_time", 150, { success: "false" });

        expect(mockNewRelic.recordMetric).toHaveBeenCalledWith(
          "Custom/Chainmail/processing_time",
          150
        );
        expect(mockNewRelic.addCustomAttribute).toHaveBeenCalledWith(
          "chainmail.success",
          "false"
        );
      });

      it("should handle breadcrumbs as custom attributes", () => {
        const mockNewRelic = {
          recordCustomEvent: vi.fn(),
          noticeError: vi.fn(),
          recordMetric: vi.fn(),
          addCustomAttribute: vi.fn(),
        };

        const provider = createNewRelicProvider(mockNewRelic);

        provider.addBreadcrumb("Processing started", {
          session_id: "test-123",
        });

        expect(mockNewRelic.addCustomAttribute).toHaveBeenCalledWith(
          "chainmail.lastAction",
          "Processing started"
        );
        expect(mockNewRelic.addCustomAttribute).toHaveBeenCalledWith(
          "chainmail.lastActionData",
          '{"session_id":"test-123"}'
        );
      });
    });

    describe("Console Provider", () => {
      beforeEach(() => {
        vi.spyOn(console, "warn").mockImplementation(() => {});
        vi.spyOn(console, "info").mockImplementation(() => {});
        vi.spyOn(console, "error").mockImplementation(() => {});
        vi.spyOn(console, "debug").mockImplementation(() => {});
      });

      afterEach(() => {
        vi.restoreAllMocks();
      });

      it("should create console provider with correct logging", () => {
        const provider = createConsoleProvider();

        provider.logSecurityEvent(mockSecurityEvent);

        expect(console.warn).toHaveBeenCalledWith(
          "[Security] prompt_injection:",
          mockSecurityEvent.message,
          mockSecurityEvent.context
        );
      });

      it("should track metrics via console.info", () => {
        const provider = createConsoleProvider();

        provider.trackMetric("processing_time", 150, { success: "false" });

        expect(console.info).toHaveBeenCalledWith(
          "[Metric] processing_time:",
          150,
          { success: "false" }
        );
      });

      it("should capture errors via console.error", () => {
        const provider = createConsoleProvider();
        const error = new Error("Test error");

        provider.captureError(error, mockTelemetryData);

        expect(console.error).toHaveBeenCalledWith(
          "[Error]",
          "Test error",
          mockTelemetryData
        );
      });

      it("should add breadcrumbs via console.debug", () => {
        const provider = createConsoleProvider();

        provider.addBreadcrumb("Processing started", {
          session_id: "test-123",
        });

        expect(console.debug).toHaveBeenCalledWith(
          "[Breadcrumb]",
          "Processing started",
          { session_id: "test-123" }
        );
      });
    });
  });
});
