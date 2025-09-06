import { describe, it, expect, vi, beforeEach } from "vitest";
import { PromptChainmail } from "../../index";
import { telemetry, createConsoleProvider, type TelemetryProvider } from "./telemetry";
import { ChainmailContext, ChainmailResult } from "../../types";

describe("telemetry(...)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should log telemetry data with default console provider", async () => {
    const consoleSpy = vi.spyOn(console, "info").mockImplementation(() => {});

    const chainmail = new PromptChainmail().forge(telemetry());

    await chainmail.protect("test input");

    expect(consoleSpy).toHaveBeenCalledWith(
      "[Chainmail]",
      expect.stringContaining("Processing completed"),
      expect.objectContaining({
        session_id: expect.any(String),
        flags: expect.any(Array),
        confidence: expect.any(Number),
        processing_time: expect.any(Number),
        input_length: 10,
        blocked: false,
        success: true,
      })
    );

    consoleSpy.mockRestore();
  });

  it("should use custom log function", async () => {
    const customLogFn = vi.fn();

    const chainmail = new PromptChainmail().forge(
      telemetry({ logFn: customLogFn })
    );

    await chainmail.protect("test input");

    expect(customLogFn).toHaveBeenCalledWith(
      "info",
      expect.stringContaining("Processing completed"),
      expect.objectContaining({
        session_id: expect.any(String),
        processing_time: expect.any(Number),
      })
    );
  });

  it("should use custom telemetry provider", async () => {
    const mockProvider: TelemetryProvider = {
      logSecurityEvent: vi.fn(),
      trackMetric: vi.fn(),
      captureError: vi.fn(),
      addBreadcrumb: vi.fn(),
    };

    const chainmail = new PromptChainmail().forge(
      telemetry({ provider: mockProvider })
    );

    await chainmail.protect("test input");

    expect(mockProvider.addBreadcrumb).toHaveBeenCalledWith(
      "Processing started",
      expect.objectContaining({
        sessionId: expect.any(String),
        inputLength: 10,
      })
    );

    expect(mockProvider.trackMetric).toHaveBeenCalledWith(
      "processing_time",
      expect.any(Number),
      expect.objectContaining({
        success: "true",
        flags_count: "0",
      })
    );
  });

  it("should log security events when flags are detected", async () => {
    const mockProvider: TelemetryProvider = {
      logSecurityEvent: vi.fn(),
      trackMetric: vi.fn(),
      captureError: vi.fn(),
      addBreadcrumb: vi.fn(),
    };

    const chainmail = new PromptChainmail()
      .forge((context, next) => {
        context.flags.push("test_flag");
        context.confidence = 0.3;
        return next();
      })
      .forge(telemetry({ provider: mockProvider }));

    await chainmail.protect("test input");

    expect(mockProvider.logSecurityEvent).toHaveBeenCalledWith({
      type: "prompt_injection",
      severity: "high",
      message: "Security check passed: test_flag",
      context: expect.objectContaining({
        flags: ["test_flag"],
        confidence: 0.3,
        blocked: false,
        success: true,
        input_length: 10,
        processing_time: expect.any(Number),
        session_id: expect.any(String),
      }),
    });
  });

  it("should handle errors and log them", async () => {
    const mockProvider: TelemetryProvider = {
      logSecurityEvent: vi.fn(),
      trackMetric: vi.fn(),
      captureError: vi.fn(),
      addBreadcrumb: vi.fn(),
    };

    const errorRivet = async (
      _context: ChainmailContext,
      _next: () => Promise<ChainmailResult>
    ) => {
      throw new Error("Test error");
    };

    const chainmail = new PromptChainmail()
      .forge(telemetry({ provider: mockProvider }))
      .forge(errorRivet);

    const result = await chainmail.protect("test input");

    expect(result.success).toBe(false);
    expect(mockProvider.captureError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({
        session_id: expect.any(String),
        success: false,
      })
    );

    expect(mockProvider.logSecurityEvent).toHaveBeenCalledWith({
      type: "processing_error",
      severity: "high",
      message: "Processing failed: Test error",
      context: expect.objectContaining({
        success: false,
      }),
    });
  });

  it("should create console provider correctly", () => {
    const provider = createConsoleProvider();

    expect(provider).toHaveProperty("logSecurityEvent");
    expect(provider).toHaveProperty("trackMetric");
    expect(provider).toHaveProperty("captureError");
    expect(provider).toHaveProperty("addBreadcrumb");
  });

  it("should disable metrics when track_metrics is false", async () => {
    const customLogFn = vi.fn();

    const chainmail = new PromptChainmail().forge(
      telemetry({ logFn: customLogFn, track_metrics: false })
    );

    await chainmail.protect("test input");

    expect(customLogFn).not.toHaveBeenCalled();
  });
});
