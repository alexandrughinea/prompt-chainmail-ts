import { describe, it, expect, vi, beforeEach } from "vitest";
import { PromptChainmail } from "../../index";
import { telemetry } from "./telemetry";
import { TelemetryProvider } from "./telemetry.types";
import { ThreatLevel } from "../rivets.types";
import { measurePerformance, expectPerformance } from "../../@shared/performance.utils";
import { createConsoleProvider } from "./telemetry.utils";
import type { ChainmailRivet } from "../../index";

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
      type: "threat_detected",
      threat_level: ThreatLevel.LOW,
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
      flags: ["test_flag"],
      risk_score: undefined,
      attack_types: undefined,
    });
  });

  it("should handle errors and log them", async () => {
    const mockProvider: TelemetryProvider = {
      logSecurityEvent: vi.fn(),
      trackMetric: vi.fn(),
      captureError: vi.fn(),
      addBreadcrumb: vi.fn(),
    };

    const errorRivet: ChainmailRivet = async (_context, _next) => {
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
      threat_level: ThreatLevel.LOW,
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

  describe("Performance", () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });
    
    it("should process telemetry logging within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(telemetry());
      
      const result = await measurePerformance(
        () => chainmail.protect("test input"),
        50
      );
      
      expectPerformance(result, 8);
      expect(result.opsPerSecond).toBeGreaterThan(125);
    });

    it("should handle custom provider within performance threshold", async () => {
      const mockProvider: TelemetryProvider = {
        logSecurityEvent: vi.fn(),
        trackMetric: vi.fn(),
        captureError: vi.fn(),
        addBreadcrumb: vi.fn(),
      };
      
      const chainmail = new PromptChainmail().forge(
        telemetry({ provider: mockProvider })
      );
      
      const result = await measurePerformance(
        () => chainmail.protect("test input"),
        50
      );
      
      expectPerformance(result, 10);
      expect(result.opsPerSecond).toBeGreaterThan(100);
    });

    it("should process large text with telemetry within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(telemetry());
      const largeText = "This is a test message for telemetry performance. ".repeat(100);
      
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        25
      );
      
      expectPerformance(result, 15);
      expect(result.opsPerSecond).toBeGreaterThan(65);
    });
  });
});
