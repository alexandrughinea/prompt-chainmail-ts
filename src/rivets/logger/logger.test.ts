import { describe, it, expect, vi } from "vitest";
import { PromptChainmail } from "../../index";
import { logger } from "./logger";
import { ChainmailContext } from "../../types";
import { measurePerformance, expectPerformance } from "../../@shared/performance.utils";

describe("logger(...)", () => {
  it("should log processing information with custom function", async () => {
    const logs: ChainmailContext[] = [];
    const mockLogger = (context: ChainmailContext) => logs.push(context);

    const chainmail = new PromptChainmail().forge(logger('log', mockLogger));

    await chainmail.protect("test input");

    expect(logs).toHaveLength(1);
    expect(logs[0].input).toBe("test input");
  });

  it("should use specified log level", async () => {
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const chainmail = new PromptChainmail().forge(logger('warn'));

    await chainmail.protect("test input");

    expect(consoleSpy).toHaveBeenCalledWith(
      "[PromptChainmail]",
      expect.objectContaining({ inputLength: 10 })
    );

    consoleSpy.mockRestore();
  });

  it("should default to log level", async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const chainmail = new PromptChainmail().forge(logger());

    await chainmail.protect("test");

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  describe("Performance", () => {
    it("should process logging within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(logger());
      
      const result = await measurePerformance(
        () => chainmail.protect("test input"),
        100
      );
      
      expectPerformance(result, 3);
      expect(result.opsPerSecond).toBeGreaterThan(300);
    });

    it("should handle custom logger within performance threshold", async () => {
      const logs: ChainmailContext[] = [];
      const mockLogger = (context: ChainmailContext) => logs.push(context);
      const chainmail = new PromptChainmail().forge(logger('log', mockLogger));
      
      const result = await measurePerformance(
        () => chainmail.protect("test input"),
        50
      );
      
      expectPerformance(result, 5);
      expect(result.opsPerSecond).toBeGreaterThan(200);
    });

    it("should process large text logging within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(logger());
      const largeText = "This is a test message for logging performance. ".repeat(100);
      
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        25
      );
      
      expectPerformance(result, 8);
      expect(result.opsPerSecond).toBeGreaterThan(125);
    });
  });
});