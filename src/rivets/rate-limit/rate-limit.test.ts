import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { rateLimit } from "./rate-limit";
import { SecurityFlags } from "../rivets.types";
import { measurePerformance, expectPerformance } from "../../@shared/performance.utils";

describe("rateLimit(...)", () => {
  it("should enforce rate limiting", async () => {
    const chainmail = new PromptChainmail().forge(rateLimit(2, 60000));

    const result1 = await chainmail.protect("test 1");
    const result2 = await chainmail.protect("test 2");

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);

    const result3 = await chainmail.protect("test 3");

    expect(result3.success).toBe(false);
    expect(result3.context.flags).toContain(SecurityFlags.RATE_LIMITED);
    expect(result3.context.blocked).toBe(true);
  });

  describe("Performance", () => {
    it("should process rate limiting within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(rateLimit(100, 60000));
      
      const result = await measurePerformance(
        () => chainmail.protect("test input"),
        100
      );
      
      expectPerformance(result, 3);
      expect(result.opsPerSecond).toBeGreaterThan(300);
    });

    it("should handle rate limit enforcement within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(rateLimit(1, 60000));
      await chainmail.protect("first request");
      
      const result = await measurePerformance(
        () => chainmail.protect("rate limited request"),
        50
      );
      
      expectPerformance(result, 5);
      expect(result.opsPerSecond).toBeGreaterThan(200);
    });

    it("should process large text with rate limiting within performance threshold", async () => {
      const chainmail = new PromptChainmail().forge(rateLimit(100, 60000));
      const largeText = "This is a test message for rate limiting performance. ".repeat(100);
      
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        25
      );
      
      expectPerformance(result, 8);
      expect(result.opsPerSecond).toBeGreaterThan(125);
    });
  });
});
