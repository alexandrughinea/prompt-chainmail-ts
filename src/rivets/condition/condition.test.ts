import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { condition } from "./condition";
import { ChainmailContext } from "../../types";
import {
  measurePerformance,
  expectPerformance,
} from "../../@shared/performance.utils";

describe("condition(...)", () => {
  it("should execute custom conditions", async () => {
    const chainmail = new PromptChainmail().forge(
      condition(
        (ctx: ChainmailContext) => ctx.sanitized.includes("secret"),
        "contains_secret",
        0.5
      )
    );

    const result = await chainmail.protect("This contains a secret word");

    expect(result.context.flags).toContain("contains_secret");
    expect(result.context.confidence).toBe(0.64);
  });

  describe("Performance", () => {
    const chainmail = new PromptChainmail().forge(
      condition((ctx: ChainmailContext) => ctx.sanitized.length > 10)
    );

    it("should process simple conditions within performance threshold", async () => {
      const result = await measurePerformance(
        () => chainmail.protect("This is a test message"),
        100
      );

      expectPerformance(result, 2);
      expect(result.opsPerSecond).toBeGreaterThan(500);
    });

    it("should process complex conditions within performance threshold", async () => {
      const complexChainmail = new PromptChainmail().forge(
        condition(
          (ctx: ChainmailContext) =>
            ctx.sanitized.includes("test") &&
            ctx.sanitized.length > 5 &&
            ctx.confidence > 0.5
        )
      );

      const result = await measurePerformance(
        () =>
          complexChainmail.protect(
            "This is a test message with complex conditions"
          ),
        100
      );

      expectPerformance(result, 3);
      expect(result.opsPerSecond).toBeGreaterThan(300);
    });

    it("should process large text within performance threshold", async () => {
      const largeText =
        "This is a test message for condition checking. ".repeat(100);
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        50
      );

      expectPerformance(result, 5);
      expect(result.opsPerSecond).toBeGreaterThan(200);
    });
  });
});
