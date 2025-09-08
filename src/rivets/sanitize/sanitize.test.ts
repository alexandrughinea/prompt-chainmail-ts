import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { sanitize } from "./sanitize";
import { SecurityFlags } from "../rivets.types";
import { measurePerformance, expectPerformance } from "../../@shared/performance.utils";

describe("sanitize(...)", () => {
  it("should sanitize HTML input", async () => {
    const chainmail = new PromptChainmail().forge(sanitize());

    const result = await chainmail.protect(
      "<script>alert('xss')</script>Hello"
    );

    expect(result.context.sanitized).toBe("alert('xss')Hello");
    expect(result.context.flags).toContain(SecurityFlags.TRUNCATED);
  });

  it("should respect max length", async () => {
    const chainmail = new PromptChainmail().forge(sanitize(10));

    const result = await chainmail.protect(
      "This is a very long input that should be truncated"
    );

    expect(result.context.sanitized).toBe("This is a ");
    expect(result.context.flags).toContain(SecurityFlags.TRUNCATED);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  describe("Performance", () => {
    const chainmail = new PromptChainmail().forge(sanitize());
    
    it("should process simple text within performance threshold", async () => {
      const result = await measurePerformance(
        () => chainmail.protect("This is a simple test message"),
        100
      );
      
      expectPerformance(result, 3);
      expect(result.opsPerSecond).toBeGreaterThan(300);
    });

    it("should sanitize HTML content within performance threshold", async () => {
      const htmlInput = "<script>alert('xss')</script><div>Content</div><p>More content</p>";
      const result = await measurePerformance(
        () => chainmail.protect(htmlInput),
        50
      );
      
      expectPerformance(result, 8);
      expect(result.opsPerSecond).toBeGreaterThan(125);
    });

    it("should process large text within performance threshold", async () => {
      const largeText = "This is a test message with <script>alert('test')</script> HTML content. ".repeat(100);
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        25
      );
      
      expectPerformance(result, 12);
      expect(result.opsPerSecond).toBeGreaterThan(80);
    });
  });
});
