import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { structureAnalysis } from "./structure-analysis";
import { SecurityFlags } from "../rivets.types";
import {
  measurePerformance,
  expectPerformance,
} from "../../@shared/performance.utils";

describe("structureAnalysis()", () => {
  it("should detect structure anomalies", async () => {
    const chainmail = new PromptChainmail().forge(structureAnalysis());

    const manyLines = Array(60).fill("line").join("\n");
    const result = await chainmail.protect(manyLines);

    expect(result.context.flags.has(SecurityFlags.EXCESSIVE_LINES)).toBe(true);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect repetitive content", async () => {
    const chainmail = new PromptChainmail().forge(structureAnalysis());

    const repetitive =
      "repeat repeat repeat repeat repeat repeat repeat repeat repeat repeat repeat";
    const result = await chainmail.protect(repetitive);

    expect(result.context.flags.has(SecurityFlags.REPETITIVE_CONTENT)).toBe(
      true
    );
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  describe("Performance", () => {
    const chainmail = new PromptChainmail().forge(structureAnalysis());

    it("should process simple text within performance threshold", async () => {
      const result = await measurePerformance(
        () => chainmail.protect("This is a simple test message"),
        100
      );

      expectPerformance(result, 5);
      expect(result.opsPerSecond).toBeGreaterThan(200);
    });

    it("should analyze structured content within performance threshold", async () => {
      const structuredInput =
        "line 1\nline 2\nline 3\nrepeat repeat repeat\n{json: 'data'}";
      const result = await measurePerformance(
        () => chainmail.protect(structuredInput),
        50
      );

      expectPerformance(result, 10);
      expect(result.opsPerSecond).toBeGreaterThan(100);
    });

    it("should process large structured text within performance threshold", async () => {
      const largeText = "This is line number X with some content.\n"
        .replace("X", "")
        .repeat(200);
      const result = await measurePerformance(
        () => chainmail.protect(largeText),
        25
      );

      expectPerformance(result, 20);
      expect(result.opsPerSecond).toBeGreaterThan(50);
    });
  });
});
