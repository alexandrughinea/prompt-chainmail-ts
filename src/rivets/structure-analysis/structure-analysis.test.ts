import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { structureAnalysis } from "./structure-analysis";
import { SecurityFlag } from "../rivets.types";

describe("structureAnalysis()", () => {
  it("should detect structure anomalies", async () => {
    const chainmail = new PromptChainmail().forge(structureAnalysis());

    const manyLines = Array(60).fill("line").join("\n");
    const result = await chainmail.protect(manyLines);

    expect(result.context.flags).toContain(SecurityFlag.EXCESSIVE_LINES);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect repetitive content", async () => {
    const chainmail = new PromptChainmail().forge(structureAnalysis());

    const repetitive =
      "repeat repeat repeat repeat repeat repeat repeat repeat repeat repeat repeat";
    const result = await chainmail.protect(repetitive);

    expect(result.context.flags).toContain(SecurityFlag.REPETITIVE_CONTENT);
    expect(result.context.confidence).toBeLessThan(1.0);
  });
});
