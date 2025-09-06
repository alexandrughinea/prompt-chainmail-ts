import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { logger } from "./logger";
import { ChainmailContext } from "../../types";

describe("logger(...)", () => {
  it("should log processing information", async () => {
    const logs: ChainmailContext[] = [];
    const mockLogger = (context: ChainmailContext) => logs.push(context);

    const chainmail = new PromptChainmail().forge(logger(mockLogger));

    await chainmail.protect("test input");

    expect(logs).toHaveLength(1);
    expect(logs[0].input).toBe("test input");
  });
});
