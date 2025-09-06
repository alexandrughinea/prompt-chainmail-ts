import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { sanitize } from "./sanitize";
import { SecurityFlag } from "../rivets.types";

describe("sanitize(...)", () => {
  it("should sanitize HTML input", async () => {
    const chainmail = new PromptChainmail().forge(sanitize());

    const result = await chainmail.protect(
      "<script>alert('xss')</script>Hello"
    );

    expect(result.context.sanitized).toBe("alert('xss')Hello");
    expect(result.context.flags).toContain(SecurityFlag.TRUNCATED);
  });

  it("should respect max length", async () => {
    const chainmail = new PromptChainmail().forge(sanitize(10));

    const result = await chainmail.protect(
      "This is a very long input that should be truncated"
    );

    expect(result.context.sanitized).toBe("This is a ");
    expect(result.context.flags).toContain(SecurityFlag.TRUNCATED);
    expect(result.context.confidence).toBeLessThan(1.0);
  });
});
