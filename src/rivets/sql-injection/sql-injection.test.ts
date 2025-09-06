import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { sqlInjection } from "./sql-injection";
import { SecurityFlag } from "../rivets.types";

describe("sqlInjection()", () => {
  it("should detect SQL injection", async () => {
    const chainmail = new PromptChainmail().forge(sqlInjection());

    const result = await chainmail.protect("'; DROP TABLE users; --");

    expect(result.context.flags).toContain(SecurityFlag.SQL_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect union-based SQL injection", async () => {
    const chainmail = new PromptChainmail().forge(sqlInjection());

    const result = await chainmail.protect(
      "1' UNION SELECT password FROM users--"
    );

    expect(result.context.flags).toContain(SecurityFlag.SQL_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect boolean-based blind SQL injection", async () => {
    const chainmail = new PromptChainmail().forge(sqlInjection());

    const result = await chainmail.protect("1' AND 1=1--");

    expect(result.context.flags).toContain(SecurityFlag.SQL_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect time-based blind SQL injection", async () => {
    const chainmail = new PromptChainmail().forge(sqlInjection());

    const result = await chainmail.protect("1'; WAITFOR DELAY '00:00:05'--");

    expect(result.context.flags).toContain(SecurityFlag.SQL_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect stacked queries SQL injection", async () => {
    const chainmail = new PromptChainmail().forge(sqlInjection());

    const result = await chainmail.protect(
      "1'; INSERT INTO users VALUES('hacker','pass')--"
    );

    expect(result.context.flags).toContain(SecurityFlag.SQL_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });
});
