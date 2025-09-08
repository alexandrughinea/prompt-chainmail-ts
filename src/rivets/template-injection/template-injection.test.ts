import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { templateInjection } from "./template-injection";
import { SecurityFlags } from "../rivets.types";
import { measurePerformance, expectPerformance } from "../../@shared/performance.utils";

describe("templateInjection()", () => {
  it("should detect template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("{{config.secret_key}}");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Jinja2 template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect(
      "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    );

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect ERB template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("<%= system('whoami') %>");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Twig template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect(
      "{{_self.env.registerUndefinedFilterCallback('exec')}}"
    );

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Smarty template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("{php}echo `id`;{/php}");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  describe("Performance", () => {
    const chainmail = new PromptChainmail().forge(templateInjection());
    
    it("should process simple text within performance threshold", async () => {
      const result = await measurePerformance(
        () => chainmail.protect("This is a simple test message"),
        50
      );
      
      expectPerformance(result, 5);
      expect(result.opsPerSecond).toBeGreaterThan(200);
    });

    it("should process template injection attempts within performance threshold", async () => {
      const result = await measurePerformance(
        () => chainmail.protect("{{config.secret_key}} ${process.env.SECRET}"),
        50
      );
      
      expectPerformance(result, 8);
      expect(result.opsPerSecond).toBeGreaterThan(125);
    });

    it("should process complex templates within performance threshold", async () => {
      const complexTemplate = "{% for item in items %}{{item.secret}}{% endfor %} <%= config.database_url %>";
      const result = await measurePerformance(
        () => chainmail.protect(complexTemplate),
        25
      );
      
      expectPerformance(result, 10);
      expect(result.opsPerSecond).toBeGreaterThan(100);
    });
  });
});
