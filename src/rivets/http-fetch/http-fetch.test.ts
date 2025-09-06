import { describe, it, expect, vi, afterEach } from "vitest";
import { PromptChainmail } from "../../index";
import { httpFetch } from "./http-fetch";
import { SecurityFlag } from "../rivets.types";

describe("httpFetch(...)", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("should make successful HTTP request", async () => {
    const mockResponse = { safe: true, score: 0.9 };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: {
        get: (name: string) => (name === "content-length" ? "100" : null),
      },
      json: () => Promise.resolve(mockResponse),
    });

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate")
    );

    const result = await chainmail.protect("test input");

    expect(result.context.flags).toContain(SecurityFlag.HTTP_VALIDATED);
    expect(result.context.metadata.httpResponse).toEqual(mockResponse);
    expect(global.fetch).toHaveBeenCalledWith(
      "https://api.example.com/validate",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: "test input" }),
        signal: expect.any(AbortSignal),
      })
    );
  });

  it("should handle HTTP errors", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    });

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate")
    );

    const result = await chainmail.protect("test input");

    expect(result.context.flags).toContain(SecurityFlag.HTTP_ERROR);
    expect(result.context.metadata.httpError).toContain("HTTP 500");
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should handle network errors", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate")
    );

    const result = await chainmail.protect("test input");

    expect(result.context.flags).toContain(SecurityFlag.HTTP_ERROR);
    expect(result.context.metadata.httpError).toBe("Network error");
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should handle timeout with AbortSignal", async () => {
    global.fetch = vi.fn().mockImplementation(() => {
      return new Promise((_, reject) => {
        setTimeout(() => {
          const error = new Error("Request timed out");
          error.name = "AbortError";
          reject(error);
        }, 100);
      });
    });

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate", { timeoutMs: 50 })
    );

    const result = await chainmail.protect("test input");

    expect(result.context.flags).toContain(SecurityFlag.HTTP_TIMEOUT);
    expect(result.context.metadata.httpError).toContain(
      "timed out after 50ms"
    );
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should use custom validation function", async () => {
    const mockResponse = { safe: false, score: 0.2 };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: {
        get: (name: string) => (name === "content-length" ? "100" : null),
      },
      json: () => Promise.resolve(mockResponse),
    });

    const validateResponse = (_response: Response, data: unknown) =>
      (data as { safe: boolean }).safe;

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate", {
        validateResponse,
      })
    );

    const result = await chainmail.protect("test input");

    expect(result.context.flags).toContain(
      SecurityFlag.HTTP_VALIDATION_FAILED
    );
    expect(result.context.metadata.httpValidationError).toBe(
      "Response validation failed"
    );
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should call success callback", async () => {
    const mockResponse = { safe: true, score: 0.9 };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: {
        get: (name: string) => (name === "content-length" ? "100" : null),
      },
      json: () => Promise.resolve(mockResponse),
    });

    const onSuccess = vi.fn();

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate", { onSuccess })
    );

    await chainmail.protect("test input");

    expect(onSuccess).toHaveBeenCalledWith(expect.any(Object), mockResponse);
  });

  it("should call error callback", async () => {
    const error = new Error("Network error");
    global.fetch = vi.fn().mockRejectedValue(error);

    const onError = vi.fn();

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate", { onError })
    );

    await chainmail.protect("test input");

    expect(onError).toHaveBeenCalledWith(expect.any(Object), error);
  });

  it("should use custom method and headers", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ safe: true }),
    });

    const chainmail = new PromptChainmail().forge(
      httpFetch("https://api.example.com/validate", {
        method: "PUT",
        headers: { Authorization: "Bearer token123" },
      })
    );

    await chainmail.protect("test input");

    expect(global.fetch).toHaveBeenCalledWith(
      "https://api.example.com/validate",
      expect.objectContaining({
        method: "PUT",
        headers: { Authorization: "Bearer token123" },
      })
    );
  });
});
