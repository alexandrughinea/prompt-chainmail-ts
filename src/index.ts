import { Rivets } from "./rivets/index";
import { Chainmails } from "./chainmails/index";
import { toChunks } from "./utils";
import { ChainmailContext, ChainmailResult, ChainmailRivet } from "./types";

export { Rivets, Chainmails };
export type { ChainmailRivet };

const MAX_INPUT_SIZE_IN_MB = 1024 * 1024 * 2; // 2MB
const STRING_CHUNKING_THRESHOLD = 64 * 1024; // 64KB
const MAX_CHUNK_SIZE = 4096; // 4KB

/**
 * Core chainmail class for forging security rivets
 *
 * @example
 * ```typescript
 * const chainmail = new PromptChainmail()
 *   .forge(Rivets.sanitize())
 *   .forge(Rivets.patternDetection())
 *   .forge(Rivets.confidenceFilter(0.7));
 *
 * const result = await chainmail.protect(userInput);
 * ```
 */
export class PromptChainmail {
  private rivets: ChainmailRivet[] = [];

  /**
   * Forge a new rivet into the chainmail
   */
  forge(rivet: ChainmailRivet): this {
    this.rivets.push(rivet);
    return this;
  }

  /**
   * Protect input by running it through all forged rivets
   */
  async protect(
    input: string | ReadableStream | ArrayBuffer | Uint8Array
  ): Promise<ChainmailResult> {
    const startTime = Date.now();
    const sessionId = crypto.randomUUID();

    if (input == null) {
      const processingTime = Date.now() - startTime;
      return {
        success: false,
        context: {
          input: "",
          sanitized: "",
          flags: ["invalid_input"],
          blocked: true,
          start_time: startTime,
          session_id: sessionId,
          confidence: 1,
          metadata: {},
        },
        error: `Invalid input: ${input}`,
        processing_time: processingTime,
      };
    }

    if (typeof input === "string") {
      if (input.length > STRING_CHUNKING_THRESHOLD) {
        const stream = this.stringToStream(input);
        return this.protectStream(stream, startTime, sessionId);
      }

      return this.protectString(input, startTime, sessionId);
    }
    return this.protectStream(input, startTime, sessionId);
  }

  /**
   * Convert a large string to ReadableStream for chunked processing
   */
  private stringToStream(input: string): ReadableStream<Uint8Array> {
    return new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder();
        let offset = 0;

        while (offset < input.length) {
          const chunk = input.slice(offset, offset + MAX_CHUNK_SIZE);
          controller.enqueue(encoder.encode(chunk));
          offset += MAX_CHUNK_SIZE;
        }
        controller.close();
      },
    });
  }

  /**
   * Protect string input (original implementation)
   */
  private async protectString(
    input: string,
    startTime: number,
    sessionId: string
  ): Promise<ChainmailResult> {
    const context: ChainmailContext = {
      input,
      sanitized: input,
      flags: [],
      confidence: 1.0,
      metadata: {},
      blocked: false,
      start_time: startTime,
      session_id: sessionId,
    };

    if (this.rivets.length === 0) {
      return {
        success: true,
        context,
        processing_time: Date.now() - startTime,
      };
    }

    let index = 0;
    const next = async (): Promise<ChainmailResult> => {
      if (index >= this.rivets.length) {
        return {
          success: !context.blocked,
          context,
          processing_time: Date.now() - startTime,
        };
      }

      const rivet = this.rivets[index++];
      return rivet(context, next);
    };

    try {
      return await next();
    } catch (error) {
      return {
        success: false,
        context,
        error: error instanceof Error ? error.message : "Unknown error",
        processing_time: Date.now() - startTime,
      };
    }
  }

  /**
   * Protect streaming input by processing chunks
   */
  private async protectStream(
    input: ReadableStream | ArrayBuffer | Uint8Array,
    startTime: number,
    sessionId: string
  ): Promise<ChainmailResult> {
    let chunkCount = 0;
    let totalLength = 0;
    const streamFlagsSet = new Set<string>();
    const streamMetadata: Record<string, unknown> = {};
    let minConfidence = 1.0;

    try {
      for await (const chunk of toChunks(input, MAX_CHUNK_SIZE)) {
        chunkCount++;
        totalLength += chunk.length;

        if (totalLength > MAX_INPUT_SIZE_IN_MB) {
          streamFlagsSet.add("stream_size_exceeded");
          streamMetadata.streamSizeLimit = MAX_INPUT_SIZE_IN_MB;
          return this.createStreamResult(
            true,
            chunkCount,
            totalLength,
            Array.from(streamFlagsSet),
            streamMetadata,
            0,
            startTime,
            sessionId
          );
        }

        const chunkContext: ChainmailContext = {
          input: chunk,
          sanitized: chunk,
          flags: [],
          confidence: 1.0,
          metadata: {},
          blocked: false,
          start_time: startTime,
          session_id: sessionId,
        };

        const chunkResult = await this.processChunkThroughRivets(
          chunkContext,
          startTime
        );

        chunkResult.context.flags.forEach((flag) => streamFlagsSet.add(flag));
        Object.assign(streamMetadata, chunkResult.context.metadata);
        minConfidence = Math.min(minConfidence, chunkResult.context.confidence);

        if (chunkResult.context.blocked) {
          return this.createStreamResult(
            true,
            chunkCount,
            totalLength,
            Array.from(streamFlagsSet),
            streamMetadata,
            minConfidence,
            startTime,
            sessionId
          );
        }
      }

      return this.createStreamResult(
        false,
        chunkCount,
        totalLength,
        Array.from(streamFlagsSet),
        streamMetadata,
        minConfidence,
        startTime,
        sessionId
      );
    } catch (error) {
      streamFlagsSet.add("stream_processing_error");
      streamMetadata.streamError =
        error instanceof Error ? error.message : "Unknown stream error";
      return this.createStreamResult(
        true,
        chunkCount,
        totalLength,
        Array.from(streamFlagsSet),
        streamMetadata,
        0,
        startTime,
        sessionId
      );
    }
  }

  private async processChunkThroughRivets(
    chunkContext: ChainmailContext,
    startTime: number
  ): Promise<ChainmailResult> {
    if (this.rivets.length === 0) {
      return {
        success: true,
        context: chunkContext,
        processing_time: Date.now() - startTime,
      };
    }

    let index = 0;
    const next = async (): Promise<ChainmailResult> => {
      if (index >= this.rivets.length) {
        return {
          success: !chunkContext.blocked,
          context: chunkContext,
          processing_time: Date.now() - startTime,
        };
      }
      const rivet = this.rivets[index++];
      return rivet(chunkContext, next);
    };
    return next();
  }

  private createStreamResult(
    blocked: boolean,
    chunkCount: number,
    totalLength: number,
    streamFlags: string[],
    streamMetadata: Record<string, unknown>,
    confidence: number,
    startTime: number,
    sessionId: string
  ): ChainmailResult {
    streamMetadata.chunk_count = chunkCount;
    streamMetadata.total_length = totalLength;

    const streamDesc = `[Stream: ${chunkCount} chunks, ${totalLength} chars]`;
    const finalContext: ChainmailContext = {
      input: streamDesc,
      sanitized: streamDesc,
      flags: streamFlags.length > 0 ? [...new Set(streamFlags)] : [],
      confidence,
      metadata: streamMetadata,
      blocked,
      start_time: startTime,
      session_id: sessionId,
    };

    return {
      success: !blocked,
      context: finalContext,
      processing_time: Date.now() - startTime,
    };
  }

  /**
   * Create a new chainmail with the same rivets
   */
  clone(): PromptChainmail {
    const chainmail = new PromptChainmail();
    chainmail.rivets = [...this.rivets];
    return chainmail;
  }

  /**
   * Get the number of rivets in the chainmail
   */
  get length(): number {
    return this.rivets.length;
  }
}
