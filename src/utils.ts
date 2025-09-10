/**
 * Generic async chunk generator for handling multiple input types
 */
export async function* toChunks(
  source: string | ReadableStream | ArrayBuffer | Uint8Array,
  chunkSize = 1024
): AsyncGenerator<string> {
  if (typeof source === "string") {
    for (let i = 0; i < source.length; i += chunkSize) {
      yield source.slice(i, i + chunkSize);
    }
    return;
  }

  if (Symbol.asyncIterator in source) {
    const decoder = new TextDecoder();
    for await (const chunk of source as AsyncIterable<Uint8Array | string>) {
      yield typeof chunk === "string" ? chunk : decoder.decode(chunk);
    }
    return;
  }

  if (source instanceof ArrayBuffer || source instanceof Uint8Array) {
    yield new TextDecoder().decode(source);
    return;
  }

  throw new Error("Unsupported input type");
}
