/**
 * Lightweight performance testing utilities for rivets
 */

export interface PerformanceResult {
  averageTime: number;
  minTime: number;
  maxTime: number;
  iterations: number;
  opsPerSecond: number;
}

/**
 * Measures performance of a function over multiple iterations
 */
export async function measurePerformance<T>(
  fn: () => Promise<T> | T,
  iterations: number = 100
): Promise<PerformanceResult> {
  const times: number[] = [];

  // Warm up
  await fn();

  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    const end = performance.now();
    times.push(end - start);
  }

  const averageTime = times.reduce((sum, time) => sum + time, 0) / times.length;
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const opsPerSecond = 1000 / averageTime;

  return {
    averageTime,
    minTime,
    maxTime,
    iterations,
    opsPerSecond,
  };
}

/**
 * Performance assertion helper
 */
export function expectPerformance(
  result: PerformanceResult,
  maxAverageMs: number,
  minOpsPerSecond?: number
) {
  if (result.averageTime > maxAverageMs) {
    throw new Error(
      `Performance regression: Average time ${result.averageTime.toFixed(2)}ms exceeds threshold ${maxAverageMs}ms`
    );
  }

  if (minOpsPerSecond && result.opsPerSecond < minOpsPerSecond) {
    throw new Error(
      `Performance regression: ${result.opsPerSecond.toFixed(0)} ops/sec below threshold ${minOpsPerSecond} ops/sec`
    );
  }
}
