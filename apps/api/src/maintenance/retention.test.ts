import { describe, expect, it } from "vitest";
import {
  pruneInBatches,
  readOptionalPositiveInteger,
  resolveRetentionCutoff
} from "./retention.js";

describe("retention helpers", () => {
  it("resolves retention cutoffs from day windows", () => {
    expect(resolveRetentionCutoff(new Date("2026-06-25T12:00:00.000Z"), 30)).toEqual(
      new Date("2026-05-26T12:00:00.000Z")
    );
  });

  it("reads optional positive integer env values", () => {
    expect(readOptionalPositiveInteger({}, "BATCH_SIZE")).toBeUndefined();
    expect(readOptionalPositiveInteger({ BATCH_SIZE: "250" }, "BATCH_SIZE")).toBe(250);
  });

  it("rejects invalid integer env values", () => {
    expect(() => readOptionalPositiveInteger({ BATCH_SIZE: "0" }, "BATCH_SIZE")).toThrow(
      "BATCH_SIZE must be a positive integer"
    );
  });

  it("prunes in batches until a partial batch completes the run", async () => {
    const calls: number[] = [];
    const results = [2, 1];

    await expect(
      pruneInBatches(
        async (limit) => {
          calls.push(limit);
          return results.shift() ?? 0;
        },
        { batchSize: 2, maxBatches: 5 }
      )
    ).resolves.toEqual({
      deletedCount: 3,
      batches: 2,
      complete: true
    });
    expect(calls).toEqual([2, 2]);
  });

  it("marks prune runs incomplete after the max batch count", async () => {
    await expect(
      pruneInBatches(async () => 2, {
        batchSize: 2,
        maxBatches: 2
      })
    ).resolves.toEqual({
      deletedCount: 4,
      batches: 2,
      complete: false
    });
  });
});
