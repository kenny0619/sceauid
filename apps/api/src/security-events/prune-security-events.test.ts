import { describe, expect, it } from "vitest";
import { resolvePruneOptions, resolveRetentionCutoff } from "./prune-security-events.js";

describe("prune security events command helpers", () => {
  it("resolves the retention cutoff from days", () => {
    expect(resolveRetentionCutoff(new Date("2026-06-25T12:00:00.000Z"), 30)).toEqual(
      new Date("2026-05-26T12:00:00.000Z")
    );
  });

  it("resolves optional batch controls from env", () => {
    expect(
      resolvePruneOptions({
        SECURITY_EVENT_PRUNE_BATCH_SIZE: "250",
        SECURITY_EVENT_PRUNE_MAX_BATCHES: "4"
      })
    ).toEqual({
      batchSize: 250,
      maxBatches: 4
    });
  });

  it("rejects invalid batch controls", () => {
    expect(() =>
      resolvePruneOptions({
        SECURITY_EVENT_PRUNE_BATCH_SIZE: "0"
      })
    ).toThrow("SECURITY_EVENT_PRUNE_BATCH_SIZE must be a positive integer");
  });
});
