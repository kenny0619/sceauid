import { describe, expect, it } from "vitest";
import { resolveStaleIdentityPruneOptions } from "./prune-stale-identity-records.js";

describe("prune stale identity records command helpers", () => {
  it("resolves optional batch controls from env", () => {
    expect(
      resolveStaleIdentityPruneOptions({
        STALE_IDENTITY_PRUNE_BATCH_SIZE: "500",
        STALE_IDENTITY_PRUNE_MAX_BATCHES: "6"
      })
    ).toEqual({
      batchSize: 500,
      maxBatches: 6
    });
  });

  it("rejects invalid batch controls", () => {
    expect(() =>
      resolveStaleIdentityPruneOptions({
        STALE_IDENTITY_PRUNE_MAX_BATCHES: "0"
      })
    ).toThrow("STALE_IDENTITY_PRUNE_MAX_BATCHES must be a positive integer");
  });
});
