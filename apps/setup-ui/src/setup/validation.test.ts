import { describe, expect, it } from "vitest";

import { setupSession, setupSnapshot } from "../test/fixtures";
import {
  ContractError,
  parseSetupSession,
  parseSetupSnapshot,
} from "./validation";

describe("setup response validation", () => {
  it("accepts an exact complete session contract", () => {
    const session = setupSession();
    expect(parseSetupSession(structuredClone(session))).toEqual(session);
  });

  it("rejects unknown fields rather than silently widening authority", () => {
    const snapshot = { ...setupSnapshot(), rawError: "docker socket path" };
    expect(() => parseSetupSnapshot(snapshot)).toThrow(ContractError);
  });

  it.each([
    { sequence: -1 },
    { planDigest: "A".repeat(64) },
    { state: "almost_ready" },
    { messageKey: "docker.raw_error" },
    {
      progress: {
        completedStages: 15,
        totalStages: 14,
        downloadedBytes: 0,
        totalBytes: 1,
      },
    },
  ])("rejects malformed security-relevant values", (override) => {
    expect(() =>
      parseSetupSnapshot({ ...setupSnapshot(), ...override }),
    ).toThrow(ContractError);
  });

  it("rejects non-HTTPS terms and control characters", () => {
    const baseline = setupSnapshot();
    expect(() =>
      parseSetupSnapshot({
        ...baseline,
        consent: { ...baseline.consent, termsUrl: "http://example.test/terms" },
      }),
    ).toThrow(ContractError);
    expect(() =>
      parseSetupSnapshot({
        ...baseline,
        consent: { ...baseline.consent, changes: ["unsafe\u0000text"] },
      }),
    ).toThrow(ContractError);
  });
});
