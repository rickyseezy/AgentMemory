import { describe, expect, it, vi } from "vitest";

import { consumeSetupCapability } from "./capability";

describe("consumeSetupCapability", () => {
  it("returns one exact 256-bit token and removes it from browser history", () => {
    const capability = "A".repeat(43);
    window.history.replaceState(
      null,
      "",
      `/setup?operation=one#capability=${capability}`,
    );
    const replace = vi.spyOn(window.history, "replaceState");

    expect(consumeSetupCapability(window.location, window.history)).toBe(
      capability,
    );
    expect(replace).toHaveBeenLastCalledWith(null, "", "/setup?operation=one");
    expect(window.location.hash).toBe("");
  });

  it.each(["", "short", `${"A".repeat(43)}=`, "contains%2Fslash"])(
    "rejects malformed capability %s after scrubbing it",
    (capability) => {
      window.history.replaceState(null, "", `/setup#capability=${capability}`);
      expect(
        consumeSetupCapability(window.location, window.history),
      ).toBeNull();
      expect(window.location.hash).toBe("");
    },
  );

  it.each([
    `capability=${"A".repeat(43)}&capability=${"B".repeat(43)}`,
    `capability=${"A".repeat(43)}&redirect=outside`,
  ])("rejects ambiguous fragment authority %s", (fragment) => {
    window.history.replaceState(null, "", `/setup#${fragment}`);
    expect(consumeSetupCapability(window.location, window.history)).toBeNull();
    expect(window.location.hash).toBe("");
  });
});
