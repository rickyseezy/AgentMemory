import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { setupSession, setupSnapshot } from "./test/fixtures";
import type { SetupTransport } from "./setup/types";

function activeTransport(snapshot = setupSnapshot()): SetupTransport {
  const exchange: SetupTransport["exchange"] = vi
    .fn()
    .mockResolvedValue(setupSession(snapshot));
  const command: SetupTransport["command"] = vi.fn().mockResolvedValue(
    setupSnapshot({
      sequence: 2,
      state: "running",
      consent: null,
      messageKey: "setup.downloading",
    }),
  );
  const stream: SetupTransport["stream"] = vi.fn(
    async (_session, _after, _onSnapshot, signal: AbortSignal) =>
      new Promise<void>((resolve) => {
        signal.addEventListener(
          "abort",
          () => {
            resolve();
          },
          { once: true },
        );
      }),
  );
  return {
    exchange,
    command,
    stream,
  };
}

describe("setup application", () => {
  it("shows an unselected exact-plan consent and submits an explicit decision", async () => {
    const transport = activeTransport();
    const user = userEvent.setup();
    render(<App capability={"A".repeat(43)} transport={transport} />);

    expect(
      await screen.findByRole("heading", { name: /ready to be assembled/i }),
    ).toBeVisible();
    expect(screen.getByText(/Nothing is preselected/i)).toBeVisible();
    expect(
      screen.getByText("Install the verified local runtime"),
    ).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Continue setup" }));
    const command = transport.command;
    expect(command).toHaveBeenCalledWith(
      expect.anything(),
      "accept",
      "a".repeat(64),
      expect.any(AbortSignal),
    );
  });

  it("has no automated WCAG violations in the consent journey", async () => {
    render(<App capability={"A".repeat(43)} transport={activeTransport()} />);
    await screen.findByRole("button", { name: "Continue setup" });
    const results = await axe.run(document.body, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(results.violations).toEqual([]);
  });

  it("does not expose diagnostics when the one-use capability is absent", async () => {
    render(<App capability={null} transport={activeTransport()} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /one-use link may have expired/i,
    );
    expect(screen.queryByText(/docker socket/i)).not.toBeInTheDocument();
  });

  it("presents terminal readiness without offering another mutation", async () => {
    const snapshot = setupSnapshot({
      state: "ready",
      messageKey: "setup.ready",
      phase: "commit_active_release",
      safeAction: "none",
      consent: null,
      progress: {
        completedStages: 14,
        totalStages: 14,
        downloadedBytes: 1024,
        totalBytes: 1024,
      },
    });
    render(
      <App capability={"A".repeat(43)} transport={activeTransport(snapshot)} />,
    );
    expect(await screen.findByText(/close this window/i)).toBeVisible();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it.each([
    ["failed", "retry", "Try again safely", "retry"],
    ["running", "cancel", "Cancel setup", "cancel"],
  ] as const)(
    "offers only the server-authorized safe action for %s",
    async (state, safeAction, label, decision) => {
      const snapshot = setupSnapshot({
        state,
        safeAction,
        consent: null,
        messageKey:
          state === "failed" ? "setup.retryable_failure" : "setup.downloading",
      });
      const transport = activeTransport(snapshot);
      const user = userEvent.setup();
      render(<App capability={"A".repeat(43)} transport={transport} />);
      await user.click(await screen.findByRole("button", { name: label }));
      expect(transport.command).toHaveBeenCalledWith(
        expect.anything(),
        decision,
        "a".repeat(64),
        expect.any(AbortSignal),
      );
    },
  );

  it.each(["reboot_required", "paused_for_administrator"] as const)(
    "defers %s to a protected native prompt",
    async (state) => {
      const snapshot = setupSnapshot({
        state,
        safeAction:
          state === "reboot_required" ? "reboot" : "open_native_prompt",
        consent: null,
        messageKey:
          state === "reboot_required"
            ? "setup.reboot_required"
            : "setup.administrator_required",
      });
      render(
        <App
          capability={"A".repeat(43)}
          transport={activeTransport(snapshot)}
        />,
      );
      expect(await screen.findByText(/protected system prompt/i)).toBeVisible();
      expect(screen.queryByRole("button")).not.toBeInTheDocument();
    },
  );

  it("applies a newer streamed snapshot and keeps terminal completion visible", async () => {
    const running = setupSnapshot({ state: "running", consent: null });
    const ready = setupSnapshot({
      sequence: 2,
      state: "ready",
      phase: "commit_active_release",
      messageKey: "setup.ready",
      safeAction: "none",
      consent: null,
      progress: {
        completedStages: 14,
        totalStages: 14,
        downloadedBytes: 0,
        totalBytes: 0,
      },
    });
    const stream: SetupTransport["stream"] = (_session, _after, onSnapshot) => {
      onSnapshot(ready);
      return Promise.resolve();
    };
    const transport: SetupTransport = {
      exchange: vi.fn().mockResolvedValue(setupSession(running)),
      command: vi.fn().mockResolvedValue(ready),
      stream,
    };
    render(<App capability={"A".repeat(43)} transport={transport} />);
    expect(await screen.findByText(/close this window/i)).toBeVisible();
  });

  it("fails closed when the protected session cannot be established", async () => {
    const transport: SetupTransport = {
      exchange: vi.fn().mockRejectedValue(new Error("native details")),
      command: vi.fn().mockRejectedValue(new Error("unused")),
      stream: vi.fn().mockRejectedValue(new Error("unused")),
    };
    render(<App capability={"A".repeat(43)} transport={transport} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/one-use link/i);
    expect(screen.queryByText(/native details/i)).not.toBeInTheDocument();
  });

  it("fails closed when a decision cannot be authenticated", async () => {
    const transport = activeTransport();
    const command: SetupTransport["command"] = vi
      .fn()
      .mockRejectedValue(new Error("secret detail"));
    const failing = { ...transport, command };
    const user = userEvent.setup();
    render(<App capability={"A".repeat(43)} transport={failing} />);
    await user.click(
      await screen.findByRole("button", { name: "Continue setup" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/one-use link/i);
    expect(screen.queryByText(/secret detail/i)).not.toBeInTheDocument();
  });
});
