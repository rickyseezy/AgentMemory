import { afterEach, describe, expect, it, vi } from "vitest";

import { setupSession, setupSnapshot } from "../test/fixtures";
import { HttpSetupTransport, SetupConnectionError } from "./http-transport";
import type { SetupSnapshot } from "./types";

function jsonResponse(value: unknown, status = 200): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": String(body.length),
    },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("HttpSetupTransport", () => {
  it("exchanges the URL capability only through the authorization header", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(setupSession()));
    vi.stubGlobal("fetch", fetchMock);
    const controller = new AbortController();

    const result = await new HttpSetupTransport().exchange(
      "A".repeat(43),
      controller.signal,
    );

    expect(result).toEqual(setupSession());
    const [, request] = fetchMock.mock.calls[0] ?? [];
    expect(request?.headers).toMatchObject({
      Authorization: `AgentMemorySetup ${"A".repeat(43)}`,
    });
    expect(request?.body).not.toContain("A".repeat(43));
  });

  it("binds decisions to the session CSRF token and exact plan", async () => {
    const next = setupSnapshot({
      sequence: 2,
      state: "running",
      consent: null,
    });
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(next));
    vi.stubGlobal("fetch", fetchMock);

    await new HttpSetupTransport().command(
      setupSession(),
      "accept",
      "a".repeat(64),
      new AbortController().signal,
    );

    const [, request] = fetchMock.mock.calls[0] ?? [];
    expect(request?.headers).toMatchObject({
      Authorization: `AgentMemorySession ${"s".repeat(43)}`,
      "X-AgentMemory-CSRF": "c".repeat(43),
    });
    expect(typeof request?.body).toBe("string");
    const body: unknown =
      typeof request?.body === "string" ? JSON.parse(request.body) : null;
    expect(body).toMatchObject({
      contractVersion: 1,
      decision: "accept",
      planDigest: "a".repeat(64),
    });
  });

  it("streams only strictly increasing authenticated snapshot events", async () => {
    const snapshot = setupSnapshot({
      sequence: 2,
      state: "running",
      consent: null,
    });
    const event = `id: 2\nevent: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(event.slice(0, 31)));
        controller.enqueue(new TextEncoder().encode(event.slice(31)));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(stream, {
          headers: { "Content-Type": "text/event-stream; charset=utf-8" },
        }),
      ),
    );
    const received: SetupSnapshot[] = [];

    await new HttpSetupTransport().stream(
      setupSession(),
      1,
      (value) => received.push(value),
      new AbortController().signal,
    );

    expect(received).toEqual([snapshot]);
  });

  it("fails closed on expired sessions and oversized or replayed responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({}, 410)),
    );
    await expect(
      new HttpSetupTransport().exchange(
        "A".repeat(43),
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "session_expired" });

    const replay = setupSnapshot({ sequence: 1 });
    const event = `id: 1\nevent: snapshot\ndata: ${JSON.stringify(replay)}\n\n`;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(event, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      ),
    );
    await expect(
      new HttpSetupTransport().stream(
        setupSession(),
        1,
        () => undefined,
        new AbortController().signal,
      ),
    ).rejects.toBeInstanceOf(SetupConnectionError);
  });

  it.each([401, 403])(
    "treats HTTP %s as an expired protected session",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({}, status)),
      );
      await expect(
        new HttpSetupTransport().exchange(
          "A".repeat(43),
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ code: "session_expired" });
    },
  );

  it.each([
    [
      new Response("{}", { headers: { "Content-Type": "text/plain" } }),
      "invalid_response",
    ],
    [jsonResponse({}, 500), "connection_failed"],
    [
      new Response("not-json", {
        headers: { "Content-Type": "application/json" },
      }),
      "invalid_response",
    ],
  ])(
    "maps untrusted HTTP responses to one safe connection code",
    async (response, code) => {
      vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(response));
      await expect(
        new HttpSetupTransport().exchange(
          "A".repeat(43),
          new AbortController().signal,
        ),
      ).rejects.toMatchObject({ code });
    },
  );

  it("maps transport failures without exposing the native error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockRejectedValue(new TypeError("private path")),
    );
    await expect(
      new HttpSetupTransport().exchange(
        "A".repeat(43),
        new AbortController().signal,
      ),
    ).rejects.toEqual(new SetupConnectionError("connection_failed"));
  });

  it("accepts heartbeat comments but rejects unknown SSE authority fields", async () => {
    const snapshot = setupSnapshot({ sequence: 2, consent: null });
    const valid = `: heartbeat\n\nid: 2\nevent: snapshot\nretry: 1000\ndata: ${JSON.stringify(snapshot)}\n\n`;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(valid, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      ),
    );
    const received: SetupSnapshot[] = [];
    await new HttpSetupTransport().stream(
      setupSession(),
      1,
      (value) => received.push(value),
      new AbortController().signal,
    );
    expect(received).toHaveLength(1);

    const invalid = `id: 2\nevent: snapshot\nauthority: broaden\ndata: ${JSON.stringify(snapshot)}\n\n`;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(invalid, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      ),
    );
    await expect(
      new HttpSetupTransport().stream(
        setupSession(),
        1,
        () => undefined,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("accepts standards-compliant CRLF event boundaries", async () => {
    const snapshot = setupSnapshot({ sequence: 2, consent: null });
    const event = `id: 2\r\nevent: snapshot\r\ndata: ${JSON.stringify(snapshot)}\r\n\r\n`;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(event, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      ),
    );
    const received: SetupSnapshot[] = [];
    await new HttpSetupTransport().stream(
      setupSession(),
      1,
      (value) => received.push(value),
      new AbortController().signal,
    );
    expect(received).toEqual([snapshot]);
  });

  it.each([
    new Response(null, { headers: { "Content-Type": "text/event-stream" } }),
    new Response("{}", { headers: { "Content-Type": "application/json" } }),
  ])("rejects a response that cannot carry an SSE stream", async (response) => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(response));
    await expect(
      new HttpSetupTransport().stream(
        setupSession(),
        1,
        () => undefined,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it.each([
    "id: 2\ndata: {}\n\n",
    "id: 2\nevent: snapshot\n\n",
    "id: 9999999999999999\nevent: snapshot\ndata: {}\n\n",
  ])("rejects an incomplete or unsafe SSE event", async (event) => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(event, {
          headers: { "Content-Type": "text/event-stream" },
        }),
      ),
    );
    await expect(
      new HttpSetupTransport().stream(
        setupSession(),
        1,
        () => undefined,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("preserves an explicit browser abort without replacing it with diagnostics", async () => {
    const abort = new DOMException("cancelled", "AbortError");
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockRejectedValue(abort));
    await expect(
      new HttpSetupTransport().exchange(
        "A".repeat(43),
        new AbortController().signal,
      ),
    ).rejects.toBe(abort);
  });

  it("rejects a declared JSON response larger than the protocol budget", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response("{}", {
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(65 * 1024),
          },
        }),
      ),
    );
    await expect(
      new HttpSetupTransport().exchange(
        "A".repeat(43),
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });
});
