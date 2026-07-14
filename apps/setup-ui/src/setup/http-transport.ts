import type {
  SetupDecision,
  SetupSession,
  SetupSnapshot,
  SetupTransport,
} from "./types";
import {
  ContractError,
  parseSetupSession,
  parseSetupSnapshot,
} from "./validation";

const MAXIMUM_RESPONSE_BYTES = 64 * 1024;
const MAXIMUM_EVENT_BYTES = 16 * 1024;

export type ConnectionFailureCode =
  "connection_failed" | "invalid_response" | "session_expired";

export class SetupConnectionError extends Error {
  public readonly code: ConnectionFailureCode;

  public constructor(code: ConnectionFailureCode) {
    super(code);
    this.name = "SetupConnectionError";
    this.code = code;
  }
}

export class HttpSetupTransport implements SetupTransport {
  public async exchange(
    capability: string,
    signal: AbortSignal,
  ): Promise<SetupSession> {
    const response = await request(
      "/setup/v1/session",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `AgentMemorySetup ${capability}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ contractVersion: 1 }),
      },
      signal,
    );
    return parseJsonResponse(response, parseSetupSession);
  }

  public async command(
    session: SetupSession,
    decision: SetupDecision,
    planDigest: string,
    signal: AbortSignal,
  ): Promise<SetupSnapshot> {
    const response = await request(
      "/setup/v1/commands",
      {
        method: "POST",
        headers: sessionHeaders(session, "application/json"),
        body: JSON.stringify({
          contractVersion: 1,
          decision,
          idempotencyKey: crypto.randomUUID(),
          planDigest,
        }),
      },
      signal,
    );
    return parseJsonResponse(response, parseSetupSnapshot);
  }

  public async stream(
    session: SetupSession,
    afterSequence: number,
    onSnapshot: (snapshot: SetupSnapshot) => void,
    signal: AbortSignal,
  ): Promise<void> {
    const response = await request(
      `/setup/v1/events?after=${encodeURIComponent(String(afterSequence))}`,
      {
        method: "GET",
        headers: sessionHeaders(session, "text/event-stream"),
      },
      signal,
    );
    const contentType = response.headers
      .get("content-type")
      ?.split(";", 1)[0]
      ?.trim();
    if (contentType !== "text/event-stream" || response.body === null) {
      throw new SetupConnectionError("invalid_response");
    }
    await consumeEventStream(response.body, afterSequence, onSnapshot, signal);
  }
}

async function request(
  path: string,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      signal,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new SetupConnectionError("connection_failed");
  }
  if (
    response.status === 401 ||
    response.status === 403 ||
    response.status === 410
  ) {
    throw new SetupConnectionError("session_expired");
  }
  if (!response.ok) {
    throw new SetupConnectionError("connection_failed");
  }
  return response;
}

function sessionHeaders(session: SetupSession, accept: string): HeadersInit {
  return {
    Accept: accept,
    Authorization: `AgentMemorySession ${session.sessionToken}`,
    "Content-Type": "application/json",
    "X-AgentMemory-CSRF": session.csrfToken,
  };
}

async function parseJsonResponse<T>(
  response: Response,
  parse: (value: unknown) => T,
): Promise<T> {
  const contentType = response.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim();
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (
    contentType !== "application/json" ||
    !Number.isSafeInteger(declaredLength) ||
    declaredLength < 0 ||
    declaredLength > MAXIMUM_RESPONSE_BYTES
  ) {
    throw new SetupConnectionError("invalid_response");
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAXIMUM_RESPONSE_BYTES) {
    throw new SetupConnectionError("invalid_response");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
    return parse(value);
  } catch (error: unknown) {
    if (error instanceof ContractError || error instanceof SyntaxError) {
      throw new SetupConnectionError("invalid_response");
    }
    throw error;
  }
}

async function consumeEventStream(
  stream: ReadableStream<Uint8Array>,
  afterSequence: number,
  onSnapshot: (snapshot: SetupSnapshot) => void,
  signal: AbortSignal,
): Promise<void> {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let buffer = "";
  let lastSequence = afterSequence;
  try {
    while (!signal.aborted) {
      const result = await reader.read();
      buffer += decoder.decode(result.value, { stream: !result.done });
      if (new TextEncoder().encode(buffer).byteLength > MAXIMUM_EVENT_BYTES) {
        throw new SetupConnectionError("invalid_response");
      }
      let boundary = eventBoundary(buffer);
      while (boundary !== null) {
        const block = buffer.slice(0, boundary.index).replaceAll("\r", "");
        buffer = buffer.slice(boundary.index + boundary.length);
        if (block !== "" && !block.startsWith(":")) {
          const parsed = parseEvent(block);
          if (
            parsed.snapshot.sequence <= lastSequence ||
            parsed.id !== parsed.snapshot.sequence
          ) {
            throw new SetupConnectionError("invalid_response");
          }
          lastSequence = parsed.snapshot.sequence;
          onSnapshot(parsed.snapshot);
        }
        boundary = eventBoundary(buffer);
      }
      if (result.done) {
        if (buffer.trim() !== "") {
          throw new SetupConnectionError("invalid_response");
        }
        return;
      }
    }
  } catch (error: unknown) {
    if (error instanceof SetupConnectionError) {
      throw error;
    }
    if (error instanceof TypeError) {
      throw new SetupConnectionError("invalid_response");
    }
    throw error;
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function eventBoundary(
  buffer: string,
): { readonly index: number; readonly length: number } | null {
  const lineFeed = buffer.indexOf("\n\n");
  const carriageReturn = buffer.indexOf("\r\n\r\n");
  if (lineFeed < 0 && carriageReturn < 0) return null;
  if (lineFeed >= 0 && (carriageReturn < 0 || lineFeed < carriageReturn)) {
    return { index: lineFeed, length: 2 };
  }
  return { index: carriageReturn, length: 4 };
}

function parseEvent(block: string): {
  readonly id: number;
  readonly snapshot: SetupSnapshot;
} {
  let event = "message";
  let id = "";
  const data: string[] = [];
  for (const line of block.split("\n")) {
    const separator = line.indexOf(":");
    const field = separator < 0 ? line : line.slice(0, separator);
    const rawValue = separator < 0 ? "" : line.slice(separator + 1);
    const value = rawValue.startsWith(" ") ? rawValue.slice(1) : rawValue;
    switch (field) {
      case "event":
        event = value;
        break;
      case "id":
        id = value;
        break;
      case "data":
        data.push(value);
        break;
      case "retry":
      case "":
        break;
      default:
        throw new SetupConnectionError("invalid_response");
    }
  }
  if (event !== "snapshot" || !/^[0-9]{1,16}$/u.test(id) || data.length === 0) {
    throw new SetupConnectionError("invalid_response");
  }
  const numericId = Number(id);
  if (!Number.isSafeInteger(numericId)) {
    throw new SetupConnectionError("invalid_response");
  }
  try {
    return {
      id: numericId,
      snapshot: parseSetupSnapshot(JSON.parse(data.join("\n")) as unknown),
    };
  } catch (error: unknown) {
    if (error instanceof ContractError || error instanceof SyntaxError) {
      throw new SetupConnectionError("invalid_response");
    }
    throw error;
  }
}
