import {
  INSTALL_PHASES,
  MESSAGE_KEYS,
  SETUP_STATES,
  type ConsentSummary,
  type SetupProgress,
  type SetupSession,
  type SetupSnapshot,
} from "./types";

const SAFE_ACTIONS = [
  "none",
  "retry",
  "cancel",
  "open_native_prompt",
  "reboot",
] as const;
const DIGEST = /^[0-9a-f]{64}$/u;
const OPERATION_ID = /^[A-Za-z0-9._-]{1,128}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;

export class ContractError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ContractError";
  }
}

export function parseSetupSession(value: unknown): SetupSession {
  const record = requireRecord(value, [
    "sessionToken",
    "csrfToken",
    "snapshot",
  ]);
  return {
    sessionToken: requirePattern(record["sessionToken"], TOKEN, "sessionToken"),
    csrfToken: requirePattern(record["csrfToken"], TOKEN, "csrfToken"),
    snapshot: parseSetupSnapshot(record["snapshot"]),
  };
}

export function parseSetupSnapshot(value: unknown): SetupSnapshot {
  const record = requireRecord(value, [
    "contractVersion",
    "sequence",
    "operationId",
    "planDigest",
    "state",
    "phase",
    "messageKey",
    "progress",
    "safeAction",
    "consent",
  ]);
  if (record["contractVersion"] !== 1) {
    throw new ContractError("unsupported setup contract");
  }
  return {
    contractVersion: 1,
    sequence: requireSafeInteger(record["sequence"], "sequence"),
    operationId: requirePattern(
      record["operationId"],
      OPERATION_ID,
      "operationId",
    ),
    planDigest: requirePattern(record["planDigest"], DIGEST, "planDigest"),
    state: requireMember(record["state"], SETUP_STATES, "state"),
    phase: requireMember(record["phase"], INSTALL_PHASES, "phase"),
    messageKey: requireMember(record["messageKey"], MESSAGE_KEYS, "messageKey"),
    progress: parseProgress(record["progress"]),
    safeAction: requireMember(record["safeAction"], SAFE_ACTIONS, "safeAction"),
    consent:
      record["consent"] === null ? null : parseConsent(record["consent"]),
  } satisfies SetupSnapshot;
}

function parseProgress(value: unknown): SetupProgress {
  const record = requireRecord(value, [
    "completedStages",
    "totalStages",
    "downloadedBytes",
    "totalBytes",
  ]);
  const progress = {
    completedStages: requireSafeInteger(
      record["completedStages"],
      "completedStages",
    ),
    totalStages: requireSafeInteger(record["totalStages"], "totalStages"),
    downloadedBytes: requireSafeInteger(
      record["downloadedBytes"],
      "downloadedBytes",
    ),
    totalBytes: requireSafeInteger(record["totalBytes"], "totalBytes"),
  } satisfies SetupProgress;
  if (
    progress.totalStages < 1 ||
    progress.completedStages > progress.totalStages ||
    progress.downloadedBytes > progress.totalBytes
  ) {
    throw new ContractError("setup progress is inconsistent");
  }
  return progress;
}

function parseConsent(value: unknown): ConsentSummary {
  const record = requireRecord(value, [
    "termsTitle",
    "termsUrl",
    "termsDigest",
    "downloadBytes",
    "expandedBytes",
    "requiresElevation",
    "mayRequireReboot",
    "changes",
  ]);
  const termsUrl = requireString(record["termsUrl"], "termsUrl");
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(termsUrl);
  } catch {
    throw new ContractError("termsUrl is invalid");
  }
  if (parsedUrl.protocol !== "https:") {
    throw new ContractError("termsUrl must use HTTPS");
  }
  if (!Array.isArray(record["changes"]) || record["changes"].length > 16) {
    throw new ContractError("changes is invalid");
  }
  const changes = record["changes"].map((change) =>
    requireBoundedText(change, "change", 160),
  );
  return {
    termsTitle: requireBoundedText(record["termsTitle"], "termsTitle", 120),
    termsUrl,
    termsDigest: requirePattern(record["termsDigest"], DIGEST, "termsDigest"),
    downloadBytes: requireSafeInteger(record["downloadBytes"], "downloadBytes"),
    expandedBytes: requireSafeInteger(record["expandedBytes"], "expandedBytes"),
    requiresElevation: requireBoolean(
      record["requiresElevation"],
      "requiresElevation",
    ),
    mayRequireReboot: requireBoolean(
      record["mayRequireReboot"],
      "mayRequireReboot",
    ),
    changes,
  };
}

function requireRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ContractError("setup response must be an object");
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new ContractError("setup response fields are invalid");
  }
  return record;
}

function requireMember<const T extends readonly string[]>(
  value: unknown,
  members: T,
  field: string,
): T[number] {
  if (typeof value !== "string" || !members.includes(value)) {
    throw new ContractError(`${field} is invalid`);
  }
  return value;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ContractError(`${field} is invalid`);
  }
  return value;
}

function requireBoundedText(
  value: unknown,
  field: string,
  maximum: number,
): string {
  const text = requireString(value, field);
  const containsControlCharacter = Array.from(text).some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
  if (text.length < 1 || text.length > maximum || containsControlCharacter) {
    throw new ContractError(`${field} is invalid`);
  }
  return text;
}

function requirePattern(
  value: unknown,
  pattern: RegExp,
  field: string,
): string {
  const text = requireString(value, field);
  if (!pattern.test(text)) {
    throw new ContractError(`${field} is invalid`);
  }
  return text;
}

function requireSafeInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ContractError(`${field} is invalid`);
  }
  return value;
}

function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new ContractError(`${field} is invalid`);
  }
  return value;
}
