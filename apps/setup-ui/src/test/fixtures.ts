import type { SetupSession, SetupSnapshot } from "../setup/types";

export function setupSnapshot(
  overrides: Partial<SetupSnapshot> = {},
): SetupSnapshot {
  return {
    contractVersion: 1,
    sequence: 1,
    operationId: "operation-1",
    planDigest: "a".repeat(64),
    state: "awaiting_consent",
    phase: "ensure_container_runtime",
    messageKey: "setup.awaiting_consent",
    progress: {
      completedStages: 1,
      totalStages: 14,
      downloadedBytes: 0,
      totalBytes: 1024,
    },
    safeAction: "cancel",
    consent: {
      termsTitle: "Docker Subscription Service Agreement",
      termsUrl:
        "https://www.docker.com/legal/docker-subscription-service-agreement/",
      termsDigest: "b".repeat(64),
      downloadBytes: 1024,
      expandedBytes: 4096,
      requiresElevation: false,
      mayRequireReboot: false,
      changes: [
        "Install the verified local runtime",
        "Create private AgentMemory storage",
      ],
    },
    ...overrides,
  };
}

export function setupSession(snapshot = setupSnapshot()): SetupSession {
  return {
    sessionToken: "s".repeat(43),
    csrfToken: "c".repeat(43),
    snapshot,
  };
}
