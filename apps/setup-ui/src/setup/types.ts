export const SETUP_STATES = [
  "connecting",
  "awaiting_consent",
  "running",
  "paused_for_administrator",
  "reboot_required",
  "ready",
  "failed",
  "cancelled",
] as const;

export type SetupState = (typeof SETUP_STATES)[number];

export const INSTALL_PHASES = [
  "verify_host",
  "ensure_container_runtime",
  "verify_release",
  "reserve_space",
  "ensure_directories",
  "ensure_keys",
  "ensure_compose_bundle",
  "ensure_network_and_volumes",
  "run_migrations",
  "ensure_core_and_graph",
  "bootstrap_local_brain",
  "merge_agent_configuration",
  "verify_readiness",
  "commit_active_release",
] as const;

export type InstallPhase = (typeof INSTALL_PHASES)[number];

export const MESSAGE_KEYS = [
  "setup.connecting",
  "setup.awaiting_consent",
  "setup.preparing_runtime",
  "setup.downloading",
  "setup.verifying",
  "setup.installing_runtime",
  "setup.starting_brain",
  "setup.checking_brain",
  "setup.ready",
  "setup.cancelled",
  "setup.retryable_failure",
  "setup.administrator_required",
  "setup.reboot_required",
] as const;

export type MessageKey = (typeof MESSAGE_KEYS)[number];
export type SafeAction =
  "none" | "retry" | "cancel" | "open_native_prompt" | "reboot";

export interface SetupProgress {
  readonly completedStages: number;
  readonly totalStages: number;
  readonly downloadedBytes: number;
  readonly totalBytes: number;
}

export interface ConsentSummary {
  readonly termsTitle: string;
  readonly termsUrl: string;
  readonly termsDigest: string;
  readonly downloadBytes: number;
  readonly expandedBytes: number;
  readonly requiresElevation: boolean;
  readonly mayRequireReboot: boolean;
  readonly changes: readonly string[];
}

export interface SetupSnapshot {
  readonly contractVersion: 1;
  readonly sequence: number;
  readonly operationId: string;
  readonly planDigest: string;
  readonly state: SetupState;
  readonly phase: InstallPhase;
  readonly messageKey: MessageKey;
  readonly progress: SetupProgress;
  readonly safeAction: SafeAction;
  readonly consent: ConsentSummary | null;
}

export interface SetupSession {
  readonly sessionToken: string;
  readonly csrfToken: string;
  readonly snapshot: SetupSnapshot;
}

export type SetupDecision = "accept" | "decline" | "retry" | "cancel";

export interface SetupTransport {
  readonly exchange: (
    capability: string,
    signal: AbortSignal,
  ) => Promise<SetupSession>;
  readonly command: (
    session: SetupSession,
    decision: SetupDecision,
    planDigest: string,
    signal: AbortSignal,
  ) => Promise<SetupSnapshot>;
  readonly stream: (
    session: SetupSession,
    afterSequence: number,
    onSnapshot: (snapshot: SetupSnapshot) => void,
    signal: AbortSignal,
  ) => Promise<void>;
}
