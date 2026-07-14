import type { InstallPhase, MessageKey } from "./types";

const ENGLISH_MESSAGES: Readonly<Record<MessageKey, string>> = {
  "setup.connecting": "Opening the protected setup session…",
  "setup.awaiting_consent": "Your local Brain is ready to be assembled.",
  "setup.preparing_runtime": "Preparing the private runtime…",
  "setup.downloading": "Bringing the verified components onto this device…",
  "setup.verifying": "Checking signatures and release evidence…",
  "setup.installing_runtime": "Installing the local runtime…",
  "setup.starting_brain": "Starting the private Brain…",
  "setup.checking_brain": "Testing memory, search, and local models…",
  "setup.ready": "Your local Brain is ready.",
  "setup.cancelled": "Setup was cancelled safely.",
  "setup.retryable_failure":
    "Setup paused before anything unsafe could continue.",
  "setup.administrator_required":
    "This device needs administrator approval to continue.",
  "setup.reboot_required":
    "A restart is required. Setup will continue automatically afterward.",
};

export function message(key: MessageKey): string {
  return ENGLISH_MESSAGES[key];
}

export function phaseLabel(phase: InstallPhase): string {
  const labels: Readonly<Record<InstallPhase, string>> = {
    verify_host: "Check this device",
    ensure_container_runtime: "Prepare local runtime",
    verify_release: "Verify release",
    reserve_space: "Reserve safe disk space",
    ensure_directories: "Prepare protected storage",
    ensure_keys: "Create local keys",
    ensure_compose_bundle: "Stage application",
    ensure_network_and_volumes: "Create private resources",
    run_migrations: "Initialize data",
    ensure_core_and_graph: "Start Core and graph",
    bootstrap_local_brain: "Create your Brain",
    merge_agent_configuration: "Connect your agent",
    verify_readiness: "Test semantic memory",
    commit_active_release: "Activate release",
  };
  return labels[phase];
}
