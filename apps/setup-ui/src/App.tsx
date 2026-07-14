import type { SetupDecision, SetupSnapshot } from "./setup/types";
import { message, phaseLabel } from "./setup/messages";
import { useSetup } from "./setup/use-setup";
import type { SetupTransport } from "./setup/types";

interface AppProps {
  readonly capability: string | null;
  readonly transport: SetupTransport;
}

const byteFormatter = new Intl.NumberFormat("en", {
  notation: "compact",
  maximumFractionDigits: 1,
});

export function App({ capability, transport }: AppProps) {
  const setup = useSetup(capability, transport);
  const snapshot = setup.snapshot;
  const progress =
    snapshot === null
      ? 0
      : snapshot.progress.completedStages / snapshot.progress.totalStages;

  return (
    <main className="setup-shell">
      <header className="brand-bar" aria-label="AgentMemory setup">
        <a className="wordmark" href="#setup" aria-label="AgentMemory">
          <span>Agent</span>
          <i aria-hidden="true" />
          <span>Memory</span>
        </a>
        <span className="local-badge">Local only</span>
      </header>

      <section className="hero" id="setup">
        <div className="hero-copy">
          <p className="eyebrow">Private memory / this machine</p>
          <h1>
            Your agent remembers.
            <br />
            You stay in control.
          </h1>
          <p className="lede">
            AgentMemory assembles a persistent Brain on this device, then
            connects it to your coding agents. Your project memory stays local
            by default.
          </p>
        </div>
        <div className="brain-mark" aria-hidden="true">
          <span>AM</span>
        </div>
      </section>

      <section className="setup-card" aria-labelledby="setup-heading">
        <div className="card-index" aria-hidden="true">
          01 / SETUP
        </div>
        <div className="card-body">
          <StatusHeading status={setup.status} snapshot={snapshot} />
          <Progress snapshot={snapshot} progress={progress} />
          {setup.status === "unavailable" ? <Unavailable /> : null}
          {snapshot?.state === "awaiting_consent" &&
          snapshot.consent !== null ? (
            <Consent
              snapshot={snapshot}
              submitting={setup.submitting}
              onDecision={setup.decide}
            />
          ) : null}
          {snapshot !== null && snapshot.state !== "awaiting_consent" ? (
            <ActionPanel
              snapshot={snapshot}
              submitting={setup.submitting}
              onDecision={setup.decide}
            />
          ) : null}
        </div>
      </section>

      <footer>
        <span>No cloud account</span>
        <span>No terminal required</span>
        <span>Verified components</span>
      </footer>
    </main>
  );
}

function StatusHeading({
  status,
  snapshot,
}: {
  readonly status: "connecting" | "active" | "unavailable";
  readonly snapshot: SetupSnapshot | null;
}) {
  const title =
    status === "unavailable"
      ? "Protected setup link unavailable"
      : snapshot === null
        ? "Opening protected setup"
        : message(snapshot.messageKey);
  return (
    <div className="status-heading">
      <p className="status-kicker" aria-live="polite">
        {snapshot === null ? "Connecting" : phaseLabel(snapshot.phase)}
      </p>
      <h2 id="setup-heading">{title}</h2>
    </div>
  );
}

function Progress({
  snapshot,
  progress,
}: {
  readonly snapshot: SetupSnapshot | null;
  readonly progress: number;
}) {
  const percent = Math.round(progress * 100);
  return (
    <div className="progress-block" aria-label="Installation progress">
      <div className="progress-meta">
        <span>
          {snapshot === null
            ? "Preparing"
            : `${String(snapshot.progress.completedStages)} of ${String(snapshot.progress.totalStages)} stages`}
        </span>
        <span>{percent}%</span>
      </div>
      <div
        className="progress-track"
        role="progressbar"
        aria-label="AgentMemory installation progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
      >
        <span style={{ transform: `scaleX(${progress.toString()})` }} />
      </div>
      {snapshot !== null && snapshot.progress.totalBytes > 0 ? (
        <p className="byte-progress">
          {byteFormatter.format(snapshot.progress.downloadedBytes)} of{" "}
          {byteFormatter.format(snapshot.progress.totalBytes)} bytes verified
        </p>
      ) : null}
    </div>
  );
}

function Consent({
  snapshot,
  submitting,
  onDecision,
}: {
  readonly snapshot: SetupSnapshot;
  readonly submitting: boolean;
  readonly onDecision: (decision: SetupDecision) => Promise<void>;
}) {
  const consent = snapshot.consent;
  if (consent === null) return null;
  return (
    <div className="consent-panel">
      <dl className="facts-grid">
        <Fact
          label="Download"
          value={`${byteFormatter.format(consent.downloadBytes)} bytes`}
        />
        <Fact
          label="Disk after setup"
          value={`${byteFormatter.format(consent.expandedBytes)} bytes`}
        />
        <Fact
          label="Administrator approval"
          value={consent.requiresElevation ? "Required" : "Not expected"}
        />
        <Fact
          label="Restart"
          value={consent.mayRequireReboot ? "May be required" : "Not expected"}
        />
      </dl>
      <div className="change-list">
        <h3>What will change</h3>
        <ul>
          {consent.changes.map((change) => (
            <li key={change}>{change}</li>
          ))}
        </ul>
      </div>
      <p className="terms-copy">
        Continuing accepts{" "}
        <a href={consent.termsUrl} target="_blank" rel="noreferrer">
          {consent.termsTitle}
        </a>{" "}
        for this exact verified plan. Nothing is preselected.
      </p>
      <div className="button-row">
        <button
          className="primary"
          disabled={submitting}
          onClick={() => void onDecision("accept")}
        >
          Continue setup
        </button>
        <button
          className="secondary"
          disabled={submitting}
          onClick={() => void onDecision("decline")}
        >
          Not now
        </button>
      </div>
    </div>
  );
}

function Fact({
  label,
  value,
}: {
  readonly label: string;
  readonly value: string;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function ActionPanel({
  snapshot,
  submitting,
  onDecision,
}: {
  readonly snapshot: SetupSnapshot;
  readonly submitting: boolean;
  readonly onDecision: (decision: SetupDecision) => Promise<void>;
}) {
  if (snapshot.state === "ready") {
    return (
      <p className="terminal-note success" role="status">
        You can close this window. Your agent will connect automatically.
      </p>
    );
  }
  if (snapshot.safeAction === "retry") {
    return (
      <button
        className="primary"
        disabled={submitting}
        onClick={() => void onDecision("retry")}
      >
        Try again safely
      </button>
    );
  }
  if (snapshot.safeAction === "cancel" || snapshot.state === "running") {
    return (
      <button
        className="text-button"
        disabled={submitting}
        onClick={() => void onDecision("cancel")}
      >
        Cancel setup
      </button>
    );
  }
  if (
    snapshot.state === "reboot_required" ||
    snapshot.state === "paused_for_administrator"
  ) {
    return (
      <p className="terminal-note" role="status">
        Follow the protected system prompt. AgentMemory will continue from the
        verified checkpoint.
      </p>
    );
  }
  return null;
}

function Unavailable() {
  return (
    <div className="terminal-note warning" role="alert">
      Reopen setup from your agent. This one-use link may have expired; no
      installation step was authorized from this page.
    </div>
  );
}
