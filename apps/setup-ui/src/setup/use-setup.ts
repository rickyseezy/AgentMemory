import { useCallback, useEffect, useMemo, useReducer, useRef } from "react";

import type {
  SetupDecision,
  SetupSession,
  SetupSnapshot,
  SetupTransport,
} from "./types";

interface ViewState {
  readonly status: "connecting" | "active" | "unavailable";
  readonly session: SetupSession | null;
  readonly snapshot: SetupSnapshot | null;
  readonly submitting: boolean;
}

type Action =
  | { readonly type: "connected"; readonly session: SetupSession }
  | { readonly type: "snapshot"; readonly snapshot: SetupSnapshot }
  | { readonly type: "submitting"; readonly value: boolean }
  | { readonly type: "unavailable" };

const INITIAL_STATE: ViewState = {
  status: "connecting",
  session: null,
  snapshot: null,
  submitting: false,
};

function reduce(state: ViewState, action: Action): ViewState {
  switch (action.type) {
    case "connected":
      return {
        status: "active",
        session: action.session,
        snapshot: action.session.snapshot,
        submitting: false,
      };
    case "snapshot":
      if (
        state.snapshot !== null &&
        action.snapshot.sequence <= state.snapshot.sequence
      ) {
        return state;
      }
      return {
        ...state,
        status: "active",
        snapshot: action.snapshot,
        submitting: false,
      };
    case "submitting":
      return { ...state, submitting: action.value };
    case "unavailable":
      return { ...state, status: "unavailable", submitting: false };
  }
}

function isTerminal(snapshot: SetupSnapshot | null): boolean {
  return (
    snapshot !== null &&
    ["ready", "failed", "cancelled"].includes(snapshot.state)
  );
}

export interface SetupController extends ViewState {
  readonly decide: (decision: SetupDecision) => Promise<void>;
}

export function useSetup(
  capability: string | null,
  transport: SetupTransport,
): SetupController {
  const [state, dispatch] = useReducer(reduce, INITIAL_STATE);
  const latestSnapshot = useRef<SetupSnapshot | null>(null);
  const commandController = useRef<AbortController | null>(null);

  useEffect(() => {
    if (capability === null) {
      dispatch({ type: "unavailable" });
      return undefined;
    }
    const controller = new AbortController();
    const connect = async (): Promise<void> => {
      try {
        const session = await transport.exchange(capability, controller.signal);
        if (controller.signal.aborted) return;
        latestSnapshot.current = session.snapshot;
        dispatch({ type: "connected", session });
        if (isTerminal(session.snapshot)) return;
        await transport.stream(
          session,
          session.snapshot.sequence,
          (snapshot) => {
            latestSnapshot.current = snapshot;
            dispatch({ type: "snapshot", snapshot });
            if (isTerminal(snapshot)) controller.abort();
          },
          controller.signal,
        );
        if (!isTerminal(latestSnapshot.current)) {
          dispatch({ type: "unavailable" });
        }
      } catch {
        if (!controller.signal.aborted) dispatch({ type: "unavailable" });
      }
    };
    void connect();
    return () => {
      controller.abort();
      commandController.current?.abort();
    };
  }, [capability, transport]);

  const decide = useCallback(
    async (decision: SetupDecision): Promise<void> => {
      if (state.session === null || state.snapshot === null || state.submitting)
        return;
      commandController.current?.abort();
      const controller = new AbortController();
      commandController.current = controller;
      dispatch({ type: "submitting", value: true });
      try {
        const snapshot = await transport.command(
          state.session,
          decision,
          state.snapshot.planDigest,
          controller.signal,
        );
        if (!controller.signal.aborted) {
          latestSnapshot.current = snapshot;
          dispatch({ type: "snapshot", snapshot });
        }
      } catch {
        if (!controller.signal.aborted) dispatch({ type: "unavailable" });
      } finally {
        if (commandController.current === controller)
          commandController.current = null;
      }
    },
    [state.session, state.snapshot, state.submitting, transport],
  );

  return useMemo(() => ({ ...state, decide }), [state, decide]);
}
