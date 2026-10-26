import { useCallback, useRef, useState } from "react";

/**
 * ### IPC_PREFIX
 *
 * What Electron puts in front of an error thrown in the main process.
 */
const IPC_PREFIX = /^Error invoking remote method '[^']*': (?:\w*Error: )?/;

/**
 * ### errorMessage
 *
 * The text to show for a failed request. The main process already turns errors into Korean
 * messages; this only removes Electron's prefix.
 *
 * @param caught What the request threw
 * @returns Message for the window
 */
export function errorMessage(caught: unknown): string {
  const text = caught instanceof Error ? caught.message : String(caught);

  return text.replace(IPC_PREFIX, "");
}

/**
 * ### useAction
 *
 * Runs one async action at a time and keeps its error message. A second run while one is in
 * flight is ignored, so double clicks do not send a request twice.
 *
 * @returns Busy flag, error and runner
 */
export function useAction(): {
  busy: boolean;
  error: string;
  run: (work: () => Promise<void>) => void;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inFlight = useRef(false);
  const run = useCallback((work: () => Promise<void>) => {
    if (inFlight.current) {
      return;
    }

    inFlight.current = true;
    setBusy(true);
    setError("");
    work()
      .catch((caught: unknown) => {
        setError(errorMessage(caught));
      })
      .finally(() => {
        inFlight.current = false;
        setBusy(false);
      });
  }, []);

  return { busy, error, run };
}
