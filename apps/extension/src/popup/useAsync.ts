import { useCallback, useRef, useState } from "react";

/**
 * ### useAsync
 *
 * Busy and error state around async handlers.
 *
 * @returns Busy flag, last error and runner
 */
export function useAsync(): {
  busy: boolean;
  error: string;
  run: (work: () => Promise<void>) => void;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // A double click must not send the same request twice while the first is still running
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
        setError(caught instanceof Error ? caught.message : String(caught));
      })
      .finally(() => {
        inFlight.current = false;
        setBusy(false);
      });
  }, []);

  return { busy, error, run };
}
