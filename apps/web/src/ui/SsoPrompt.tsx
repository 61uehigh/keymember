import type { SsoHandler } from "@keymember/client";
import { useCallback, useRef, useState } from "react";
import type { ReactNode } from "react";

/**
 * ### useSsoPrompt
 *
 * Lets a screen take part in the company-account (SSO) check. `run` hands a handler to the SDK
 * call; while the SDK waits, `prompt` shows a button that opens the provider in a new tab (a
 * click, so the browser does not block it) and a cancel button.
 *
 * @returns `run` to wrap an SDK call, and the prompt to render
 */
export function useSsoPrompt(): {
  run: <T>(work: (handler: SsoHandler) => Promise<T>) => Promise<T>;
  prompt: ReactNode;
} {
  const [url, setUrl] = useState<string | undefined>(undefined);
  const controller = useRef<AbortController | undefined>(undefined);

  const run = useCallback(
    async <T,>(work: (handler: SsoHandler) => Promise<T>): Promise<T> => {
      const abort = new AbortController();

      controller.current = abort;

      try {
        return await work({
          signal: abort.signal,
          onChallenge: ({ path }) => {
            setUrl(new URL(path, location.origin).toString());
          },
        });
      } finally {
        setUrl(undefined);
        controller.current = undefined;
      }
    },
    [],
  );

  const prompt =
    url === undefined ? null : (
      <div className="notice stack" role="status">
        <p>
          Verify with your company account to continue. Once you finish in the
          new tab, this screen moves on automatically.
        </p>
        <div className="row wrap">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              window.open(url, "_blank", "noopener");
            }}
          >
            Verify with Google
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              controller.current?.abort(
                new Error("Company account verification was cancelled."),
              );
            }}
          >
            Cancel
          </button>
        </div>
      </div>
    );

  return { run, prompt };
}
