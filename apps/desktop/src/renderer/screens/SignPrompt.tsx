import type { SignRequestView } from "../../shared/ipc.js";

/**
 * ### SignPrompt
 *
 * Asks whether an SSH client may use a key.
 *
 * @param props Request and answer handler
 * @returns The prompt
 */
export function SignPrompt({
  request,
  onAnswer,
}: {
  request: SignRequestView;
  onAnswer: (answer: "session" | "once" | "deny") => void;
}) {
  return (
    <div className="overlay" role="dialog" aria-labelledby="sign-title">
      <div className="card stack">
        <h2 id="sign-title">SSH key request</h2>
        <p>
          ssh or git wants to sign with <strong>{request.title}</strong>.
        </p>
        <p className="small muted mono">{request.fingerprint}</p>
        <div className="row wrap">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => {
              onAnswer("session");
            }}
          >
            Allow until locked
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => {
              onAnswer("once");
            }}
          >
            Allow once
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => {
              onAnswer("deny");
            }}
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  );
}
