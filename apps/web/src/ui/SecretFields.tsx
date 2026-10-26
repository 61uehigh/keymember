import { parseTotp, totpCode } from "@keymember/client";
import { useEffect, useMemo, useState } from "react";

import { copySecret } from "../lib/clipboard.js";
import { useToast } from "./primitives.js";

/**
 * ### SecretValue
 *
 * One row of an item: a label, a value that can be masked, and a copy button.
 *
 * @param props Row label, value and whether it is secret
 * @returns The row
 */
export function SecretValue({
  label,
  value,
  secret,
}: {
  label: string;
  value: string;
  secret: boolean;
}) {
  const [revealed, setRevealed] = useState(!secret);
  const toast = useToast();

  return (
    <div className="kv">
      <dt>{label}</dt>
      <dd className={secret ? "mono" : undefined}>
        {revealed ? value : "••••••••••"}
      </dd>
      <div className="row">
        {secret ? (
          <button
            type="button"
            className="btn btn-ghost btn-small"
            aria-label={`${label} ${revealed ? "Hide" : "Show"}`}
            onClick={() => {
              setRevealed(!revealed);
            }}
          >
            {revealed ? "Hide" : "Show"}
          </button>
        ) : null}
        <button
          type="button"
          className="btn btn-small"
          aria-label={`Copy ${label}`}
          onClick={() => {
            void copySecret(value).then(
              () => {
                toast(
                  `Copied ${label}. The clipboard will be cleared in 30 seconds.`,
                );
              },
              () => {
                toast("Couldn't copy to the clipboard.");
              },
            );
          }}
        >
          Copy
        </button>
      </div>
    </div>
  );
}

/**
 * ### TotpValue
 *
 * Live TOTP code with its remaining seconds.
 *
 * @param props TOTP field value
 * @returns The row, or a note when the value cannot generate codes
 */
export function TotpValue({ value }: { value: string }) {
  const parameters = useMemo(() => parseTotp(value), [value]);
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(new Date());
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, []);

  if (parameters === undefined) {
    return <SecretValue label="TOTP seed" value={value} secret />;
  }

  const { code, secondsLeft } = totpCode(parameters, now);

  return (
    <div className="kv">
      <dt>Two-factor code</dt>
      <dd className="mono" style={{ fontVariantNumeric: "tabular-nums" }}>
        {code.slice(0, 3)} {code.slice(3)}{" "}
        <span className="small muted">({secondsLeft}s)</span>
      </dd>
      <SecretCopy value={code} label="two-factor code" />
    </div>
  );
}

/**
 * ### SecretCopy
 *
 * Copy button for a value shown elsewhere in the row.
 *
 * @param props Value and its label
 * @returns The button
 */
export function SecretCopy({ value, label }: { value: string; label: string }) {
  const toast = useToast();

  return (
    <button
      type="button"
      className="btn btn-small"
      aria-label={`Copy ${label}`}
      onClick={() => {
        void copySecret(value).then(
          () => {
            toast(`Copied ${label}.`);
          },
          () => {
            toast("Couldn't copy to the clipboard.");
          },
        );
      }}
    >
      Copy
    </button>
  );
}
