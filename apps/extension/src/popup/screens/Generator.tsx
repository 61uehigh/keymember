import { useEffect, useState } from "react";

import { call } from "../background.js";
import { copy } from "../copy.js";

/**
 * ### Generator
 *
 * Password generator.
 *
 * @returns The generator view
 */
export function Generator() {
  const [length, setLength] = useState(20);
  const [symbols, setSymbols] = useState(true);
  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    // Moving the slider quickly sends several requests; only the latest settings' answer counts
    let latest = true;

    void call<{ password: string }>({ type: "generate", length, symbols }).then(
      ({ password: generated }) => {
        if (latest) {
          setPassword(generated);
          setCopied(false);
        }
      },
      // Generating runs locally in the background and does not fail; nothing to show
      () => undefined,
    );

    return () => {
      latest = false;
    };
  }, [length, symbols]);

  return (
    <>
      <div className="generated">{password}</div>
      <div className="field">
        <label htmlFor="length">Length {length}</label>
        <input
          id="length"
          type="range"
          min={8}
          max={64}
          value={length}
          onChange={(event) => {
            setLength(Number(event.target.value));
          }}
        />
      </div>
      <label className="row small">
        <input
          type="checkbox"
          style={{ width: "auto", minHeight: 0 }}
          checked={symbols}
          onChange={(event) => {
            setSymbols(event.target.checked);
          }}
        />
        Include symbols
      </label>
      <button
        type="button"
        className="btn btn-primary"
        onClick={() => {
          void copy(password).then(() => {
            setCopied(true);
          });
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </>
  );
}
