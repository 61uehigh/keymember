import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import type { InputHTMLAttributes, ReactNode } from "react";

import { describeError } from "../lib/api.js";

/**
 * ### FieldProps
 *
 * Props of {@link Field}: a labelled input plus optional hint and error.
 */
export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  /**
   * ### label
   *
   * Visible label, also the input's accessible name.
   */
  readonly label: string;

  /**
   * ### hint
   *
   * Help text under the input.
   */
  readonly hint?: ReactNode;
}

/**
 * ### Field
 *
 * A labelled text input. The label is linked to the input so screen readers announce it.
 *
 * @param props Label, hint and native input attributes
 * @returns The field element
 */
export function Field({ label, hint, id, ...input }: FieldProps) {
  const generated = useId();
  const inputId = id ?? generated;
  const hintId = `${inputId}-hint`;

  return (
    <div className="field">
      <label htmlFor={inputId}>{label}</label>
      <input
        id={inputId}
        className="input"
        {...(hint === undefined ? {} : { "aria-describedby": hintId })}
        {...input}
      />
      {hint === undefined ? null : (
        <span id={hintId} className="hint">
          {hint}
        </span>
      )}
    </div>
  );
}

/**
 * ### DialogProps
 *
 * Props of {@link Dialog}.
 */
export interface DialogProps {
  /**
   * ### title
   *
   * Heading, also the dialog's accessible name.
   */
  readonly title: string;

  /**
   * ### onClose
   *
   * Called when the user dismisses the dialog (Escape or a close button).
   */
  readonly onClose: () => void;

  /**
   * ### children
   *
   * Dialog content.
   */
  readonly children: ReactNode;
}

/**
 * ### Dialog
 *
 * A modal dialog on the native `<dialog>` element, which traps focus and handles Escape.
 * Mount it to open it; unmount it to close it.
 *
 * @param props Title, close handler and content
 * @returns The dialog element
 */
export function Dialog({ title, onClose, children }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dialog = ref.current;

    dialog?.showModal();

    return () => {
      dialog?.close();
    };
  }, []);

  return (
    <dialog
      ref={ref}
      className="dialog"
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="dialog-body">
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </dialog>
  );
}

const ToastContext = createContext<(message: string) => void>(() => undefined);

/**
 * ### ToastProvider
 *
 * Shows short status messages in a polite live region.
 *
 * @param props Children to render inside the provider
 * @returns The provider element
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<string | undefined>(undefined);
  const timer = useRef<number | undefined>(undefined);
  const show = useCallback((next: string) => {
    window.clearTimeout(timer.current);
    setMessage(next);
    timer.current = window.setTimeout(() => {
      setMessage(undefined);
    }, 3000);
  }, []);

  return (
    <ToastContext value={show}>
      {children}
      <div role="status" aria-live="polite">
        {message === undefined ? null : <div className="toast">{message}</div>}
      </div>
    </ToastContext>
  );
}

/**
 * ### useToast
 *
 * Returns the function that shows a toast.
 *
 * @returns Toast trigger
 */
export function useToast(): (message: string) => void {
  return useContext(ToastContext);
}

/**
 * ### useAction
 *
 * Runs async work with a busy flag and a user-facing error, for buttons and forms.
 * Concurrent runs are ignored while one is in flight.
 *
 * @returns The busy flag, the last error message, and a runner
 */
export function useAction(): {
  busy: boolean;
  error: string | undefined;
  run: (work: () => Promise<void>) => Promise<void>;
  clearError: () => void;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>(undefined);
  const inFlight = useRef(false);

  const run = useCallback(async (work: () => Promise<void>) => {
    if (inFlight.current) {
      return;
    }

    inFlight.current = true;
    setBusy(true);
    setError(undefined);

    try {
      await work();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }, []);

  return {
    busy,
    error,
    run,
    clearError: () => {
      setError(undefined);
    },
  };
}

/**
 * ### ErrorText
 *
 * Renders an error message in an assertive live region, or nothing.
 *
 * @param props The message
 * @returns The error element
 */
export function ErrorText({ message }: { message: string | undefined }) {
  return (
    <p className="error" role="alert">
      {message ?? ""}
    </p>
  );
}

/**
 * ### downloadBytes
 *
 * Offers bytes to the user as a file download.
 *
 * @param bytes File contents
 * @param fileName Suggested file name
 * @param type MIME type
 */
export function downloadBytes(
  bytes: Uint8Array,
  fileName: string,
  type: string,
): void {
  const url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type }));
  const link = document.createElement("a");

  link.href = url;
  link.download = fileName;
  link.click();

  // Revoke after the click has been processed so the download is not cut off
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 1000);
}
