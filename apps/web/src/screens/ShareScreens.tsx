import {
  ApiError,
  openShareLink,
  parseShareLink,
  shareLinkUrl,
} from "@keymember/client";
import type {
  ItemSummary,
  SharedSnapshot,
  ShareField,
  ShareLinkControl,
  ShareLinkSummary,
} from "@keymember/client";
import { useEffect, useState } from "react";

import { transport } from "../lib/api.js";
import { copySecret } from "../lib/clipboard.js";
import { clearSensitiveParams } from "../lib/router.js";
import {
  Dialog,
  ErrorText,
  Field,
  useAction,
  useToast,
} from "../ui/primitives.js";
import { SecretValue, TotpValue } from "../ui/SecretFields.js";
import { AuthCard } from "./auth/AuthCard.js";

const HOUR = 60 * 60 * 1000;

const LIFETIMES: ReadonlyArray<{ label: string; ms: number }> = [
  { label: "1 hour", ms: HOUR },
  { label: "1 day", ms: 24 * HOUR },
  { label: "7 days", ms: 7 * 24 * HOUR },
  { label: "30 days", ms: 30 * 24 * HOUR },
];

const VIEW_LIMITS: ReadonlyArray<number> = [1, 3, 10];

const FIELD_LABELS: Readonly<Record<ShareField, string>> = {
  username: "Username",
  password: "Password",
  totp: "Two-factor authentication (TOTP)",
  notes: "Notes",
};

const STATUS_LABELS: Readonly<Record<ShareLinkSummary["status"], string>> = {
  active: "Open",
  expired: "Expired",
  used_up: "Used up",
  revoked: "Revoked",
};

/**
 * ### ShareLinkDialog
 *
 * Makes a share link for one item and lists the links already made for it. The link is shown
 * once; keymember cannot show it again, because the server never had its secret.
 *
 * @param props Session, item and close handler
 * @returns The dialog
 */
export function ShareLinkDialog({
  session,
  item,
  onClose,
}: {
  session: ShareLinkControl;
  item: ItemSummary;
  onClose: () => void;
}) {
  const { details } = session.getItem(item.id);
  // FIELD_LABELS is a Record keyed by exactly the share fields
  const available = (Object.keys(FIELD_LABELS) as Array<ShareField>).filter(
    (field) => details[field] !== undefined && details[field] !== "",
  );
  const [fields, setFields] = useState<ReadonlySet<ShareField>>(
    new Set(
      available.filter((field) => field === "username" || field === "password"),
    ),
  );
  const [lifetime, setLifetime] = useState(24 * HOUR);
  const [maxViews, setMaxViews] = useState(1);
  const [passphrase, setPassphrase] = useState("");
  const [created, setCreated] = useState<
    { url: string; passphrase: boolean } | undefined
  >(undefined);
  const [links, setLinks] = useState<Array<ShareLinkSummary>>([]);
  const action = useAction();
  const toast = useToast();
  const { run } = action;

  const refresh = async (): Promise<void> => {
    setLinks(await session.shareLinks({ itemId: item.id }));
  };

  useEffect(() => {
    void run(refresh);
    // refresh closes over stable props; re-running on its identity would refetch every render
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Dialog title={`Share link for "${item.overview.title}"`} onClose={onClose}>
      {created === undefined ? (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void action.run(async () => {
              const link = await session.createShareLink(item.id, {
                fields: [...fields],
                expiresInMs: lifetime,
                maxViews,
                passphrase,
              });

              setCreated({
                url: shareLinkUrl(location.origin, link),
                passphrase: link.needsPassphrase,
              });
              setPassphrase("");
              await refresh();
            });
          }}
        >
          <p className="hint">
            Sends this item as it is right now to someone outside the vault.
            They can open it without an account, and only the key inside the
            link can decrypt it. Later edits to the item won't show up in the
            link.
          </p>
          <fieldset
            className="stack"
            style={{ border: 0, padding: 0, margin: 0 }}
          >
            <legend className="small muted">
              Fields to include (title and websites are always included)
            </legend>
            <div className="row wrap">
              {available.map((field) => (
                <label key={field} className="row small">
                  <input
                    type="checkbox"
                    checked={fields.has(field)}
                    onChange={(event) => {
                      const next = new Set(fields);

                      if (event.target.checked) {
                        next.add(field);
                      } else {
                        next.delete(field);
                      }

                      setFields(next);
                    }}
                  />
                  {FIELD_LABELS[field]}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="row wrap">
            <label className="field" style={{ flex: "1 1 140px" }}>
              <span>Expires after</span>
              <select
                className="input"
                value={lifetime}
                onChange={(event) => {
                  setLifetime(Number(event.target.value));
                }}
              >
                {LIFETIMES.map((entry) => (
                  <option key={entry.ms} value={entry.ms}>
                    {entry.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="field" style={{ flex: "1 1 140px" }}>
              <span>Max views</span>
              <select
                className="input"
                value={maxViews}
                onChange={(event) => {
                  setMaxViews(Number(event.target.value));
                }}
              >
                {VIEW_LIMITS.map((views) => (
                  <option key={views} value={views}>
                    {views === 1 ? "1 view" : `${String(views)} views`}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Field
            label="Access password (optional)"
            type="text"
            autoComplete="off"
            value={passphrase}
            onChange={(event) => {
              setPassphrase(event.target.value);
            }}
            hint="If you set one, send it separately from the link (by phone or text message). The link closes after 10 wrong attempts."
          />
          <ErrorText message={action.error} />
          <div className="dialog-actions">
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={action.busy}
            >
              Create link
            </button>
          </div>
        </form>
      ) : (
        <div className="stack">
          <div className="notice stack">
            <p>
              Link created. Copy it now: you can't see it again after you close
              this screen.
              {created.passphrase
                ? " Send the access password separately, through a different channel."
                : ""}
            </p>
            <code style={{ wordBreak: "break-all" }}>{created.url}</code>
            <div>
              <button
                type="button"
                className="btn btn-primary btn-small"
                onClick={() => {
                  void copySecret(created.url).then(() => {
                    toast("Copied the link.");
                  });
                }}
              >
                Copy link
              </button>
            </div>
          </div>
          <div className="dialog-actions">
            <button
              type="button"
              className="btn"
              onClick={() => {
                setCreated(undefined);
              }}
            >
              Create another link
            </button>
            <button type="button" className="btn btn-primary" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      )}
      {links.length === 0 ? null : (
        <div className="stack">
          <h3>Sent links</h3>
          <ul
            className="stack"
            style={{ margin: 0, padding: 0, listStyle: "none" }}
          >
            {links.map((link) => (
              <li key={link.id} className="row spread wrap small">
                <span>
                  <span className="badge">{STATUS_LABELS[link.status]}</span>{" "}
                  {String(link.views)}/{String(link.maxViews)} views · expires{" "}
                  {new Date(link.expiresAt).toLocaleString(undefined)}
                  {link.passphrase ? " · password" : ""}
                </span>
                {link.status === "active" ? (
                  <button
                    type="button"
                    className="btn btn-danger btn-small"
                    disabled={action.busy}
                    onClick={() => {
                      void action.run(async () => {
                        await session.revokeShareLink(link.id);
                        await refresh();
                      });
                    }}
                  >
                    Revoke
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Dialog>
  );
}

/**
 * ### SharedItemScreen
 *
 * What a link's recipient sees, with or without an account. Opening counts a view, so the
 * page waits for a click instead of opening on load.
 *
 * @param props Route path and parameters of the link
 * @returns The screen
 */
export function SharedItemScreen({
  path,
  query,
}: {
  path: string;
  query: string;
}) {
  // Read once, then dropped from the address bar so the secret does not stay in history
  const [link] = useState(() =>
    parseShareLink(`${path.replace(/^\//, "")}?${query}`),
  );

  useEffect(() => {
    if (link !== undefined) {
      clearSensitiveParams(`/share/${link.shareId}`);
    }
  }, [link]);
  const [passphrase, setPassphrase] = useState("");
  const [opened, setOpened] = useState<
    | { snapshot: SharedSnapshot; expiresAt: string; viewsLeft: number }
    | undefined
  >(undefined);
  const action = useAction();

  if (link === undefined) {
    return (
      <AuthCard title="Invalid link">
        <p>The link is cut off or malformed. Ask the sender for it again.</p>
      </AuthCard>
    );
  }

  if (opened !== undefined) {
    const { snapshot } = opened;

    return (
      <AuthCard title={snapshot.title}>
        <p className="small muted">
          {snapshot.sharedBy} sent you this item with keymember.{" "}
          {opened.viewsLeft > 0
            ? `It can be opened ${String(opened.viewsLeft)} more ${opened.viewsLeft === 1 ? "time" : "times"}, until ${new Date(opened.expiresAt).toLocaleString(undefined)}.`
            : "This link is now closed. Copy anything you need now."}
        </p>
        <dl style={{ margin: 0 }}>
          {snapshot.urls.map((url) => (
            <div className="kv" key={url}>
              <dt>Website</dt>
              <dd>{url}</dd>
              <span />
            </div>
          ))}
          {snapshot.username === undefined ? null : (
            <SecretValue
              label="Username"
              value={snapshot.username}
              secret={false}
            />
          )}
          {snapshot.password === undefined ? null : (
            <SecretValue label="Password" value={snapshot.password} secret />
          )}
          {snapshot.totp === undefined ? null : (
            <TotpValue value={snapshot.totp} />
          )}
        </dl>
        {snapshot.notes === undefined ? null : (
          <div className="stack">
            <h3>Notes</h3>
            <p style={{ whiteSpace: "pre-wrap" }}>{snapshot.notes}</p>
          </div>
        )}
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Shared item">
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            try {
              setOpened(
                await openShareLink(
                  transport,
                  link,
                  link.needsPassphrase ? passphrase : undefined,
                ),
              );
            } catch (error) {
              if (
                error instanceof ApiError &&
                error.code === "share_unavailable"
              ) {
                throw new Error(
                  "This link has expired, used up its views, or been closed by the sender.",
                  { cause: error },
                );
              }

              if (error instanceof ApiError && error.code === "share_denied") {
                throw new Error(
                  link.needsPassphrase
                    ? "Incorrect access password."
                    : "The link is damaged. Ask the sender for it again.",
                  { cause: error },
                );
              }

              throw error;
            }
          });
        }}
      >
        <p>
          Someone sent you a password with keymember. Opening it uses up one of
          its views.
        </p>
        {link.needsPassphrase ? (
          <Field
            label="Access password"
            type="password"
            required
            autoFocus
            autoComplete="off"
            value={passphrase}
            onChange={(event) => {
              setPassphrase(event.target.value);
            }}
            hint="The password the sender gave you separately."
          />
        ) : null}
        <ErrorText message={action.error} />
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy}
        >
          {action.busy ? "Opening…" : "View contents"}
        </button>
      </form>
    </AuthCard>
  );
}
