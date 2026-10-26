import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";

import {
  detectImportFormat,
  ImportFormatError,
  parse1Pux,
  parseBitwardenJson,
  parseChromeCsv,
  parseImport,
} from "@keymember/client";

describe("parseChromeCsv", () => {
  it("reads quoted cells, embedded commas, newlines and a BOM", () => {
    const csv =
      "﻿name,url,username,password,note\r\n" +
      'GitHub,https://github.com/login,me@example.com,"p,a""ss",\r\n' +
      ',https://intranet.example.com,admin,secret,"line 1\nline 2"\r\n' +
      ",,,,\r\n";
    const { items, skipped } = parseChromeCsv(csv);

    expect(items).toHaveLength(2);
    expect(items[0]?.details.password).toBe('p,a"ss');
    expect(items[0]?.details.notes).toBeUndefined();
    expect(items[1]?.overview.title).toBe("intranet.example.com");
    expect(items[1]?.details.notes).toBe("line 1\nline 2");
    expect(skipped).toHaveLength(0);
  });

  it("rejects files without the expected columns", () => {
    expect(() => parseChromeCsv("a,b\n1,2")).toThrow(ImportFormatError);
  });
});

describe("parseBitwardenJson", () => {
  it("imports logins and notes, keeps folders and hidden fields, skips cards", () => {
    const json = JSON.stringify({
      encrypted: false,
      folders: [{ id: "f1", name: "인프라" }],
      items: [
        {
          type: 1,
          name: "AWS",
          folderId: "f1",
          notes: null,
          login: {
            username: "root",
            password: "pw",
            totp: "JBSWY3DPEHPK3PXP",
            uris: [{ uri: "https://aws.amazon.com" }],
          },
          fields: [{ name: "PIN", value: "1234", type: 1 }],
          passwordHistory: [
            { password: "old", lastUsedDate: "2026-01-01T00:00:00Z" },
          ],
        },
        { type: 2, name: "Wi-Fi", notes: "guest/welcome" },
        { type: 3, name: "Corporate card" },
      ],
    });
    const { items, skipped } = parseBitwardenJson(json);

    expect(items.map((item) => item.overview.title)).toEqual(["AWS", "Wi-Fi"]);
    expect(items[0]).toMatchObject({
      folder: "인프라",
      overview: { type: "login", urls: ["https://aws.amazon.com"] },
      details: {
        username: "root",
        totp: "JBSWY3DPEHPK3PXP",
        fields: [{ label: "PIN", value: "1234", concealed: true }],
        passwordHistory: [{ password: "old" }],
      },
    });
    expect(items[1]?.overview.type).toBe("secure-note");
    expect(skipped).toEqual(["Corporate card: unsupported item type 3"]);
  });

  it("refuses encrypted exports with an actionable message", () => {
    expect(() =>
      parseBitwardenJson(JSON.stringify({ encrypted: true, items: [] })),
    ).toThrow(/unencrypted/);
  });
});

describe("parse1Pux", () => {
  const archive = (data: unknown): Uint8Array =>
    zipSync({
      "export.attributes": strToU8("{}"),
      "export.data": strToU8(JSON.stringify(data)),
    });

  it("imports logins with TOTP, custom fields and history, keeping the vault name", () => {
    const { items, skipped } = parse1Pux(
      archive({
        accounts: [
          {
            vaults: [
              {
                attrs: { name: "Shared" },
                items: [
                  {
                    categoryUuid: "001",
                    overview: {
                      title: "Slack",
                      urls: [{ url: "https://example.slack.com" }],
                      tags: ["work"],
                    },
                    details: {
                      loginFields: [
                        { designation: "username", value: "me" },
                        { designation: "password", value: "pw" },
                      ],
                      sections: [
                        {
                          fields: [
                            {
                              title: "one-time password",
                              value: { totp: "otpauth://totp/x?secret=ABC" },
                            },
                            {
                              title: "Recovery code",
                              value: { concealed: "R-1" },
                            },
                          ],
                        },
                      ],
                      passwordHistory: [{ value: "old", time: 1_700_000_000 }],
                    },
                  },
                  {
                    categoryUuid: "001",
                    state: "archived",
                    overview: { title: "Old" },
                    details: {},
                  },
                  {
                    categoryUuid: "002",
                    overview: { title: "Card" },
                    details: {},
                  },
                ],
              },
            ],
          },
        ],
      }),
    );

    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      folder: "Shared",
      overview: {
        type: "login",
        title: "Slack",
        urls: ["https://example.slack.com"],
        tags: ["work"],
      },
      details: {
        username: "me",
        password: "pw",
        totp: "otpauth://totp/x?secret=ABC",
        fields: [{ label: "Recovery code", value: "R-1", concealed: true }],
        passwordHistory: [
          { password: "old", replacedAt: "2023-11-14T22:13:20.000Z" },
        ],
      },
    });
    expect(skipped).toEqual([
      "Old: archived",
      "Card: unsupported category 002",
    ]);
  });

  it("rejects files that are not 1PUX archives", () => {
    expect(() => parse1Pux(strToU8("not a zip"))).toThrow(ImportFormatError);
  });
});

describe("format detection", () => {
  it("maps extensions to parsers", () => {
    expect(detectImportFormat("1PasswordExport.1pux")).toBe("1password-1pux");
    expect(detectImportFormat("bitwarden_export.json")).toBe("bitwarden-json");
    expect(detectImportFormat("Chrome Passwords.csv")).toBe("chrome-csv");
    expect(detectImportFormat("notes.txt")).toBeUndefined();
    expect(
      parseImport(
        "chrome-csv",
        strToU8("name,url,username,password\nA,https://a.test,u,p"),
      ).items,
    ).toHaveLength(1);
  });
});
