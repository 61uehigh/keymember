/**
 * ### FakeFrame
 *
 * A frame of the fake browser: its current URL and what its content script answers to a fill.
 */
export interface FakeFrame {
  url: string;
  received: Array<unknown>;
}

/**
 * ### FakeBrowser
 *
 * Handles for steering the fake `chrome` API from a test.
 */
export interface FakeBrowser {
  /**
   * ### frames
   *
   * Frames keyed by `tabId:frameId`.
   */
  readonly frames: Map<string, FakeFrame>;

  /**
   * ### activeTabs
   *
   * Tabs currently in the foreground.
   */
  readonly activeTabs: Set<number>;

  /**
   * ### session
   *
   * Contents of `chrome.storage.session`; clear it to simulate a browser restart.
   */
  readonly session: Map<string, unknown>;

  /**
   * ### alarms
   *
   * Scheduled alarms by name, with their requested time.
   */
  readonly alarms: Map<string, { when?: number }>;

  /**
   * ### onWindow
   *
   * Called when the background opens a window, with its URL; set it to act as the user.
   */
  onWindow: ((url: string) => void) | undefined;
}

/**
 * ### installChromeMock
 *
 * Installs a minimal in-memory `chrome` global covering what the background controller uses.
 * Content scripts are simulated: a fill "succeeds" by recording the message and reporting the
 * number of values it carried.
 *
 * @returns Handles to steer the fake browser
 */
export function installChromeMock(): FakeBrowser {
  const local = new Map<string, unknown>();
  const session = new Map<string, unknown>();
  const alarms = new Map<string, { when?: number }>();
  const frames = new Map<string, FakeFrame>();
  const activeTabs = new Set<number>();
  const area = (store: Map<string, unknown>) => ({
    get: (key: string | null) =>
      Promise.resolve(
        key === null
          ? Object.fromEntries(
              [...store].map(([name, value]) => [name, structuredClone(value)]),
            )
          : store.has(key)
            ? { [key]: structuredClone(store.get(key)) }
            : {},
      ),
    set: (values: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(values)) {
        store.set(key, structuredClone(value));
      }

      return Promise.resolve();
    },
    remove: (keys: string | Array<string>) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        store.delete(key);
      }

      return Promise.resolve();
    },
    clear: () => {
      store.clear();

      return Promise.resolve();
    },
  });

  const browser: FakeBrowser = {
    frames,
    activeTabs,
    session,
    alarms,
    onWindow: undefined,
  };
  let nextWindowId = 1;

  (globalThis as { chrome?: unknown }).chrome = {
    windows: {
      create: ({ url }: { url: string }) => {
        const id = nextWindowId;

        nextWindowId += 1;
        // Let the broker register its pending request before the "user" answers
        setTimeout(() => browser.onWindow?.(url), 0);

        return Promise.resolve({ id });
      },
      remove: () => Promise.resolve(),
    },
    runtime: {
      id: "test-extension",
      getURL: (path: string) => `chrome-extension://test-extension/${path}`,
    },
    storage: { local: area(local), session: area(session) },
    alarms: {
      create: (name: string, info: { when?: number }) => {
        alarms.set(name, info);

        return Promise.resolve();
      },
      clear: (name: string) => Promise.resolve(alarms.delete(name)),
    },
    webNavigation: {
      getFrame: ({ tabId, frameId }: { tabId: number; frameId: number }) => {
        const frame = frames.get(`${String(tabId)}:${String(frameId)}`);

        return Promise.resolve(
          frame === undefined ? null : { url: frame.url, frameId },
        );
      },
    },
    tabs: {
      get: (tabId: number) =>
        Promise.resolve({ id: tabId, active: activeTabs.has(tabId) }),
      sendMessage: (
        tabId: number,
        message: { username?: string; password?: string; totp?: string },
        options: { frameId: number },
      ) => {
        const frame = frames.get(`${String(tabId)}:${String(options.frameId)}`);

        frame?.received.push(message);

        const filled = [
          message.username,
          message.password,
          message.totp,
        ].filter((value) => value !== undefined).length;

        return Promise.resolve({ filled: frame === undefined ? 0 : filled });
      },
    },
  };

  return browser;
}
