const BUTTON_SIZE = 22;
const MENU_WIDTH = 300;
const MENU_HEIGHT = 220;
const VISIBLE_BEFORE_CLICK_MS = 500;

/**
 * ### VisibilityTracking
 *
 * IntersectionObserver v2 options and entries; not in the TypeScript DOM library yet.
 */
interface VisibilityTracking {
  readonly trackVisibility: boolean;
  readonly delay: number;
}

/**
 * ### watchVisibility
 *
 * Tracks whether an element is really visible to the user (not covered, transparent, filtered
 * or transformed by the page) with IntersectionObserver v2, which is how a page that lays a
 * decoy over keymember UI is caught. Browsers without it report the element as visible.
 *
 * @param element Element to watch
 * @param onChange Called with the visibility as it changes
 * @returns A function that stops watching
 */
function watchVisibility(
  element: Element,
  onChange: (visible: boolean) => void,
): () => void {
  if (typeof IntersectionObserver === "undefined") {
    onChange(true);

    return () => undefined;
  }

  const options: IntersectionObserverInit & VisibilityTracking = {
    threshold: [1],
    trackVisibility: true,
    delay: 100,
  };
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      // Intersection Observer v2 adds isVisible in Chrome; the DOM types do not have it yet
      const tracked = entry as IntersectionObserverEntry & {
        isVisible?: boolean;
      };

      // Without v2 support isVisible is absent; fall back to plain intersection
      onChange(tracked.isVisible ?? entry.isIntersecting);
    }
  }, options);

  observer.observe(element);

  return () => {
    observer.disconnect();
  };
}

/**
 * ### keyIcon
 *
 * The key glyph on the inline button.
 *
 * @returns An SVG element
 */
function keyIcon(): SVGSVGElement {
  const svgNs = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNs, "svg");
  const path = document.createElementNS(svgNs, "path");

  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("aria-hidden", "true");
  path.setAttribute("fill", "currentColor");
  path.setAttribute(
    "d",
    "M7 14a5 5 0 1 1 4.58-7H22v4h-2v3h-4v-3h-4.42A5 5 0 0 1 7 14Zm0-3a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z",
  );
  svg.append(path);

  return svg;
}

/**
 * ### pageLooksTampered
 *
 * Refuses to show the inline UI on pages that hide their own content, a trick to make users
 * click on keymember UI they cannot properly see (clickjacking).
 *
 * @returns Whether the page root is transparent or hidden
 */
function pageLooksTampered(): boolean {
  for (const element of [document.documentElement, document.body]) {
    const style = getComputedStyle(element);

    if (
      Number(style.opacity === "" ? "1" : style.opacity) < 0.9 ||
      style.visibility === "hidden"
    ) {
      return true;
    }
  }

  return false;
}

/**
 * ### InlineUi
 *
 * The key button shown inside a focused login field and the menu it opens. Both live in a
 * closed shadow root attached to an element outside the page's own tree, and the menu is an
 * extension-origin iframe, so page scripts can neither read nor restyle what it shows.
 */
export class InlineUi {
  readonly #host: HTMLElement;
  readonly #root: ShadowRoot;
  readonly #button: HTMLButtonElement;
  #frame: HTMLIFrameElement | undefined;
  #field: HTMLInputElement | undefined;
  #buttonVisibleSince: number | undefined;
  #stopFrameWatch: (() => void) | undefined;
  #stopWatching: Array<() => void> = [];
  readonly #onOpen: (field: HTMLInputElement) => Promise<string | undefined>;
  readonly #reposition = (): void => {
    this.#place();
  };

  /**
   * ### constructor
   *
   * Builds the (hidden) UI. Nothing is attached to the page until a field is shown.
   *
   * @param onOpen Called when the user clicks the key button; resolves to a menu token, or
   *   `undefined` when there is nothing to show (locked or no matches)
   */
  constructor(
    onOpen: (field: HTMLInputElement) => Promise<string | undefined>,
  ) {
    this.#onOpen = onOpen;
    this.#host = document.createElement("keymember-inline");
    this.#root = this.#host.attachShadow({ mode: "closed" });
    // Built with DOM calls rather than innerHTML: nothing here is markup from outside
    const style = document.createElement("style");

    style.textContent = `
        :host { all: initial; }
        button {
          position: fixed; z-index: 2147483647; display: grid; place-items: center;
          width: ${String(BUTTON_SIZE)}px; height: ${String(BUTTON_SIZE)}px; padding: 0;
          border: 1px solid #c9c6bf; border-radius: 6px; background: #fff; color: #2f5bea; cursor: pointer;
        }
        iframe {
          position: fixed; z-index: 2147483647; width: ${String(MENU_WIDTH)}px; height: ${String(MENU_HEIGHT)}px;
          border: 1px solid #c9c6bf; border-radius: 10px; background: #fff;
          box-shadow: 0 4px 16px rgb(0 0 0 / 18%); color-scheme: normal;
        }
      `;
    this.#root.append(style);
    this.#button = document.createElement("button");
    this.#button.type = "button";
    this.#button.title = "keymember";
    this.#button.setAttribute("aria-label", "Fill with keymember");
    this.#button.append(keyIcon());
    this.#button.addEventListener("mousedown", (event) => {
      // Keep focus in the field so the page does not treat the click as leaving it
      event.preventDefault();
    });
    this.#button.addEventListener("click", (event) => {
      // Only a real user click opens the menu (page scripts can dispatch synthetic clicks), and
      // only on a button that has been plainly visible for a moment (a covered or faded one, or
      // one that just appeared under the cursor, is how clickjacking works)
      if (
        !event.isTrusted ||
        this.#field === undefined ||
        this.#buttonVisibleSince === undefined ||
        performance.now() - this.#buttonVisibleSince < VISIBLE_BEFORE_CLICK_MS
      ) {
        return;
      }

      void this.#openMenu(this.#field);
    });
    this.#root.append(this.#button);
  }

  /**
   * ### show
   *
   * Shows the key button inside a field.
   *
   * @param field Focused login field
   */
  show(field: HTMLInputElement): void {
    if (pageLooksTampered()) {
      return;
    }

    if (this.#field !== field) {
      this.closeMenu();
    }

    this.#field = field;

    if (!this.#host.isConnected) {
      document.documentElement.append(this.#host);
      this.#buttonVisibleSince = undefined;
      this.#stopWatching.push(
        watchVisibility(this.#button, (visible) => {
          this.#buttonVisibleSince = visible
            ? (this.#buttonVisibleSince ?? performance.now())
            : undefined;
        }),
      );
      window.addEventListener("scroll", this.#reposition, {
        capture: true,
        passive: true,
      });
      window.addEventListener("resize", this.#reposition, { passive: true });
    }

    this.#button.hidden = false;
    this.#place();
  }

  /**
   * ### hide
   *
   * Removes the button and menu from the page.
   */
  hide(): void {
    this.closeMenu();
    this.#field = undefined;
    this.#host.remove();
    this.#buttonVisibleSince = undefined;

    for (const stop of this.#stopWatching.splice(0)) {
      stop();
    }
    window.removeEventListener("scroll", this.#reposition, { capture: true });
    window.removeEventListener("resize", this.#reposition);
  }

  /**
   * ### closeMenu
   *
   * Closes the menu iframe, keeping the button.
   */
  closeMenu(): void {
    this.#stopFrameWatch?.();
    this.#stopFrameWatch = undefined;
    this.#frame?.remove();
    this.#frame = undefined;
  }

  /**
   * ### contains
   *
   * Whether an event target belongs to this UI, so clicks on it do not count as clicking away.
   *
   * @param target Event target
   * @returns Whether the target is the UI host
   */
  contains(target: EventTarget | null): boolean {
    return target === this.#host;
  }

  /**
   * ### #openMenu
   *
   * Asks the background for a menu token and shows the menu below the field.
   *
   * @param field Field the menu fills
   */
  async #openMenu(field: HTMLInputElement): Promise<void> {
    const token = await this.#onOpen(field);

    if (token === undefined || this.#field !== field) {
      return;
    }

    this.closeMenu();

    const frame = document.createElement("iframe");

    // The token rides in the fragment, which is never sent anywhere and is unreadable cross-origin
    frame.src = `${chrome.runtime.getURL("menu.html")}#${token}`;
    frame.setAttribute("allow", "");
    frame.title = "keymember";
    this.#frame = frame;
    this.#root.append(frame);
    this.#place();

    // A menu the page covers or fades out is closed before anyone can click on it unseen
    this.#stopFrameWatch = watchVisibility(frame, (visible) => {
      if (!visible && this.#frame === frame) {
        this.closeMenu();
      }
    });
  }

  /**
   * ### #place
   *
   * Positions the button inside the field's right edge and the menu below the field.
   */
  #place(): void {
    if (this.#field === undefined) {
      return;
    }

    const rect = this.#field.getBoundingClientRect();

    this.#button.style.left = `${String(Math.round(rect.right - BUTTON_SIZE - 6))}px`;
    this.#button.style.top = `${String(Math.round(rect.top + (rect.height - BUTTON_SIZE) / 2))}px`;

    if (this.#frame !== undefined) {
      const below = rect.bottom + 4 + MENU_HEIGHT <= window.innerHeight;

      this.#frame.style.left = `${String(Math.round(Math.min(rect.left, window.innerWidth - MENU_WIDTH - 8)))}px`;
      this.#frame.style.top = `${String(Math.round(below ? rect.bottom + 4 : rect.top - MENU_HEIGHT - 4))}px`;
    }
  }
}
