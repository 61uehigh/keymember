import { fetchTransport } from "@keymember/client";
import type { Transport } from "@keymember/client";

/**
 * ### transport
 *
 * Transport to the server that served this page. The web app always talks to its own origin.
 */
export const transport: Transport = fetchTransport(location.origin);

export { describeError } from "@keymember/client";
