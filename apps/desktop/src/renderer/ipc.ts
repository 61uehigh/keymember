import type { DesktopRequest, KeymemberBridge } from "../shared/ipc.js";

declare global {
  interface Window {
    readonly keymember: KeymemberBridge;
  }
}

/**
 * ### call
 *
 * Sends a request to the main process.
 *
 * @param request Request
 * @returns The main process's answer
 */
export async function call<T>(request: DesktopRequest): Promise<T> {
  // The main process answers each request type with the type documented on its handler
  return (await window.keymember.request(request)) as T;
}
