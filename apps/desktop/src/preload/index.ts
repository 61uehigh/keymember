import { contextBridge, ipcRenderer } from "electron";

import {
  IPC_CHANNEL,
  SIGN_ANSWER_CHANNEL,
  SIGN_REQUEST_CHANNEL,
  STATE_CHANGED_CHANNEL,
} from "../shared/channels.js";
import type { KeymemberBridge, SignRequestView } from "../shared/ipc.js";

/**
 * Exposes a narrow API to the sandboxed window: one validated request channel and the SSH
 * signature prompt. The window never gets Node or Electron objects.
 */
const bridge: KeymemberBridge = {
  request: (request) => ipcRenderer.invoke(IPC_CHANNEL, request),
  onSignRequest: (listener) => {
    ipcRenderer.on(SIGN_REQUEST_CHANNEL, (_event, request: SignRequestView) => {
      listener(request);
    });
  },
  answerSignRequest: (id, answer) => {
    ipcRenderer.send(SIGN_ANSWER_CHANNEL, { id, answer });
  },
  onStateChanged: (listener) => {
    ipcRenderer.on(STATE_CHANGED_CHANNEL, () => {
      listener();
    });
  },
};

contextBridge.exposeInMainWorld("keymember", bridge);
