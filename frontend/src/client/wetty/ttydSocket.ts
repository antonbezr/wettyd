/**
 * Transport layer speaking ttyd's native binary WebSocket protocol
 * (see ttyd/src/protocol.c and ttyd/html/src/components/terminal/xterm/index.ts,
 * both MIT licensed, github.com/tsl0922/ttyd) instead of wetty's original
 * Socket.IO transport. Exposes the same on()/emit() surface wetty's client
 * code (wetty.ts, term.ts) already expects, so the rest of the frontend
 * needed no structural changes.
 */

import { OutputDecoder } from './outputDecoder';

// Byte-code protocol shared by client and server (ttyd/src/server.h)
const enum ServerCmd {
  Output = '0',
  SetWindowTitle = '1',
  SetPreferences = '2',
}
const enum ClientCmd {
  Input = '0',
  ResizeTerminal = '1',
  Pause = '2',
  Resume = '3',
}

export type SocketEventName =
  | 'connect'
  | 'data'
  | 'login'
  | 'logout'
  | 'disconnect'
  | 'error';

type Listener = (...args: never[]) => void;

export interface SocketLike {
  on(event: SocketEventName, cb: Listener): this;
  emit(event: string, payload?: unknown): void;
}

export class TtydSocket implements SocketLike {
  private listeners: Partial<Record<SocketEventName, Listener[]>> = {};

  private ws?: WebSocket;

  private readonly encoder = new TextEncoder();

  // Used only for one-off, always-complete-in-one-message metadata (window
  // title, preferences), decoded without streaming mode.
  private readonly decoder = new TextDecoder();

  // Decodes the continuous PTY output byte stream, see outputDecoder.ts for
  // why this needs to be separate from the metadata decoder above.
  private readonly outputDecoder = new OutputDecoder();

  private token = '';

  private cols = 80;

  private rows = 24;

  private everOpened = false;

  constructor(
    private readonly wsUrl: string,
    private readonly tokenUrl: string,
  ) {}

  on(event: SocketEventName, cb: Listener): this {
    (this.listeners[event] ??= []).push(cb);
    return this;
  }

  private fire(event: SocketEventName, ...args: unknown[]): void {
    for (const cb of this.listeners[event] ?? []) {
      (cb as (...a: unknown[]) => void)(...args);
    }
  }

  async connect(): Promise<void> {
    try {
      const resp = await fetch(this.tokenUrl);
      if (resp.ok) {
        const json = (await resp.json()) as { token?: string };
        this.token = json.token ?? '';
      }
    } catch {
      // No auth endpoint reachable — proceed unauthenticated.
    }

    const ws = new WebSocket(this.wsUrl, ['tty']);
    ws.binaryType = 'arraybuffer';
    ws.addEventListener('open', this.onOpen);
    ws.addEventListener('message', this.onMessage as EventListener);
    ws.addEventListener('close', this.onClose as EventListener);
    ws.addEventListener('error', this.onError);
    this.ws = ws;
  }

  private readonly onOpen = (): void => {
    const msg = JSON.stringify({
      AuthToken: this.token,
      columns: this.cols,
      rows: this.rows,
    });
    this.ws?.send(this.encoder.encode(msg));
    if (this.everOpened) {
      this.fire('login');
    } else {
      this.everOpened = true;
      this.fire('connect');
    }
  };

  private readonly onMessage = (event: MessageEvent<ArrayBuffer>): void => {
    const raw = new Uint8Array(event.data);
    if (raw.length === 0) return;
    const cmd = String.fromCharCode(raw[0]);
    const data = raw.subarray(1);

    switch (cmd) {
      case ServerCmd.Output:
        this.fire('data', this.outputDecoder.decode(data));
        break;
      case ServerCmd.SetWindowTitle:
        document.title = this.decoder.decode(data);
        break;
      case ServerCmd.SetPreferences:
        // wettyd applies terminal preferences client-side (see term/load.ts);
        // server-sent preferences from ttyd's --client-option are ignored.
        break;
      default:
        break;
    }
  };

  private readonly onClose = (event: CloseEvent): void => {
    this.fire(event.code === 1000 ? 'logout' : 'disconnect', event.reason);
  };

  private readonly onError = (): void => {
    this.fire('error', 'WebSocket connection error');
  };

  emit(event: string, payload?: unknown): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;

    switch (event) {
      case 'input': {
        const data = payload as string;
        const bytes = new Uint8Array(data.length * 3 + 1);
        bytes[0] = ClientCmd.Input.charCodeAt(0);
        const stats = this.encoder.encodeInto(data, bytes.subarray(1));
        this.ws.send(bytes.subarray(0, stats.written + 1));
        break;
      }
      case 'resize': {
        const { cols, rows } = payload as { cols: number; rows: number };
        this.cols = cols;
        this.rows = rows;
        this.ws.send(
          this.encoder.encode(
            ClientCmd.ResizeTerminal + JSON.stringify({ columns: cols, rows }),
          ),
        );
        break;
      }
      case 'pause':
        this.ws.send(this.encoder.encode(ClientCmd.Pause));
        break;
      case 'resume':
        this.ws.send(this.encoder.encode(ClientCmd.Resume));
        break;
      default:
        break;
    }
  }
}
