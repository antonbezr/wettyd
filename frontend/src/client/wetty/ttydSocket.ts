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
  SetSession = '3',
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
  | 'reconnecting'
  | 'reset'
  | 'error';

// Close codes after which reconnecting can't help: the command exited (the
// server closes normally whatever its exit code), auth was refused, or
// another tab resumed this session (src/server.h's CLOSE_SESSION_TAKEN_OVER).
// Anything else, 1006 above all, is a dropped connection, and the server
// keeps the session running for this client to come back to.
const CLOSE_NORMAL = 1000;
const CLOSE_POLICY_VIOLATION = 1008;
const CLOSE_SESSION_TAKEN_OVER = 4000;

export function shouldReconnect(code: number): boolean {
  return (
    code !== CLOSE_NORMAL &&
    code !== CLOSE_POLICY_VIOLATION &&
    code !== CLOSE_SESSION_TAKEN_OVER
  );
}

const RECONNECT_DELAYS_MS = [500, 1000, 2000, 4000, 8000];
const RECONNECT_MAX_DELAY_MS = 10000;

export function reconnectDelay(attempt: number): number {
  return RECONNECT_DELAYS_MS[attempt] ?? RECONNECT_MAX_DELAY_MS;
}

const SESSION_STORAGE_KEY = 'wettyd-session';

function storedSessionId(): string {
  try {
    return sessionStorage.getItem(SESSION_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

function storeSessionId(id: string): void {
  try {
    sessionStorage.setItem(SESSION_STORAGE_KEY, id);
  } catch {
    // Storage unavailable, a reload just starts a new session.
  }
}

/**
 * Holds a Web Lock named after the session for as long as this page lives,
 * resolving to whether it got it. A duplicated tab inherits the original's
 * sessionStorage, session id included, and would otherwise take the session
 * over from the original; the original holding this lock stops that. A
 * reload releases the lock as the old page unloads, so waiting briefly for
 * it lets the reloaded page claim it straight back.
 */
function claimSession(id: string): Promise<boolean> {
  // Only exposed in secure contexts, without it there's no telling a
  // duplicated tab apart, so resume regardless.
  if (!('locks' in navigator)) return Promise.resolve(true);
  return new Promise((resolve) => {
    navigator.locks
      .request(
        `wettyd-session-${id}`,
        { signal: AbortSignal.timeout(500) },
        () => {
          resolve(true);
          return new Promise<never>(() => {});
        },
      )
      .catch(() => resolve(false));
  });
}

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
  private outputDecoder = new OutputDecoder();

  private token = '';

  private cols = 80;

  private rows = 24;

  private everOpened = false;

  // The server-side session this page is attached to, and how many bytes of
  // its output have arrived, sent back on reconnect to resume it without
  // replaying what this page already shows.
  private sessionId = '';

  private received = 0;

  private reconnectAttempt = 0;

  private reconnectTimer?: ReturnType<typeof setTimeout>;

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
    const id = storedSessionId();
    if (id && (await claimSession(id))) this.sessionId = id;
    window.addEventListener('online', this.reconnectNow);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') this.reconnectNow();
    });
    await this.open();
  }

  private async open(): Promise<void> {
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
      SessionId: this.sessionId,
      Offset: this.received,
    });
    this.ws?.send(this.encoder.encode(msg));
    this.reconnectAttempt = 0;
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
        this.received += data.length;
        this.fire('data', this.outputDecoder.decode(data));
        break;
      case ServerCmd.SetSession:
        this.onSession(
          JSON.parse(this.decoder.decode(data)) as {
            id: string;
            offset: number;
          },
        );
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

  // Sent before any output, says where in the session's output stream what
  // follows starts. Anything other than exactly where this page left off
  // (a new session, or a replay of one this page has a gap in) means the
  // terminal has to start over from what's about to arrive.
  private onSession({ id, offset }: { id: string; offset: number }): void {
    const replaced = this.sessionId !== '' && id !== this.sessionId;
    if (replaced || offset !== this.received) {
      this.outputDecoder = new OutputDecoder();
      this.fire('reset', replaced);
    }
    this.received = offset;
    if (id !== this.sessionId) {
      this.sessionId = id;
      storeSessionId(id);
      void claimSession(id);
    }
  }

  private readonly onClose = (event: CloseEvent): void => {
    if (event.target !== this.ws) return;
    this.ws = undefined;
    if (event.code === CLOSE_NORMAL) {
      this.fire('logout', event.reason);
    } else if (event.code === CLOSE_SESSION_TAKEN_OVER) {
      this.fire('disconnect', 'Session resumed in another tab');
    } else if (!shouldReconnect(event.code) || !this.everOpened) {
      this.fire('disconnect', event.reason);
    } else {
      this.fire('reconnecting');
      this.reconnectTimer = setTimeout(
        this.reconnectNow,
        reconnectDelay(this.reconnectAttempt),
      );
      this.reconnectAttempt += 1;
    }
  };

  // The connection is likely back (the network returned, or the tab came to
  // the foreground), so skip whatever's left of the backoff.
  private readonly reconnectNow = (): void => {
    if (this.reconnectTimer === undefined) return;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    void this.open();
  };

  // A failed connection is always followed by a close event, which decides
  // whether to reconnect, see onClose.
  private readonly onError = (): void => {};

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
