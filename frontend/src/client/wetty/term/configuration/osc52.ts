import { ClipboardAddon } from '@xterm/addon-clipboard';

import {
  decodeBase64Utf8,
  parseTmuxOsc52Passthrough,
  WriteOnlyClipboardProvider,
} from './osc52Clipboard';
import type { Term } from '../../term';

function installTmuxPassthrough(term: Term): void {
  term.parser.registerDcsHandler({ final: 't' }, (data) => {
    const payload = parseTmuxOsc52Passthrough(data);
    if (payload === null) return true;

    try {
      void navigator.clipboard.writeText(decodeBase64Utf8(payload));
    } catch {
      // Malformed base64 from a misbehaving remote program, ignore it.
    }
    return true;
  });
}

/**
 * OSC 52 lets a program running in the shell, tmux/vim yank included, ask
 * the terminal to write to the system clipboard. See osc52Clipboard.ts for
 * the security-relevant read-disabling policy and the tmux DCS passthrough
 * handling this also wires up.
 */
export function installOsc52Clipboard(term: Term): void {
  term.loadAddon(new ClipboardAddon(undefined, new WriteOnlyClipboardProvider()));
  installTmuxPassthrough(term);
}
