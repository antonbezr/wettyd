import { overlay } from './disconnect/elements';
import { verifyPrompt } from './disconnect/verify';
import { resetTitle } from './title';

function showOverlay(text: string): void {
  if (overlay === null) return;
  overlay.style.display = 'block';
  const msg = document.getElementById('msg');
  if (msg !== null) msg.textContent = text;
}

export function disconnect(reason?: string): void {
  window.removeEventListener('beforeunload', verifyPrompt, false);
  resetTitle();
  showOverlay(reason || 'Session ended');
}

// The session is still running server-side, this is just the connection.
export function reconnecting(): void {
  showOverlay('Connection lost, reconnecting…');
}
