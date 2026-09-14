import { dom, library } from '@fortawesome/fontawesome-svg-core';
import { faCogs, faKeyboard } from '@fortawesome/free-solid-svg-icons';

import '../assets/scss/styles.scss';

import { disconnect } from './wetty/disconnect';
import { overlay } from './wetty/disconnect/elements';
import { verifyPrompt } from './wetty/disconnect/verify';
import { FileDownloader } from './wetty/download';
import { mobileKeyboard } from './wetty/mobile';
import { TtydSocket } from './wetty/ttydSocket';
import { terminal, Term } from './wetty/term';

// Setup for fontawesome
library.add(faCogs);
library.add(faKeyboard);
dom.watch();

function onResize(term: Term): () => void {
  return function resize() {
    term.resizeTerm();
  };
}

// ttyd's own protocol constants for flow control (see ttyd/html/src/components/app.tsx):
// batch writes in chunks of roughly `limit` characters before deciding whether
// the terminal is falling behind (tracked via xterm's write() callback).
const FLOW_LIMIT = 100000;
const FLOW_HIGH_WATER = 10;
const FLOW_LOW_WATER = 4;

const path = window.location.pathname.replace(/\/+$/, '');
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${wsProtocol}//${window.location.host}${path}/ws${window.location.search}`;
const tokenUrl = `${window.location.protocol}//${window.location.host}${path}/token`;

const socket = new TtydSocket(wsUrl, tokenUrl);

socket.on('connect', () => {
  const term = terminal(socket);
  if (term === undefined) return;

  if (overlay !== null) overlay.style.display = 'none';
  window.addEventListener('beforeunload', verifyPrompt, false);
  window.addEventListener('resize', onResize(term), false);

  term.resizeTerm();
  term.focus();
  mobileKeyboard();
  const fileDownloader = new FileDownloader();

  let written = 0;
  let pending = 0;

  term.onData((data: string) => {
    socket.emit('input', data);
  });
  term.onResize((size: { cols: number; rows: number }) => {
    socket.emit('resize', size);
  });
  socket
    .on('data', (data: string) => {
      const remainingData = fileDownloader.buffer(data);
      if (!remainingData) return;

      written += remainingData.length;
      if (written <= FLOW_LIMIT) {
        term.write(remainingData);
        return;
      }

      written = 0;
      pending += 1;
      term.write(remainingData, () => {
        pending = Math.max(pending - 1, 0);
        if (pending < FLOW_LOW_WATER) socket.emit('resume');
      });
      if (pending > FLOW_HIGH_WATER) socket.emit('pause');
    })
    .on('login', () => {
      term.writeln('');
      term.resizeTerm();
    })
    .on('logout', disconnect)
    .on('disconnect', disconnect)
    .on('error', (err: string | null) => {
      if (err) disconnect(err);
    });
});

void socket.connect();
