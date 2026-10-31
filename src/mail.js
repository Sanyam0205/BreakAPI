import net from 'node:net';
import tls from 'node:tls';
import { mkdirSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const crlf = (s) => String(s).replace(/\r?\n/g, '\r\n');
const header = (s) => String(s).replace(/[\r\n]+/g, ' ');

function message({ from, to, subject, text }) {
  const id = `${Date.now()}.${randomBytes(6).toString('hex')}@breakapi`;
  return [
    `From: ${header(from)}`,
    `To: ${header(to)}`,
    `Subject: ${header(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${id}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    // Dot-stuffing: a line starting with "." must be doubled inside DATA.
    crlf(text).replace(/^\./gm, '..'),
  ].join('\r\n');
}

/** A small SMTP client: implicit TLS (465), STARTTLS (587) or plain (local relays such as Mailpit). */
async function smtpSend(cfg, { from, to, raw }) {
  let socket = cfg.secure
    ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host })
    : net.connect({ host: cfg.host, port: cfg.port });
  socket.setTimeout(20000, () => socket.destroy(new Error('SMTP timeout')));
  let buffer = '';
  let waiting = null;
  const attach = (s) => s.on('data', (d) => {
    buffer += d.toString('utf8');
    // A complete reply ends with a line "NNN text" (a space, not a dash, after the code).
    const lines = buffer.split('\r\n');
    const last = lines.filter(Boolean).pop() || '';
    if (/^\d{3} /.test(last) && buffer.endsWith('\r\n') && waiting) {
      const reply = buffer;
      buffer = '';
      const w = waiting;
      waiting = null;
      w(reply);
    }
  });
  attach(socket);
  const read = () => new Promise((resolve, reject) => {
    waiting = resolve;
    socket.once('error', reject);
  });
  const expect = async (code) => {
    const reply = await read();
    if (!reply.startsWith(String(code))) throw new Error(`SMTP: expected ${code}, got ${reply.trim().slice(0, 200)}`);
    return reply;
  };
  const cmd = async (line, code) => {
    socket.write(`${line}\r\n`);
    return expect(code);
  };

  await (cfg.secure ? new Promise((r, j) => { socket.once('secureConnect', r); socket.once('error', j); }) : new Promise((r, j) => { socket.once('connect', r); socket.once('error', j); }));
  await expect(220);
  let ehlo = await cmd('EHLO breakapi', 250);
  if (!cfg.secure && cfg.startTls) {
    if (!/STARTTLS/i.test(ehlo)) throw new Error('SMTP server does not offer STARTTLS');
    await cmd('STARTTLS', 220);
    socket.removeAllListeners('data');
    socket = tls.connect({ socket, servername: cfg.host });
    await new Promise((r, j) => { socket.once('secureConnect', r); socket.once('error', j); });
    attach(socket);
    ehlo = await cmd('EHLO breakapi', 250);
  }
  if (cfg.user) {
    if (!cfg.secure && !cfg.startTls && !['localhost', '127.0.0.1'].includes(cfg.host)) throw new Error('Refusing to send SMTP credentials without TLS');
    await cmd(`AUTH PLAIN ${Buffer.from(`\0${cfg.user}\0${cfg.pass}`).toString('base64')}`, 235);
  }
  const addr = (s) => (String(s).match(/<([^>]+)>/) || [null, s])[1].trim();
  await cmd(`MAIL FROM:<${addr(from)}>`, 250);
  await cmd(`RCPT TO:<${addr(to)}>`, 250);
  await cmd('DATA', 354);
  await cmd(`${raw}\r\n.`, 250);
  socket.write('QUIT\r\n');
  socket.end();
}

/**
 * Outbound email. In "outbox" mode (development and tests) messages are written to
 * <dataDir>/outbox/*.eml and logged, never delivered. In "smtp" mode they are sent.
 */
export function createMailer(config, { log = console } = {}) {
  const outbox = join(config.dataDir, 'outbox');
  return {
    mode: config.mail.mode,
    async send({ to, subject, text }) {
      const raw = message({ from: config.mail.from, to, subject, text });
      if (config.mail.mode === 'smtp') {
        await smtpSend(config.mail, { from: config.mail.from, to, raw });
        return { delivered: true };
      }
      mkdirSync(outbox, { recursive: true, mode: 0o700 });
      const file = join(outbox, `${Date.now()}-${randomBytes(3).toString('hex')}.eml`);
      writeFileSync(file, raw, { mode: 0o600 });
      log.info?.(`[mail:outbox] to=${to} subject="${subject}" file=${file}`);
      return { delivered: false, file };
    },
    /** Development/test helper: messages in the outbox, newest last. */
    readOutbox() {
      try {
        return readdirSync(outbox).sort().map((f) => readFileSync(join(outbox, f), 'utf8'));
      } catch {
        return [];
      }
    },
  };
}
