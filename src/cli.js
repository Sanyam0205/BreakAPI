// Operator commands. Stop the server first: the CLI edits the same data file.
//   node src/cli.js create-admin --email a@b.co --name "Dana Ruiz"   (password from BREAKAPI_ADMIN_PASSWORD or prompt)
//   node src/cli.js reset-password --email a@b.co                    (password from BREAKAPI_ADMIN_PASSWORD or prompt)
//   node src/cli.js list-users
//   node src/cli.js gen-key                                          (prints a value for BREAKAPI_SECRET_KEY)
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';
import { loadConfig } from './config.js';
import { Store } from './store.js';
import { hashPassword, passwordProblem, normalizeEmail, validEmail } from './auth.js';
import { newId, nowIso } from './util.js';

const [cmd, ...rest] = process.argv.slice(2);
const arg = (name) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : undefined;
};

async function askPassword() {
  if (process.env.BREAKAPI_ADMIN_PASSWORD) return process.env.BREAKAPI_ADMIN_PASSWORD;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const pw = await new Promise((r) => rl.question('New password (12+ characters): ', r));
  rl.close();
  return pw;
}

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const config = loadConfig();

if (cmd === 'gen-key') {
  console.log(randomBytes(32).toString('base64'));
  process.exit(0);
}

const store = new Store(config.dataDir);
store.data.users ??= {};
const users = Object.values(store.data.users);

if (cmd === 'list-users') {
  for (const u of users) console.log(`${u.role.padEnd(5)} ${u.email}${u.disabledAt ? ' (disabled)' : ''}${u.emailVerifiedAt ? '' : ' (unverified)'}`);
  process.exit(0);
}

if (cmd === 'create-admin' || cmd === 'reset-password') {
  const email = normalizeEmail(arg('email'));
  if (!validEmail(email)) fail('Pass --email with a valid address.');
  const password = await askPassword();
  const why = passwordProblem(password, email);
  if (why) fail(why);
  let u = users.find((x) => x.email === email);
  if (cmd === 'create-admin') {
    if (u) {
      u.role = 'admin';
      u.disabledAt = null;
    } else {
      u = { id: newId('usr'), email, name: arg('name') || email.split('@')[0], role: 'admin', createdAt: nowIso() };
      store.data.users[u.id] = u;
    }
    u.emailVerifiedAt ??= nowIso();
  } else if (!u) {
    fail(`No user ${email}.`);
  }
  u.passwordHash = hashPassword(password);
  // Sign the account out everywhere.
  for (const [h, s] of Object.entries(store.data.sessions || {})) if (s.userId === u.id) delete store.data.sessions[h];
  store.data.systemAudit ??= [];
  store.data.systemAudit.push({ at: nowIso(), event: `cli.${cmd}`, userId: u.id });
  store.saveNow();
  console.log(`${cmd === 'create-admin' ? 'Administrator ready' : 'Password reset'}: ${email}`);
  process.exit(0);
}

fail('Usage: node src/cli.js <create-admin|reset-password|list-users|gen-key> [--email x] [--name y]');
