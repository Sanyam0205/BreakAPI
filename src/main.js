import { loadConfig, configProblems, publicConfig } from './config.js';
import { createApp, VERSION } from './server.js';

const config = loadConfig();
const problems = configProblems(config);
if (problems.length) {
  console.error('breakAPI will not start with this configuration:');
  for (const p of problems) console.error(`  - ${p}`);
  console.error('See DEPLOY.md for the required settings.');
  process.exit(1);
}

const log = {
  info: (m) => console.log(m),
  error: (m) => console.error(m instanceof Error ? m.stack : m),
};
const app = createApp({ config, log });
// An embedded simulation takes a moment to load. A failure is logged and only turns the playground off.
const simUp = await app.ready;

app.server.listen(config.port, config.host, () => {
  const shown = ['0.0.0.0', '::'].includes(config.host) ? 'localhost' : config.host;
  const url = config.publicUrl || `http://${shown}:${config.port}`;
  console.log(`breakAPI ${VERSION} (${config.env}) listening on ${config.host}:${config.port} — ${url}`);
  console.log(`Settings: ${JSON.stringify(publicConfig(config))}`);
  const setup = app.setupToken();
  if (setup) {
    console.log('');
    console.log('No accounts exist yet. Create the first administrator at:');
    console.log(`  ${url}/#/login/admin`);
    console.log(`  setup token: ${setup}   (also saved in ${config.dataDir}/setup-token)`);
    console.log('');
  }
  if (!config.production && config.mail.mode === 'outbox') {
    console.log(`Email is not configured: messages are written to ${config.dataDir}/outbox and printed here instead of being sent.`);
  }
  if (!config.production && config.host !== '127.0.0.1' && config.host !== 'localhost') {
    console.warn('Warning: listening beyond localhost in development mode. Use BREAKAPI_ENV=production behind TLS for anything shared.');
  }
  if (config.hosted && (config.allowLocalTargets || config.allowPrivateTargets)) {
    console.warn('Warning: this server is hosted but lets users scan local or private addresses. Set BREAKAPI_ALLOW_LOCAL_TARGETS=false and BREAKAPI_ALLOW_PRIVATE_TARGETS=false.');
  }
  if (config.simEmbedDir) console.log(simUp ? `Lab playground: simulation embedded, sandboxes at ${config.simPublicUrl}/sim/s/<id>` : 'Lab playground: OFF, the embedded simulation did not start (see the error above)');
  else console.log(config.simUrl ? `Lab playground: simulation at ${new URL(config.simUrl).host}` : 'Lab playground: off (set BREAKAPI_SIM_URL and BREAKAPI_SIM_CONTROL_KEY, or BREAKAPI_SIM_EMBED_DIR, to turn it on)');
});

let stopping = false;
const stop = async (signal) => {
  if (stopping) return;
  stopping = true;
  console.log(`${signal} received: stopping scans and closing.`);
  app.server.close();
  await app.shutdown();
  process.exit(0);
};
process.on('SIGTERM', () => stop('SIGTERM'));
process.on('SIGINT', () => stop('SIGINT'));
