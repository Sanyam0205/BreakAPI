// Prints fresh demo-API test tokens (valid 24h) as JSON and as copy-paste lines.
import { demoTokens } from '../demo/vulnerable-api.js';

const t = demoTokens();
const accounts = [
  { label: 'alice', role: 'user', authType: 'bearer', secret: t.alice, resourceIds: { id: '1', email: 'alice@demo.test' } },
  { label: 'bob', role: 'user', authType: 'bearer', secret: t.bob, resourceIds: { id: '2', email: 'bob@demo.test' } },
  { label: 'root', role: 'admin', authType: 'bearer', secret: t.root, resourceIds: { id: '3', email: 'root@demo.test' } },
];
if (process.argv.includes('--json')) {
  console.log(JSON.stringify(accounts, null, 2));
} else {
  for (const a of accounts) console.log(`${a.label.padEnd(6)} ${a.role.padEnd(6)} id=${a.resourceIds.id}\n  ${a.secret}\n`);
}
