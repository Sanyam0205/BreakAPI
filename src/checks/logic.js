import { is2xx, evidence, label } from './common.js';
import { syntheticTargets, actingAccount, ownRequest, cloneBody, parseJson, findKey, acceptance, accepted, confidenceOf } from './writes.js';
import { createSynthetic } from '../synthetic.js';

const QTY = /^(quantity|qty|count)$/i;
const PRICE = /^(price|amount|total|unit_?price|discount)$/i;
const ID_KEYS = ['id', 'orderId', 'order_id', 'uuid'];

// Bounded, sequential, synthetic. Race-condition flooding is deliberately not attempted.
export default {
  id: 'logic',
  async run({ client, endpoints, accounts, report, log, scan }) {
    const syn = createSynthetic(scan.id);
    const targets = syntheticTargets(client, endpoints, ['order']).filter((e) => e.bodyExample && typeof e.bodyExample === 'object');
    if (!targets.length) return log('Business-logic checks skipped: no order or payment endpoint is opted in to synthetic writes (and write requests authorized).');

    for (const ep of targets) {
      const account = actingAccount(ep, accounts);
      const req = ownRequest(ep, account);
      if (!req || (ep.requiresAuth && !account)) { log(`${label(ep)}: cannot build a safe request; business-logic checks skipped.`); continue; }
      const where = label(ep);
      const send = (body, purpose) => client.sendSynthetic(ep, { ...req, body, account, purpose });
      const fields = Object.keys(ep.bodyExample);
      const base = await send(cloneBody(ep, syn), 'business-logic baseline (synthetic data)');
      if (base.skipped) continue;
      if (!is2xx(base)) { log(`${where}: the baseline synthetic request returned ${base.status}; business-logic checks skipped.`); continue; }
      const baseJson = parseJson(base);

      for (const f of fields.filter((k) => QTY.test(k) && typeof ep.bodyExample[k] === 'number')) {
        const neg = await send(cloneBody(ep, syn, { [f]: -1 }), `negative ${f}`);
        if (neg.skipped) break;
        const negAcc = acceptance(neg, f, -1);
        if (accepted(negAcc)) {
          report({
            key: `logic|negative-quantity|${where}|${f}`,
            title: `Negative "${f}" accepted`,
            severity: negAcc === 'echoed' ? 'high' : 'medium',
            confidence: confidenceOf(negAcc),
            endpoint: where,
            param: f,
            description: `${f} = -1 was accepted and returned HTTP ${neg.status}.`,
            impact: 'A negative quantity can reduce a total, create credit or refunds, or corrupt stock counts.',
            remediation: 'Enforce quantity >= 1 (and a sensible maximum) on the server, independent of the client.',
            evidence: [evidence(neg, 'Synthetic order.')],
          });
        }
        const huge = await send(cloneBody(ep, syn, { [f]: 999999999 }), `huge ${f}`);
        if (huge.skipped) break;
        if (accepted(acceptance(huge, f, 999999999))) {
          report({
            key: `logic|huge-quantity|${where}|${f}`,
            title: `Unbounded "${f}" accepted`,
            severity: 'low',
            confidence: 'low',
            endpoint: where,
            param: f,
            description: `${f} = 999999999 was accepted and returned HTTP ${huge.status}.`,
            impact: 'Absurd quantities can exhaust stock, overflow totals or be used to probe for limits.',
            remediation: 'Set an upper bound per item and per order, and validate against available stock.',
            evidence: [evidence(huge, 'Indicator: some APIs legitimately accept large values.')],
          });
        }
      }

      for (const f of fields.filter((k) => PRICE.test(k) && typeof ep.bodyExample[k] === 'number')) {
        const cheap = await send(cloneBody(ep, syn, { [f]: 0.01 }), `client-supplied ${f}`);
        if (cheap.skipped) break;
        const cheapAcc = acceptance(cheap, f, 0.01);
        const was = findKey(baseJson, [f]);
        if (cheapAcc === 'echoed' && !(was && Number(was.value) === 0.01)) {
          report({
            key: `logic|client-price|${where}|${f}`,
            title: `The client decides the "${f}"`,
            severity: 'high',
            endpoint: where,
            param: f,
            description: `Sending ${f} = 0.01 was accepted and the order came back with that value.`,
            impact: 'Customers can set their own prices or discounts and buy at any amount.',
            remediation: 'Never trust prices, totals or discounts from the client. Look them up server-side from the item and recompute the total.',
            evidence: [evidence(cheap, 'Synthetic order.')],
          });
        }
        const negative = await send(cloneBody(ep, syn, { [f]: -1 }), `negative ${f}`);
        if (negative.skipped) break;
        const negativeAcc = acceptance(negative, f, -1);
        if (accepted(negativeAcc)) {
          report({
            key: `logic|negative-amount|${where}|${f}`,
            title: `Negative "${f}" accepted`,
            severity: 'medium',
            confidence: confidenceOf(negativeAcc, 'medium'),
            endpoint: where,
            param: f,
            description: `${f} = -1 was accepted and returned HTTP ${negative.status}.`,
            impact: 'Negative amounts can act as refunds or credits.',
            remediation: 'Reject negative and zero amounts on the server and compute totals server-side.',
            evidence: [evidence(negative)],
          });
        }
      }

      // Replaying an identical request.
      const body = cloneBody(ep, syn);
      const one = await send(body, 'replay: first submission');
      const two = one.skipped ? one : await send(body, 'replay: identical second submission');
      if (!one.skipped && !two.skipped && is2xx(one) && is2xx(two)) {
        const a = findKey(parseJson(one), ID_KEYS);
        const b = findKey(parseJson(two), ID_KEYS);
        if (a && b && String(a.value) !== String(b.value)) {
          report({
            key: `logic|replay|${where}`,
            title: 'Identical requests create duplicate records',
            severity: 'low',
            confidence: 'low',
            endpoint: where,
            description: `Two identical submissions both succeeded and produced different ids (${a.value}, ${b.value}).`,
            impact: 'Double submits and retries can charge or ship twice when there is no idempotency key or duplicate guard.',
            remediation: 'Support an Idempotency-Key header (or a client-generated unique reference) and reject or merge repeats.',
            evidence: [evidence(one, 'First submission.'), evidence(two, 'Second submission.')],
          });
        }
      }
    }
  },
};
