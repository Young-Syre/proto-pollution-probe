import { fingerprint, upgrade } from './finding.js';
import { rule } from './rules.js';
import { SEVERITY_RANK, type Finding, type RelatedLocation, type Severity } from './types.js';

export interface PairOptions {
  /** Sinks paired with each gadget, best-ranked first. */
  maxSinksPerGadget?: number;
  /** Absolute cap on chain findings, so a large scan cannot explode. */
  maxChains?: number;
}

/** Halves below this are candidates rather than findings, and do not form chains. */
const PAIRABLE = SEVERITY_RANK['medium'];

/**
 * Pair a write primitive with a read it could feed.
 *
 * A sink on its own says "this code could write to Object.prototype", which a reviewer
 * cannot act on without knowing what would read it. A gadget on its own says "this code
 * trusts a default", which is only a problem if something can forge that default. The
 * pair is the finding worth someone's afternoon, so the pair is what this emits.
 *
 * Pairing is gadget-led, and that choice came out of measurement. Sinks outnumber gadgets
 * by two orders of magnitude in real code — a dependency tree scanned during development
 * produced several hundred sinks and three ranked gadgets — so iterating sinks produced a
 * hundred near-identical criticals all pointing at the same three reads. Iterating gadgets
 * produces one chain per thing an attacker could actually achieve, which is the number a
 * reviewer wants. Every sink is still reported in its own right.
 *
 * Pairing is deliberately not a proof. The analyser does not claim the sink and the gadget
 * run in the same request, only that both halves are present in the scanned source, which
 * is the condition under which this bug class has historically been exploitable:
 * Object.prototype is process-wide, so the two halves need share no module, call stack or
 * author.
 */
export function pairFindings(findings: Finding[], options: PairOptions = {}): Finding[] {
  const maxSinks = options.maxSinksPerGadget ?? 1;
  const maxChains = options.maxChains ?? 100;

  const pairable = findings.filter((finding) => SEVERITY_RANK[finding.severity] <= PAIRABLE);
  const sinks = pairable.filter((finding) => finding.kind === 'sink');
  const gadgets = pairable
    .filter((finding) => finding.kind === 'gadget')
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.loc.file.localeCompare(b.loc.file) ||
        a.loc.start.offset - b.loc.start.offset,
    );
  if (sinks.length === 0 || gadgets.length === 0 || maxSinks === 0) return [];

  const meta = rule('PP-C01');
  const chains: Finding[] = [];
  for (const gadget of gadgets) {
    // A sink in the same file as the gadget is the one a reviewer can check fastest.
    const ranked = [...sinks].sort(
      (a, b) =>
        Number(b.loc.file === gadget.loc.file) - Number(a.loc.file === gadget.loc.file) ||
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.loc.file.localeCompare(b.loc.file) ||
        a.loc.start.offset - b.loc.start.offset,
    );
    const others = Math.max(0, sinks.length - maxSinks);
    for (const sink of ranked.slice(0, maxSinks)) {
      if (chains.length >= maxChains) return chains;
      const related: RelatedLocation[] = [
        { label: `write primitive: ${sink.ruleId} ${sink.ruleName}`, loc: sink.loc },
        { label: `read primitive: ${gadget.ruleId} ${gadget.ruleName}`, loc: gadget.loc },
        ...gadget.related,
      ];
      const sameFile = sink.loc.file === gadget.loc.file;
      chains.push({
        ruleId: meta.id,
        ruleName: meta.name,
        kind: 'chain',
        severity: chainSeverity(sink.severity, gadget.severity),
        message:
          `"${gadgetProperty(gadget)}" is read at ${gadget.loc.file}:${gadget.loc.start.line}:` +
          `${gadget.loc.start.column} without ever being assigned` +
          (gadget.reach ? `, and reaches ${gadget.reach.replace(/-/g, ' ')}` : '') +
          `. ${sink.ruleId} here can put that key on Object.prototype, which is where the read ` +
          `would find it. ` +
          (sameFile
            ? 'Both halves are in this file.'
            : 'The halves are in different files, which does not matter: Object.prototype is process-wide.') +
          (others > 0
            ? ` ${others} other write primitive${others === 1 ? '' : 's'} in this scan could serve instead.`
            : ''),
        loc: sink.loc,
        related,
        guards: sink.guards,
        ...(gadget.reach ? { reach: gadget.reach } : {}),
        fingerprint: fingerprint(`${meta.id}:${gadget.fingerprint}`, sink.loc),
      });
    }
  }
  return chains;
}

function gadgetProperty(gadget: Finding): string {
  return gadget.property ?? gadget.ruleName;
}

/** The pair is worse than either half, so the more severe half is promoted one step. */
function chainSeverity(sink: Severity, gadget: Severity): Severity {
  const worse = SEVERITY_RANK[sink] <= SEVERITY_RANK[gadget] ? sink : gadget;
  return upgrade(worse);
}
