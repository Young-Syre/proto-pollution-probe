# proto-pollution-probe

[![tests](https://github.com/Young-Syre/proto-pollution-probe/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/proto-pollution-probe/actions/workflows/tests.yml)
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A static analyser for prototype-pollution **sinks**, **gadgets**, and the **chains**
between them. No network, no execution of the analysed code, two runtime dependencies
(`acorn` and `acorn-walk`), SARIF 2.1.0 output.

## A sink is only half a bug

JavaScript has no private fields on a plain object and no distinction, at the point of
assignment, between "a key the program chose" and "a key that arrived in a request body".
`obj[key] = value` writes whatever `key` holds. Two of the names it might hold are
special:

```js
const target = {};
target['__proto__'] = { isAdmin: true };   // sets target's prototype
```

That one is a dead end on its own — it replaces one object's prototype. The interesting
version is a *nested* write, because `__proto__` on the way *in* is a getter that hands
back the prototype itself:

```js
function merge(dst, src) {
  for (const key in src) {
    if (typeof src[key] === 'object') merge(dst[key], src[key]);
    else dst[key] = src[key];
  }
}

merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
({}).isAdmin;   // true — for every plain object in the process
```

`dst['__proto__']` resolved to `Object.prototype`, and the recursive call wrote
`isAdmin` onto it. `Object.prototype` sits at the end of almost every property lookup in
the program, so from that moment on, any code that reads a property it never set gets the
attacker's value as a default. `JSON.parse` is in that example for a reason: it is the
ordinary way the *text* `__proto__` becomes a real own property of a real object, because
a parser has no other way to represent the key it was given.

The bug therefore has two halves, and they are usually written years apart by people who
have never met:

- a **sink** — a write that can reach `Object.prototype`: a recursive merge, a dotted-path
  setter, a query-string parser that builds nested objects from `a[b][c]=d`;
- a **gadget** — a read of a property that nothing in the program ever assigns, which the
  polluted prototype now answers: `if (options.isAdmin)`, `exec(cmd, opts)` where
  `opts.shell` was never set, `engine.compile(view.layoutSource)`.

A sink with no gadget is a latent bug nobody can demonstrate. A gadget with no sink is
ordinary code. Most tools report only the first half, which is why their output tends to
be filed and forgotten. This one reports both and names the pair.

## Install

```
git clone https://github.com/Young-Syre/proto-pollution-probe
cd proto-pollution-probe
npm ci
npm run build
```

Node 20 or later. The build produces `dist/src/cli.js`; `npm link` exposes it as
`proto-pollution-probe` (or `ppp`).

## Usage

Scan a file, a directory, or several of each:

```
$ node dist/src/cli.js --no-color test/fixtures/vulnerable/chain.js
test/fixtures/vulnerable/chain.js
  CRITICAL PP-C01 pollution-chain  8:18
    "shellCommand" is read at test/fixtures/vulnerable/chain.js:17:19 without ever being
    assigned, and reaches command execution. PP-S01 here can put that key on Object.prototype,
    which is where the read would find it. Both halves are in this file.
    | mergeInto((target[key] ??= {}), source[key]);
    → write primitive: PP-S01 unguarded-recursive-merge (test/fixtures/vulnerable/chain.js:8:18)
    → read primitive: PP-G01 gadget-command-execution (test/fixtures/vulnerable/chain.js:17:19)
    → the value reaches execSync (test/fixtures/vulnerable/chain.js:17:10)

  CRITICAL PP-G01 gadget-command-execution  17:19
    "shellCommand" is read from hook but is never assigned anywhere in the scanned source and
    never own-checked, so a polluted Object.prototype supplies its value. From there the value
    reaches execSync.
    | return execSync(hook.shellCommand);
    → the value reaches execSync (test/fixtures/vulnerable/chain.js:17:10)

  HIGH     PP-S01 unguarded-recursive-merge  8:18
    Recursive merge writes every key of source onto target with no key check. A source key of
    "__proto__" makes the write land on Object.prototype.
    | mergeInto((target[key] ??= {}), source[key]);
    → keys are taken from the source object here (test/fixtures/vulnerable/chain.js:6:3)
    → merge function mergeInto (test/fixtures/vulnerable/chain.js:5:8)

1 file scanned in 7ms — 2 critical, 1 high (1 paired chain)
```

The chain finding sits at the **write**, because that is what gets fixed, and names the
read so the reviewer can see what it is worth.

Guarded code produces nothing:

```
$ node dist/src/cli.js --no-color test/fixtures/guarded
14 files scanned in 13ms — no findings
```

Partially guarded code produces the finding *and* the reason the guard is not enough:

```
$ node dist/src/cli.js --no-color --verbose test/fixtures/weak/merge-proto-only-denylist.js
test/fixtures/weak/merge-proto-only-denylist.js
  MEDIUM   PP-S01 unguarded-recursive-merge  9:9
    Recursive merge writes every key of source onto target with no key check. A source key of
    "__proto__" makes the write land on Object.prototype. The key denylist here only rejects
    __proto__, so constructor.prototype still reaches it.
    | target[key] = {};
    → keys are taken from the source object here (test/fixtures/weak/merge-proto-only-denylist.js:4:3)
    → merge function merge (test/fixtures/weak/merge-proto-only-denylist.js:3:8)
    [guard: key-denylist, weak] Only __proto__ is rejected; a merge still recurses through the own "constructor" property into "prototype".

  LOW      PP-Q01 incomplete-key-denylist  9:9
    Key denylist covers __proto__ but not constructor or prototype. Where this sink recurses or
    walks a path, constructor.prototype arrives in the same place.
    | target[key] = {};
    → keys are taken from the source object here (test/fixtures/weak/merge-proto-only-denylist.js:4:3)
    → merge function merge (test/fixtures/weak/merge-proto-only-denylist.js:3:8)
    [guard: key-denylist, weak] Only __proto__ is rejected; a merge still recurses through the own "constructor" property into "prototype".

1 file scanned in 7ms — 1 medium, 1 low
```

### Options

```
  -f, --format <text|json|sarif>  Output format (default: text)
  -o, --output <file>             Write the report to a file instead of stdout
  -s, --min-severity <level>      critical|high|medium|low|note (default: low)
      --no-pair                   Do not emit PP-C01 chain findings
      --corpus <dir>              Count findings per rule over a tree, for measuring
                                  the false-positive rate yourself
      --include-node-modules      Do not skip node_modules
      --include-minified          Analyse *.min.js and bundled output as well
      --strict-files              Exit 3 if any file could not be analysed
      --exit-zero                 Always exit 0, whatever was found
      --max-sinks-per-gadget <n>  Write primitives paired with each gadget (default: 1)
      --max-chains <n>            Cap on chain findings (default: 100)
  -v, --verbose                   Show the guard analysis behind each finding
      --no-color                  Disable colour (also honours NO_COLOR)
      --rules                     Print the rule table and exit
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; nothing at or above the severity threshold |
| `1` | Scan completed; at least one finding at or above the threshold |
| `2` | Bad usage: unknown flag, missing value, no path given |
| `3` | The scan could not be completed — no analysable files, or `--strict-files` and a file was skipped |

The threshold is `--min-severity`, default `low`. Both the report and the exit code use
it, so `--min-severity high` gates a build on the findings worth blocking a build for.
`--corpus` always exits `0` unless the scan itself failed: it measures rather than gates,
and a tree of other people's dependencies containing findings is not a build failure.

## Rules

Severity in this table is the *default* severity. A partial guard lowers it by one step
(see below). Rules at `note` are deliberately below the default threshold — the
measurement section explains why.

<!-- rules-table:begin -->
| ID | Name | Kind | Default severity | What it means |
| --- | --- | --- | --- | --- |
| `PP-S01` | unguarded-recursive-merge | sink | high | Recursive merge copies attacker-chosen keys into a destination object |
| `PP-S02` | unguarded-path-setter | sink | high | Dotted or slashed path setter creates intermediate objects without a key check |
| `PP-S03` | unguarded-key-copy-loop | sink | medium | Shallow key-copy loop assigns a computed key onto a destination object |
| `PP-S04` | unvalidated-assign-into-shared-object | sink | medium | Object.assign or object spread copies an unvalidated source into a shared object |
| `PP-S05` | dynamic-path-utility-call | sink | high | Lodash-shaped merge or set helper called with a non-literal key or path |
| `PP-S06` | nested-key-query-parse | sink | high | Flat input is expanded into nested objects by bracket or operator syntax |
| `PP-S07` | computed-key-property-definition | sink | note | Object.defineProperty, Reflect.set or a class field uses a non-literal key |
| `PP-S08` | json-parse-into-sink | sink | high | JSON.parse output reaches a pollution sink with no reviver and no key filter |
| `PP-G01` | gadget-command-execution | gadget | critical | Unvalidated property read reaches a process-spawning call |
| `PP-G02` | gadget-path-resolution | gadget | high | Unvalidated property read reaches path or filesystem resolution |
| `PP-G03` | gadget-template-render | gadget | high | Unvalidated property read reaches a template compile, render or HTML sink |
| `PP-G04` | gadget-auth-decision | gadget | high | Unvalidated property read is used as a security decision |
| `PP-G05` | gadget-unvalidated-default | gadget | note | Property read that is never assigned and never own-checked |
| `PP-C01` | pollution-chain | chain | critical | A reported sink and a reported gadget together form an exploitable chain |
| `PP-Q01` | incomplete-key-denylist | guard quality | low | Key denylist blocks __proto__ but not constructor or prototype |
| `PP-Q02` | own-property-filter-only | guard quality | low | Sink relies on an own-property filter, which JSON input defeats |
| `PP-E01` | parse-error | diagnostic | note | File could not be parsed as a module or a script |
| `PP-E02` | typescript-erasure-unavailable | diagnostic | note | TypeScript file could not have its types erased |
| `PP-E03` | file-unreadable | diagnostic | note | File could not be read from disk |
| `PP-E04` | minified-source | diagnostic | note | File looks like bundled or minified output and was not analysed |
<!-- rules-table:end -->

`npm run build && node scripts/rules-table.mjs --check` verifies that this table still
matches `src/rules.ts`; CI runs it, so the two cannot drift.

## Guard recognition

This is the part that decides whether anyone keeps the tool installed. A tool that
reports correctly written code gets switched off, and a tool that calls a weak guard
"safe" is worse than no tool. So guards are recognised generously and called *sufficient*
reluctantly, and guard quality is reported separately from the sink.

| Guard | Recognised as | Effect | Proven by |
| --- | --- | --- | --- |
| Key denylist covering `__proto__`, `constructor`/`prototype` | sufficient | no finding | `test/fixtures/guarded/merge-denylist.js`, `path-setter-denylist.js` |
| Key denylist covering `__proto__` only, on a **one-level** write | sufficient | no finding | `test/fixtures/guarded/merge-shallow-proto-denylist.js` |
| Key denylist covering `__proto__` only, on a **deep** write | weak | sink reported one severity lower, plus `PP-Q01` | `test/fixtures/weak/merge-proto-only-denylist.js` |
| `Object.create(null)` destination, no plain `{}` intermediates | sufficient | no finding | `test/fixtures/guarded/merge-null-prototype.js`, `path-setter-null-prototype.js` |
| `Object.create(null)` root with plain `{}` intermediates | partial | sink reported, with the reason | `test/fixtures/vulnerable/path-setter-null-root.js` |
| `Map` / `WeakMap` container | sufficient | no finding | `test/fixtures/guarded/merge-map.js`, `map-bracket-write.js` |
| `Object.freeze(Object.prototype)` anywhere in the program | sufficient | no finding | `test/fixtures/guarded/merge-frozen-prototype.js` |
| `JSON.parse` reviver that drops `__proto__` | sufficient | the parse is not treated as a source | `test/fixtures/guarded/json-reviver.js` |
| `Object.hasOwn` / `hasOwnProperty.call` filter, no `__proto__`-producing parser in the file | sufficient in context | no finding at the default threshold; `PP-Q02` at `note` | `test/fixtures/guarded/merge-has-own.js` |
| `Object.hasOwn` / `hasOwnProperty.call` filter **with** `JSON.parse` in the file | partial | sink reported one severity lower, pointing at the parser | `test/fixtures/weak/merge-has-own-json.js` |
| `Object.hasOwn` on a gadget read | sufficient | no finding | `test/fixtures/guarded/gadget-has-own.js` |
| `'key' in obj` on a gadget read | weak | gadget reported one severity lower, with the reason | `test/fixtures/weak/gadget-in-check.js` |

Three of those entries are judgement calls worth stating plainly, because they are where
this tool disagrees with the usual advice.

**An own-property filter is not a prototype-pollution guard.** `hasOwnProperty` excludes
keys inherited through the prototype chain, and `__proto__` written in source *is* the
prototype — so for an object built by code, the filter never sees the key anyway. But
`JSON.parse('{"__proto__":{}}')` creates `__proto__` as an **own** property, and the
filter waves it through. So the filter is honoured only while nothing in the file can
produce such a key: `JSON.parse` without a reviver, `Object.fromEntries`, `qs.parse`,
`querystring.parse`, a YAML loader, `URLSearchParams`, or a `req.body`-shaped read. When
one of those is present, the sink is reported and the finding points at the parser.

**`Object.create(null)` protects one level, not the tree.** It is the standard
recommendation and for a shallow copy it is complete: `dst['__proto__'] = v` on a
prototype-less object is an ordinary own property with nothing behind it. But a deep merge
or a path setter *creates* the objects it writes into, and if it creates them as `{}` then
level two is an ordinary object again — with an inherited, truthy `constructor`. A path of
`a.constructor.prototype.polluted` walks out of the null-prototype root, through the real
`Object`, and onto `Object.prototype`. The two fixtures in that table differ only in
whether the intermediates are `Object.create(null)` or `{}`.

**`'key' in obj` is not a guard either.** `in` walks the prototype chain, so it returns
`true` for exactly the property an attacker has just planted there. It is honoured as a
*weak* guard — the gadget is reported one severity lower with that sentence attached —
because code that writes it has clearly thought about absence, but it does not stop this
bug.

**Depth decides whether a `__proto__`-only denylist is enough.** For a one-level write it
is: `dst['constructor'] = v` merely shadows an inherited property. For anything that
recurses or walks a path it is not, because `constructor.prototype` arrives in the same
place. The analyser knows which kind of sink it found, so the same denylist is accepted in
one fixture and reported in the other.

## Measuring the false-positive rate yourself

`--corpus` runs the analyser over a tree and reports counts per rule, so nothing here has
to be taken on trust.

### On the labelled fixtures

`test/fixtures/` contains paired vulnerable and guarded versions of every sink. The test
suite asserts both directions: 142 tests and 400 assertions, run with `node --test`.

```
npm ci && npm test
```

The guarded directory is asserted to be **completely clean at the default threshold** —
not "low noise", zero findings — and every guard in the table above has a fixture proving
it. The vulnerable directory is asserted to produce the rule each fixture is named for.

### On a real dependency tree

The figures below come from one run over the installed dependency tree of an unrelated
local Node project: a front-end/tooling tree whose largest packages are webpack,
prettier, puppeteer, zod, ajv, postcss and react-dom. The command was
`proto-pollution-probe --corpus node_modules`, run from that project's root so the paths
below are relative; the output is otherwise unedited.

```
corpus: node_modules
4885 file(s) discovered, 4699 analysed, 186 skipped, 5009ms

rule     name                                   findings   files
-------  -------------------------------------  --------  ------
PP-S01   unguarded-recursive-merge                     7       5
PP-S02   unguarded-path-setter                         1       1
PP-S03   unguarded-key-copy-loop                      56      47
PP-S04   unvalidated-assign-into-shared-object         4       4
PP-S05   dynamic-path-utility-call                     0       0
PP-S06   nested-key-query-parse                        0       0
PP-S07   computed-key-property-definition              0       0
PP-S08   json-parse-into-sink                          0       0
PP-G01   gadget-command-execution                      0       0
PP-G02   gadget-path-resolution                        0       0
PP-G03   gadget-template-render                        0       0
PP-G04   gadget-auth-decision                          2       2
PP-G05   gadget-unvalidated-default                    0       0
PP-C01   pollution-chain                               2       1
PP-Q01   incomplete-key-denylist                       0       0
PP-Q02   own-property-filter-only                      0       0
PP-E01   parse-error                                   0       0
PP-E02   typescript-erasure-unavailable                0       0
PP-E03   file-unreadable                               0       0
PP-E04   minified-source                               0       0

by severity: 2 critical, 10 high, 58 medium, 2 low

files with the most findings:
     4  postcss/lib/container.js
     3  ajv-keywords/src/definitions/deepProperties.ts
     3  postcss/lib/node.js
     3  webpack/lib/hmr/JavascriptHotModuleReplacement.runtime.js
     2  browserslist/node.js
     2  webpack/lib/asset/AssetGenerator.js
     2  webpack/lib/config/normalization.js
     2  webpack/lib/util/deterministicGrouping.js
     2  wrappy/wrappy.js
     1  @babel/types/lib/modifications/inherits.js
```

72 findings over 4,699 analysed files, or roughly one finding per 65 files.

**What was triaged, and what "false positive" means here.** Two different questions get
confused under that phrase, so both are answered separately.

1. *Is the rule's own claim true?* "There is no key check here", "this property is never
   assigned", "this target is module-level". I read all 16 findings outside `PP-S03`, plus
   a 15-finding sample of `PP-S03`'s 56 — 31 in total. **In 31 findings I found no case
   where the rule's stated condition was false.** That is the number the implementation is
   responsible for.
2. *Is it reachable from untrusted input in that package?* A different question, and the
   answer is mostly no. By my reading, 2 of those 31 are shaped like something an attacker
   could reach: `ajv-keywords`' JSON-pointer path setter (`PP-S02`, exploitable if a
   schema is attacker-supplied) and `@babel/types`' `inherits` key copy, whose `_`-prefix
   filter lets `__proto__` through. The other 29 are build tooling copying keys that the
   developer typed — correct detections of the pattern, in code no request ever reaches.
   The `PP-G04` pair in `ws` is a genuine gadget (`req.socket.authorized` is set natively,
   never in source, and decides `verifyClient`'s `secure` flag), and the two `PP-C01`
   chains pair it with a write primitive in a different package, which is true but is not
   an exploit.

A static analyser cannot answer question 2 — it has no idea which functions sit behind an
HTTP handler. It is stated here because quoting only question 1 would be misleading, and
because the ratio is the honest reason to run this on your own code rather than on your
dependencies.

**What that measurement changed.** Several rules were recalibrated by it rather than by
taste, and the reasons are recorded in the source next to the code they justify:

- `PP-S07` and `PP-G05` fire so broadly on real code that they are now `note`-level and
  below the default threshold. `PP-S07` found 452 `Object.defineProperty` calls, almost
  all of them in the module-interop helpers TypeScript and Babel emit; `PP-G05` found 797
  unassigned property reads, almost all in bundled output whose type declarations were not
  scanned. Both remain available with `--min-severity note` as candidate lists.
- Reach analysis now requires knowing where a function came from. Matching the callee's
  *name* reported `regex.exec(s)` as command execution and a promise's `resolve(value)` as
  path resolution. A bare call now only counts when the name was imported from a module
  that does that thing, and argument position is checked too —
  `fs.appendFileSync(file, text)` writes `text` into `file`, so a value arriving in `text`
  is not path traversal.
- `PP-S02` now requires the write's key to *be* a segment of the split string. Accepting
  any computed write in a function that called `.split('.')` somewhere produced 14 reports
  and was right about one of them.
- `PP-S03` ignores destinations the function just created as `{}`, since writing
  `__proto__` into an object nothing else has seen replaces only that object's prototype.
  That alone removed 300-odd reports.
- Chains are paired gadget-first. Sinks outnumber gadgets by two orders of magnitude, so
  pairing sink-first produced 100 near-identical criticals pointing at the same three
  reads; gadget-first produces one chain per thing an attacker could actually achieve.
- Bundled and minified files are skipped by default (`PP-E04`). A finding on a 40,000-
  character line has an unreadable excerpt and a fix that belongs in a source file the
  scan never saw.

Total effect of that pass on the same tree: 1,198 findings down to 72, and the scan from
18s to 5s.

### Reproducing a measurement

The tree above is not in this repository, so those exact numbers are not reproducible by
anyone else. One number here is: this repository's own installed dev dependencies, which
are `acorn`, `acorn-walk`, `typescript` and `@types/node`.

```
$ npm ci && npm run build
$ node dist/src/cli.js --corpus node_modules
corpus: node_modules
9 file(s) discovered, 7 analysed, 2 skipped, 58ms
...
by severity: none
skipped: 2 PP-E04
```

Zero findings, and worth saying why rather than claiming it as a precision result: the
tree is nine files, two of which are the TypeScript compiler's own multi-megabyte bundles
and are skipped as generated output. It is a useful smoke test and nothing more. For a
real figure, point `--corpus` at a tree of your own:

```
node dist/src/cli.js --corpus ../some-other-project/node_modules
node dist/src/cli.js --corpus src --format json       # your own code
```

`--corpus` lists every rule including the ones that scored zero, and the files that drove
the counts, which is what you need to triage a sample and get your own figure.

## SARIF

`--format sarif` emits SARIF 2.1.0. Every rule that fired is declared once in
`runs[0].tool.driver.rules` with a short and full description, a default level, and
`properties.tags` carrying `security`, `prototype-pollution` and `external/cwe/cwe-NNNN`.

- SARIF has three result levels and no notion of "critical", so severity travels twice:
  `level` (`error` / `warning` / `note`) for tools that only read SARIF, and
  `properties["security-severity"]` — the CVSS-shaped number GitHub code scanning sorts
  and filters on — for tools that read that.
- Each result carries `partialFingerprints["protoPollutionProbe/v1"]`, derived from the
  rule, the path, the text of the offending line and (for gadgets) the property name.
  Line numbers are deliberately not part of it, so a finding keeps its identity when code
  moves above it.
- Chain findings use `relatedLocations` to carry the other half, each with an `id` and a
  message.
- `artifactLocation.uri` is always relative to the scan root, with forward slashes, in
  results and in `relatedLocations` alike. The scan root is the working directory when
  every scanned path is inside it — so `probe src` keeps reporting `src/a.js` — and the
  common ancestor of the scanned paths when they are not, which is what stops an
  absolute path reaching a SARIF file bound for a pull request. CI asserts it from a
  different working directory, against an absolute target, because an assertion that
  only ever sees relative inputs cannot fail.
- Skipped files become `invocations[0].toolExecutionNotifications`, not results: a file
  that could not be parsed is a fact about the run, not a finding about the code.

```
node dist/src/cli.js --format sarif --output report.sarif src
```

## What this tool does not do

- **It does not prove exploitability.** A `PP-C01` chain says both halves exist in the
  scanned source, which is the condition under which this bug class has historically been
  exploitable, because `Object.prototype` is process-wide. It does not say the two halves
  run in the same request, or that either is reachable from outside. See the triage above.
- **No interprocedural dataflow.** Reach analysis follows a value from a read to a call
  within one function, through at most one local binding. A gadget whose value is handed
  to a helper in another module will be reported as `PP-G05` (a `note`) rather than as
  command execution.
- **No cross-file resolution beyond property names.** The one thing the analyser does
  globally is collect every property name assigned anywhere in the scan, so that a
  property some other module sets is not reported as a gadget. It does not resolve
  imports, types or call graphs. Scanning one file alone therefore reports more gadgets
  than scanning the project it belongs to.
- **TypeScript is erased, not understood.** Types are removed with Node's built-in
  `module.stripTypeScriptTypes` in strip-only mode, which overwrites type syntax with
  spaces, so every reported line and column is the line and column in the original `.ts`
  file. That requires **Node 22.13 or later**; on Node 20 a `.ts` file is skipped and
  reported as `PP-E02`. Strip-only mode also cannot erase syntax with runtime behaviour:
  `enum` declarations, `namespace` / `module` bodies, and constructor parameter properties
  (`constructor(private x: T) {}`). Files using those are skipped and reported, never
  silently ignored. The analyser reads no type information — a `Record<string, unknown>`
  tells it nothing a `{}` would not.
- **No JSX or TSX.** `acorn` does not parse JSX without a plugin, and this tool has two
  dependencies. `.jsx` and `.tsx` files are not discovered at all.
- **Bundled output is skipped by default.** See `PP-E04`; `--include-minified` overrides.
- **It never runs the code.** No `eval`, no `require` or `import` of an analysed file, no
  network access, no shelling out. The analysed source is read as text and parsed.
- **It is a linter, not an oracle.** `PP-S03`, `PP-S04` and the `note`-level rules describe
  patterns rather than bugs. They are worth a reviewer's glance in code that handles
  untrusted input and worth nothing at all in a build script.

## Library use

```js
import { analysePaths, discoverFiles, renderSarif } from 'proto-pollution-probe';

const files = discoverFiles('src');
const result = analysePaths(files, { minSeverity: 'medium' });

for (const finding of result.findings) {
  console.log(finding.ruleId, finding.loc.file, finding.loc.start.line, finding.message);
}

console.log(renderSarif(result, { toolVersion: '0.1.0' }));
```

`analyseSources` takes in-memory sources instead, which is what the test suite uses.
Types are exported for `Finding`, `ScanResult`, `GuardNote`, `Severity` and the rest.

## Licence

MIT © 2026 David Nichols
