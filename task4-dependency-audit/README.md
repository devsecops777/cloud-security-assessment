# Task 4 — Third-Party Dependency Security Audit

Audit of the supplied `package.json` for `vulnerable-node-app`, with a verified
remediation and a script that turns `npm audit` output into CSV/JSON reports.

**Tool:** `npm audit` (npm 10.9.7, Node 22.22.2) ·
raw output in `reports/npm-audit.json`.

```
package.json            the manifest as supplied
package-lock.json       resolved tree the audit ran against (reproducible)
package.fixed.json      remediated manifest -- verified 0 vulnerabilities
package-lock.fixed.json its resolved tree
audit_report.py         bonus: npm audit JSON -> CSV + JSON report, and a CI gate
reports/                npm-audit.json, vulnerabilities.csv, audit-report.json
```

## Headline result

| | Supplied manifest | After remediation |
|---|---|---|
| Vulnerable packages | **23** | **0** |
| Advisories | 45 | 0 |
| Critical / High / Moderate / Low | 8 / 9 / 3 / 3 | 0 / 0 / 0 / 0 |
| Direct vs transitive | 5 direct, 18 transitive | — |

149 packages resolve from 7 declared dependencies (128 prod, 22 dev) — the usual
reminder that a dependency audit is mostly an audit of things nobody chose.

```
$ npm audit
23 vulnerabilities (3 low, 3 moderate, 9 high, 8 critical)

$ npm audit --package-lock-only   # with package.fixed.json
found 0 vulnerabilities
```

## Which dependencies are vulnerable

### Direct dependencies

| Declared | Resolves to | Severity | Representative advisories | Fix |
|---|---|---|---|---|
| `mongoose` `^4.2.4` | 4.13.x | **critical** (CVSS 10.0) | Prototype pollution via `Schema.path`, prototype pollution in Schema object, search injection, improper `$nor` sanitisation → NoSQL injection | `9.10.1` — **major** |
| `lodash` `4.17.10` | 4.17.10 | **critical** (CVSS 9.1) | Command injection (`GHSA-35jh-r3h4-6jhm`), three prototype-pollution advisories, two ReDoS | `4.18.1` — non-breaking |
| `mocha` `5.0.5` (dev) | 5.0.5 | **critical** | Pulls vulnerable `mkdirp`→`minimist` (prototype pollution, CVSS 9.8) and `diff` (DoS) | `12.0.2` — **major** |
| `jsonwebtoken` `8.1.0` | 8.1.0 | **high** (CVSS 8.1) | Signature-validation bypass via insecure default algorithm in `jwt.verify()`, forgeable tokens via RSA→HMAC key confusion, unrestricted key type | `9.0.3` — **major** |
| `express` `4.15.0` | 4.15.0 | **high** | XSS via `response.redirect()`, open redirect on malformed URLs, drags in vulnerable `qs`, `send`, `serve-static`, `path-to-regexp`, `fresh`, `mime`, `debug`, `cookie` | `4.22.3` — non-breaking |
| `body-parser` `^1.19.0` | 1.20.x | clean | — | unchanged |
| `dotenv` `^8.2.0` | 8.6.0 | clean | — | unchanged |

### The worst of it, in plain terms

- **`jsonwebtoken` 8.1.0 — signature bypass.** `jwt.verify()` can be induced to
  accept a token the server never signed (algorithm confusion, RSA public key
  used as an HMAC secret). For an app whose authentication *is* JWT, this is
  authentication bypass, not a theoretical risk. Highest priority despite not
  being the highest CVSS on the list.
- **`mongoose` 4.x — prototype pollution, CVSS 10.0**, plus search injection and
  incomplete `$nor` sanitisation. Prototype pollution in an ORM reaches query
  construction: the path from user-supplied JSON to NoSQL injection is short.
- **`lodash` 4.17.10 — command injection** (`template`/`toNumber` paths) and
  prototype pollution. `lodash.merge` on request bodies is the classic sink.
- **`minimist` ≤0.2.3 (via `mocha`→`mkdirp`) — prototype pollution, CVSS 9.8.**
  Dev-only, so the exposure is the build machine, not production — but a
  compromised build agent signs and ships the artifact, so "dev-only" is a
  reason to schedule it, not to skip it.
- **`qs` and `path-to-regexp` (via `express`) — ReDoS and prototype pollution.**
  Reachable from any request that carries a query string.

## How many can be fixed

**All 23.** But the route matters, and the obvious command does nothing:

| Approach | Result |
|---|---|
| `npm audit fix` | **0 fixed, 23 remain** |
| Non-major upgrades only (`express ^4.22.3`, `lodash ^4.18.1`) | 11 fixed, 12 remain |
| `npm audit fix --force` (allows majors) | 23 fixed, **0 remain** |
| `package.fixed.json` (the same upgrades, written explicitly) | **0 remain**, verified |

Each row was measured, not estimated.

**Why plain `npm audit fix` fixes nothing here** is the most useful finding in
this report: the manifest pins exact versions — `"express": "4.15.0"`,
`"lodash": "4.17.10"`, `"jsonwebtoken": "8.1.0"`, `"mocha": "5.0.5"`. npm will
not move a dependency outside its declared range, so with exact pins there is
nothing it is permitted to do. A team that runs `npm audit fix`, sees no errors
and assumes it is patched would stay vulnerable indefinitely. Exact pins are a
supply-chain *defence* (they stop a malicious republish landing silently), but
they make patching a deliberate act — which needs Dependabot or Renovate, not a
one-off command.

Twelve findings need a major upgrade, all reachable from three direct
dependencies:

| Upgrade | Breaking changes to expect |
|---|---|
| `jsonwebtoken` 8 → 9 | `algorithms` must be passed explicitly to `verify()` (that *is* the fix), stricter key-type checks, Node ≥ 12 |
| `mongoose` 4 → 9 | Five majors. New MongoDB driver, connection options (`useNewUrlParser` and friends removed), `Model.update`/`remove` removed in favour of `updateOne`/`deleteOne`, `strictQuery` default changed, promise handling. Plan a migration, not an afternoon |
| `mocha` 5 → 12 | Node ≥ 20, `--require` behaviour with ESM, some reporter and config renames. Dev-only, so lowest blast radius |

`express` 4.15.0 → 4.22.3 and `lodash` 4.17.10 → 4.18.1 stay within the same
major and fix 11 of the 23 with no API change — do those today.

## Bonus — `audit_report.py`

Parses `npm audit --json` into a CSV and a JSON report, and doubles as a CI gate.
Standard library only, Python 3.9+.

```bash
./audit_report.py --run --csv reports/vulnerabilities.csv --json reports/audit-report.json
./audit_report.py --input reports/npm-audit.json --min-severity high
./audit_report.py --run --fail-on critical      # exit 1 when a critical is present
```

```
23 vulnerable packages  (critical 8, high 9, moderate 3, low 3)
23 fixable: 11 without a breaking change, 12 require a major upgrade

PACKAGE               SEVERITY  CVSS   DIRECT  FIX         BREAKING
-------------------------------------------------------------------
mongoose              critical  10.0   yes     9.10.1      yes
bson                  critical  9.8    no      9.10.1      yes
minimist              critical  9.8    no      12.0.2      yes
lodash                critical  9.1    yes     4.18.1      no
...
```

Worth noting: the script's split of 11 non-breaking / 12 major was derived from
the advisory metadata, and it matches the empirically measured result of
actually performing the non-breaking upgrades (11 findings cleared, 12 left).
The two numbers were produced independently.

What it does beyond reformatting:

- **Ranks by real risk** — severity, then CVSS, then direct-vs-transitive, so the
  top of the report is the part someone can act on this morning.
- **Separates fixable-without-breaking from needs-a-major**, which is the
  decision a maintainer actually has to make.
- **Explains transitive findings** via an `affects` column, so a package nobody
  installed on purpose arrives with its reason attached.
- **Handles both audit schemas** — npm v7+ `vulnerabilities` and npm v6
  `advisories` — so it keeps working on older CI images.
- **`--fail-on`** gives a threshold gate: fail the build on critical while
  high and below are tracked rather than blocking.
- **Non-zero npm exit status is not treated as failure** — npm exits non-zero
  precisely when it finds something, and mishandling that is how audit steps end
  up silently green.