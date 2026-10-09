# Unit Test Plan — bandaid

Goal: unit tests for the critical and complex parts of the codebase, written with the **tdd**
skill's rules (tests at pre-agreed seams, vertical slices, no implementation-coupled or
tautological tests), and structured so that **workstreams execute concurrently without touching
each other's files**.

Preconditions (verified): `go vet ./...` passes, `go test ./...` runs green (no test files yet),
Go 1.27 toolchain.

---

## 1. Scope philosophy

- Test **behavior through public seams** — complex logic, untrusted input handling, and
  regression-prone areas (several past bug-fix commits touch exactly these).
- **Skip simple and non-critical parts** (see §3). Thin wrappers, cosmetic formatting, and flag
  wiring get no unit tests.
- **Stdlib only** (`testing`, `net/http/httptest`, `bytes`, `os`, `time`, ...). No new module
  dependencies, no shared test-helper package. Helpers stay package-local.

## 2. Seams under test (confirm before starting — tdd skill requires pre-agreed seams)

| Seam (public API)                                  | Package        | Why critical |
| -------------------------------------------------- | -------------- | ------------ |
| `model.Report.{Exclude, Normalize, Hash}`          | internal/model | IP-set arithmetic, in-process change-detection hash; past bug here (`hashDelim`) |
| `model.Finding.{Normalize, String, ReasonsStr}`    | internal/model | untrusted input validation (target + reason grammar) |
| `geo.NewGenerator`, `Generator.Generate`           | internal/geo   | the product output (nginx geo file); past bugs in default/addr-var handling |
| `report.Parse`                                     | internal/report| untrusted JSON wire format |
| `report.NewFetcher`, `Fetcher.Fetch`               | internal/report| network boundaries: status check, size cap, timeout; past bugs here |
| `app.Config.Validate`, `app.ParseFileMode`         | internal/app   | config validation; `GeoFileMode` octal parsing is regression-prone (see W4 note) |
| `app.Run` (error paths only)                       | internal/app   | end-to-end config error surfacing |

Not seams (do not test through them): private helpers, `runService`'s closure internals, slog
output formatting, HTTP header decoration (e.g. User-Agent) — implementation detail.

## 3. Explicitly out of scope

| Area | Reason |
| --- | --- |
| `internal/info` | ldflags-injected build-info getters + string formatting; trivial and cosmetic |
| `pkg/logx`       | thin `slog` wrappers; trivial context get/set |
| `pkg/execx`      | thin `os/exec` wrapper; testing it means spawning processes, low value |
| `cmd/bandaid`    | pflag registration and `os.Exit` wiring; no logic worth pinning |
| mTLS happy path (client cert against TLS server) | heavyweight cert generation; error paths of `newMTLSClient` are covered via `NewFetcher` instead |
| `runService` timer loop cadence / interval clamp | needs clock injection; low value vs. cost (clamping is 3 lines) |

## 4. Concurrency model

Four workstreams, one per package (plus one tiny shared package). **File ownership is disjoint**:
each stream only creates `*_test.go` files in its own package directory. No shared fixtures,
no `go.mod`/`Makefile` edits (std-lib only), so parallel execution produces zero merge conflicts.
Streams have **no dependencies on each other** and can run fully in parallel (e.g. four parallel
sub-agents, each loading the `tdd` skill).

Shared conventions for every stream:
- Table-driven where it fits; test names describe behavior (`TestExcludeRemovesWhitelistedPrefixes`),
  not methods.
- **Expected values come from an independent source of truth**: worked examples, RFC/spec-derived
  values, or reviewed literals — never recomputed the way the code does.
- Deterministic time via injected `now func() time.Time`; no sleeps; `t.TempDir()` for file tests.
- One seam → one failing test → minimal green, per the tdd skill. Where a test exposes a real bug,
  keep the red test and fix it in the same slice (record the bug in the commit message).

---

## 5. Workstreams

### W1 — `internal/model` (new file: `internal/model/model_test.go`)

Seams: `Report.Exclude`, `Report.Normalize`, `Report.Hash`, `Finding.Normalize`,
`Finding.String`, `Finding.ReasonsStr`, `Finding.Hash` (via `Report.Hash`).

Vertical slices (each = one test → green):

1. **Normalize masks host bits** — `10.1.2.3/8` → `10.0.0.0/8`, `2001:db8::1/32` → masked.
2. **Normalize sorts findings by target** — shuffled IPv4+IPv6 findings come out ordered
   (`netip.Prefix.Compare` order).
3. **Normalize rejects invalid target** — zero `netip.Prefix` → error wrapping `ErrInvalidTarget`.
4. **Normalize rejects invalid reasons** — `""`, `"a b"`, `"-x"`, `".x"`, non-ASCII →
   `ErrInvalidReason`; accepts `A-Z a-z 0-9 _ . -` with alnum first char (the `reasonRe` grammar).
5. **Exclude keeps non-overlapping findings unchanged** — whitelist disjoint from targets.
6. **Exclude splits partially overlapping findings** — e.g. finding `10.0.0.0/24`, whitelist
   `10.0.0.0/25` → exactly one finding `10.0.0.128/25`; **reasons survive the split**.
7. **Exclude drops fully covered findings** — whitelist superset of target → no findings.
8. **Exclude handles IPv6 and bare-address whitelist entries** (`1.2.3.4/32`-style).
9. **Hash is a deterministic chain** — identical findings → identical hash: independently
   constructed equal reports agree (the updater's change-detection contract; values are
   stable only within a version, not across versions — see the note at slice 12).
10. **Hash discriminates** — hash differs when target, prefix length, or reasons differ.
11. **Hash delimiter regression** — reasons `["ab","c"]` vs `["a","bc"]` hash differently
    (this is the bug fixed in `680c392`; also covers "reasons vs target bytes bleed").
12. **Hash golden constants — dropped (decision).** Exact `Report.Hash()` values are **not**
    a pinned contract: change detection (`lastHash`) is in-process only and resets on every
    restart, and the geo file's `# Report hash:` header is diagnostic-only — so the hash
    algorithm may change between versions without consequence, and pinning exact `uint32`
    literals would over-specify behavior. The required hash invariants are slices 9–11.
13. **String/ReasonsStr contract** — reasons joined with `":"`, `String()` is `target,reasons`
    (this string is the geo-file value contract; keep assertions here, not in W2).

### W2 — `internal/geo` (new files: `internal/geo/geo_test.go`, optional `internal/geo/testdata/`)

Seams: `NewGenerator`, `Generator.Generate`.

1. **NewGenerator rejects empty VariableName**; accepts minimal valid config.
2. **Generate rejects nil report / nil writer** — clear errors, no panic.
3. **Golden geo block** — fixed `now` and a fixed hash literal passed to `Generate` (a
   rendering input, not a pinned `Report.Hash()` value); a representative report (3 findings,
   mixed IPv4/IPv6) must render to one exact expected multiline string literal (header lines,
   `geo` opening, entries with `%q` quoting, closing `}`). The literal is written by hand from
   the nginx `geo` format spec, not copied from output.
4. **DefaultString rendered when set** (regression `bd6550e`: default was not written);
   **omitted when empty**.
5. **AddressVariableName rendered when set** (`geo $arg_remote_addr $geo {`) and omitted when
   empty (`geo $geo {`).
6. **Header reflects generator info** — hash line format `# Report hash: %x`, timestamp line
   uses the injected `now` (assert via literal in slice 3; only add a separate case if golden
   must vary).
7. **Writer errors propagate** — an `io.Writer` failing after N bytes makes `Generate` return an
   error (exercises the `writeString`/`bw.Flush` error path).
8. **Empty report renders a valid empty block** — `geo ... {` / `}` with no entries.

### W3 — `internal/report` (new files: `internal/report/report_test.go`, `internal/report/fetch_test.go`)

Seams: `report.Parse`, `report.NewFetcher`, `Fetcher.Fetch`.

`report.Parse`:

1. **Parses bare addresses** — `"1.2.3.4"` → `1.2.3.4/32`, `"2001:db8::1"` → `/128`
   (relies on `ipx.ParsePrefixOrAddr` semantics; pin the /32-/128 contract here).
2. **Parses prefixes verbatim** — `"10.0.0.0/8"`, `"2001:db8::/32"` with reasons.
3. **Empty/absent findings** → empty report, no error.
4. **Malformed JSON** → error wrapping `decode report`.
5. **Invalid target string** (including multi-slash `"a/b/c"`, empty string) → error.
6. **Unknown JSON fields ignored**; `reasons: null` tolerated.

`NewFetcher` (validation; exercises `newMTLSClient` error paths through the constructor seam):

7. **Timeout must be ≥ 1s** (regression `24b234e`/`571895b`) — `0`, `500ms` → error.
8. **MaxReportBytes bounds** — `0`, negative, `> 1<<40` → error.
9. **Cert without key (and vice versa) → error**; **bad CA PEM file** (temp file with garbage)
   → error; **missing CA file** → error.

`Fetcher.Fetch` (against `httptest.Server`):

10. **Happy path** — 200 + valid report body → parsed report matches expected.
11. **Non-200 responses fail** — 404/500 → error (regression `0e9bb7e`: status not checked).
12. **Oversized report rejected** — body of `MaxReportBytes+1` → "report too large" error
    (regression `38feb94`); boundary: exactly `MaxReportBytes` accepted.
13. **Invalid body fails to parse** — 200 + garbage → error.
14. **Context cancellation** — cancelled/very short-deadline ctx → error, no hang.

### W4 — `internal/app` (new file: `internal/app/app_test.go`) — includes one approved refactor

**Seam extraction first (production code change — confirm with the user before doing it):**
- rename `Config.validate` → `Config.Validate`, `parseFileMode` → `ParseFileMode` (exported;
  `internal/` package, so no public API impact). Fallback if declined: test the unexported
  functions from package-internal tests.
- Optional, second step: extract `runService`'s `update` closure into a named type
  (e.g. `updater.update(now time.Time)`) so file-write behavior becomes testable. **If declined,
  slices 6–10 are dropped** and W4 is slices 1–5 only.

Slices:

1. **Validate: URL rules** — empty URL, unparseable URL, non-http(s) scheme (`ftp://`), empty
   host → distinct errors.
2. **Validate: geofile rules** — empty `GeoFile` errors in service mode, allowed in dry-run.
3. **ParseFileMode** — `""` → `0644`; `"644"`, `"600"`, `"777"` parsed **octal** (regression
   `571895b`: mode must not parse as decimal); `"9"`, `"abc"`, `"1000"` (exceeds 9 bits),
   negative → errors.
4. **Run surfaces config errors** — `Run` with each invalid config returns the wrapped
   `validate config: ...` / `parse whitelist target: ...` / `parse geofile mode` error and
   performs no network I/O (error paths only — valid configs would enter the service loop).
5. **Whitelist target parsing** — bad entry in `WhitelistTargets` (e.g. `"a/b/c"`) fails `Run`.
6. *(needs updater extraction)* **Update writes geo file atomically** — after `update`, `GeoFile`
   exists with generated content and the requested file mode; no stray `geofile-*` temp files.
7. *(needs extraction)* **Unchanged hash skips rewrite** — same fetched report twice → file not
   rewritten the second time (content mtime/inode unchanged).
8. *(needs extraction)* **Changed report rewrites and runs PostExec** — `PostExec` pointing at
   e.g. `/bin/touch <marker>` → marker exists after change.
9. *(needs extraction)* **PostExec failure does not undo the update** — geo file still in place,
   update reports success.
10. *(needs extraction)* **Fetch failure leaves previous geo file intact** — nothing written.

---

## 6. Execution

1. **Confirm §2 seams and the W4 refactor decision** (single question to the user).
2. **Run W1–W4 concurrently** (parallel sub-agents). Each agent: load the `tdd` skill, work
   vertical slices, stay inside its package directory, run `go test ./<pkg>/... -race` as its own
   gate. Do **not** touch `go.mod`, `Makefile`, or other packages.
3. **Integration (after all streams land)** — run once in the shared tree:
   - `go vet ./...`
   - `go test -race ./...`
   - `go test -coverprofile=coverage.out ./...` and check the §2 seams are covered
     (target: each seam ≥ 85% statement coverage; spot-check W1 hash and W3 size-cap slices).
4. **Review** — run the `code-review` skill on the accumulated diff (standards + spec vs. this
   plan). Any test that breaks under a no-behavior-change refactor is flagged for rewrite.

## 7. Definition of done

- All slices in §5 green under `go test -race ./...`, `go vet ./...` clean.
- No new dependencies; no test-only production APIs except the approved W4 extractions.
- Every §2 seam has at least the slices listed; every regression named in §5 has a test that
  would have caught the original bug.
- Out-of-scope areas in §3 remain test-free (that is intentional).
