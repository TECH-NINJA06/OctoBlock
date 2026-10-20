# OctoPage and OctoBlock

OctoPage is an embedded relational database that uses a GitHub repository as its
storage layer. It provides SQL, transactions, branching, time-travel queries,
and database tooling while storing database state in ordinary Git objects.

OctoBlock extends the same Git-backed storage model to a POSIX-style file
system. It provides a copy-on-write file-system core, a durable write-back
engine, and control-plane and FUSE-facing layers for synchronizing mounted
volumes with a Git-compatible remote.

## Architecture

```text
+-----------------------------------------------------------------------------+
|                        Applications / POSIX Workloads                       |
+------------------------------------+----------------------------------------+
                                     |
         +---------------------------+---------------------------+
         |                                                       |
         v (SQL / DB-API / N-API / FFI / HTTP)                   v (POSIX / FUSE / CLI)
+------------------------------------+  +-------------------------------------+
|             OctoPage               |  |       OctoBlock VFS & Daemon        |
|  - SQLite VFS & Catalog            |  |  - FuseDispatcher & VfsSession      |
|  - Serializable Rebase & Replay    |  |  - Virtual /.octoblock/ Namespace  |
|  - AS OF Time-Travel & Branches    |  |  - ioctl Atomic Regions (REQ-3)     |
+------------------------------------+  +-------------------------------------+
         |                                                       |
         |                              +-------------------------------------+
         |                              |    octoblock-wb (Write-Back Engine) |
         |                              |  - Path-Class Router (policy.toml)  |
         |                              |  - L0 / L1 Encrypted Local Journal  |
         |                              |  - Op-Log Elision & Coalescing      |
         |                              |  - CAS Writer Leases & Conflict Log |
         |                              |  - OBEX Encryption & Signed Commits      |
         |                              +-------------------------------------+
         |                                                       |
         |                              +-------------------------------------+
         |                              |     octoblock-fs (OBF1 Core)        |
         |                              |  - 4 KiB CoW B+Trees (Inode/Dentry) |
         |                              |  - Extents, Inline Data & Xattrs    |
         |                              |  - Orphan Recovery & Online fsck        |
         |                              +-------------------------------------+
         |                                                       |
         +---------------------------+---------------------------+
                                     |
                                     v
+-----------------------------------------------------------------------------+
|                      octopage-git (Git Transport Layer)                     |
|  - 3-Level Fanout Page Trees (pages/aa/bb/cc) & Canonical Changelogs        |
|  - Atomic Ref CAS (refs/heads/*, refs/octopage/lease, refs/tags/octoblock/*)|
|  - Smart HTTP / GitHub REST / Raw CDN / Fault-Injection Testkit             |
+-----------------------------------------------------------------------------+
```

## What it does

OctoPage is designed for applications that want a database with GitHub's
durability, access controls, audit trail, and collaboration model. It turns
database activity into Git history:

- Database pages are stored as Git blobs.
- A committed transaction is represented by a Git commit.
- The current database state is identified by a Git ref.
- Changelogs make transactions reproducible and support replay and historical
  reads.
- SQLite provides the SQL engine through a custom virtual file system (VFS).

This makes the repository both the database backend and a transparent history
of its changes. Existing GitHub permissions and repository workflows can be
used to control access, inspect changes, and automate maintenance.

## How it works

When a client opens a database, OctoPage connects to a GitHub repository or a
Git-compatible remote and reads the database page map from the selected branch.
SQL is executed by SQLite, while the OctoPage VFS translates SQLite page reads
and writes into operations on Git-backed pages.

A write transaction reads a consistent snapshot, records the statements and
their deterministic inputs, and stages changed pages. OctoPage then creates a
Git commit and advances the database ref. If another writer commits first, the
transaction is checked and replayed against the newer state before it is
committed. This provides serializable writes without requiring a separate
database server.

Reads can target the current head or a historical commit with `AS OF`. Branches
provide isolated database histories that can later be merged. Encrypted
databases protect pages, schema information, and changelogs before they are
written to the repository.

## Main components

- **Rust database engine:** SQLite integration, page storage, transactions,
  changelogs, branching, encryption, and GitHub transport.
- **Command-line shell:** Run SQL, inspect history, create branches, manage
  encryption, and perform maintenance.
- **Language bindings:** Use the database from Rust, Python, Node.js, or C.
- **HTTP service:** Expose databases through a multi-tenant API backed by a
  GitHub App, with API keys, reader pools, and queued writes.
- **Browser client:** Run read-only SQL against public repositories using
  SQLite compiled to WebAssembly and GitHub's raw-content CDN.
- **Dashboard and SDKs:** Provide a web interface and TypeScript/Python clients
  for the hosted service.
- **OctoBlock file system:** Store files and directories in an `OBF1` volume,
  journal local changes, coalesce writes, and commit generations to Git.

The repository is also useful as a development reference: the [project
layout](#layout) shows where the engine, bindings, service, browser client,
dashboard, and SDKs live. Design notes and implementation investigations are
kept separately from this user guide in the repository.

## The `octopage` shell

```powershell
$env:OCTOPAGE_GITHUB_TOKEN = "github_pat_..."
cargo run --release -p octopage-cli -- --repo YOUR_USER/octopage-spike --branch refs/heads/sql --create
```

```text
octopage> CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT);
committed 4a349b24e5e9
octopage> INSERT INTO notes(body) VALUES('pages are git blobs'), ('a transaction is a commit');
2 rows changed
committed 6b66f21a1168
octopage> SELECT count(*) FROM notes AS OF '4a349b2';
count(*)
--------
0
(1 row)
octopage> .log 2
```

Each statement outside `BEGIN … COMMIT` is a commit of its own, and `.log` shows the statements each commit
ran. `-c "SQL"` runs one command, SQL piped on stdin runs as a script, and `--memory` gives a scratch
database that never leaves the machine. `.help` lists the dot commands.

- **Encrypted:** `--create --encrypt` makes an encrypted database. Pages, schema and changelogs are unreadable
  in the repository. The passphrase comes from `OCTOPAGE_PASSPHRASE` or a prompt, and the recovery key is
  printed once: store it. `--recovery-key` opens the database with it.
- **Branches:** `CREATE BRANCH feature;`, `MERGE BRANCH feature INTO main;` and `DROP BRANCH feature;`, and
  `.branches` lists them. Open a branch with `--branch refs/heads/feature`.
- **Signed commits:** `--sign-with ~/.ssh/id_ed25519` signs every commit; register the key on GitHub as a
  signing key to see them verified.

## The OctoBlock file system

OctoBlock is organized as a layered file-system stack:

1. **`octoblock-fs` (Layer 3)** implements the `OBF1` on-disk format, copy-on-write
   B+trees for inodes, dentries, extents, xattrs and orphans, page allocation,
   canonical JSONL operation logs, `mkfs`, `fsck`, and an in-memory reference
   model.
2. **`octoblock-wb` (Layer 4)** provides the write-back engine over a Git
   transport. It journals changes locally, coalesces and elides operations,
   groups commits, recovers after crashes, and applies path persistence policy.
3. **The daemon/VFS layer (Layer 5)** exposes inode-addressed FUSE operations
   such as lookup, getattr, readdir, open, read, write, rename, unlink, flush,
   and statfs. A background tick flushes dirty data and refreshes follower
   mounts.

### OctoBlock features

- **Git-backed persistence:** committed volume generations are represented by
  Git objects and refs, using the existing `octopage-git` transport.
- **Copy-on-write file system:** directories, files, extents, xattrs, hard-link
  limits, rename flags, sparse/unwritten extents, and POSIX-style errors are
  tracked in the `OBF1` page format.
- **Durable write-back modes:** `strict` waits for a remote `L2` commit on
  `fsync`, `balanced` (the default) waits for a local journal `L1` barrier,
  and `relaxed` keeps `fsync` at `L0` while background flushes run.
- **Crash-safe encrypted journal:** local journal records use checksums,
  segment rotation, recovery, and optional authenticated encryption. A full
  journal can fail with `ENOSPC` or transition the mount read-only.
- **Path-class persistence policy:** paths can be `persist`, `local`,
  `volatile`, or `exclude`. Volume policies live in
  `.octoblock/policy.toml`, while machine-local overrides may only make a path
  less persistent.
- **Multi-writer coordination:** writer leases and fencing prevent stale
  mounts from pushing after lease loss. Conflict detection records logical
  replay conflicts and exposes them through
  `.octoblock/conflicts/index.json`.
- **Branches and snapshots:** create and switch branches, create named
  snapshots, resolve historical views, and merge a source branch from a
  supplied base commit.
- **Quota and history management:** live bytes are charged against a soft
  budget (800 MiB by default), and `compact` archives an old generation before
  writing a squashed continuation.
- **Integrity and authenticity:** `fsck` validates the volume, remote page
  envelopes can be encrypted, commit metadata can be signed, and pinned
  signer fingerprints protect against unauthorized history.
- **Operational status:** mounts report state, role, durability, journal
  depth, remote head, epoch, quota usage, and lease information through
  `.octoblock/status` and JSON output.

### OctoBlock control plane

The `octoblock` binary provides the control-plane command surface:

```text
octoblock status [--json]
octoblock sync
octoblock compact [--no-archive]
octoblock branch list
octoblock branch create <name>
octoblock branch switch <name>
octoblock snapshot list
octoblock snapshot create <name>
octoblock merge <source-branch> <base-commit-sha>
octoblock lease status
octoblock lease break
octoblock conflicts
octoblock fsck
```

For example, the workspace binary can be exercised with:

```powershell
cargo run --release -p octoblock-wb -- status --json
cargo run --release -p octoblock-wb -- branch list
cargo run --release -p octoblock-wb -- snapshot create before-migration
cargo run --release -p octoblock-wb -- compact
```

The binary is the control-plane and dispatcher integration point; the
underlying `WriteBackEngine`, `FuseDispatcher`, `PolicyEngine`, lease manager,
conflict log, and compaction APIs are also available to Rust callers for
embedding in a mount daemon.

### OctoBlock persistence policy

An `OBF1` volume can define rules in `.octoblock/policy.toml`:

```toml
[[rule]]
match = "/**"
class = "persist"

[[rule]]
match = "/tmp/**"
class = "volatile"

[[rule]]
match = "/var/cache/**"
class = "local"

[[rule]]
match = "/secrets/**"
class = "exclude"
```

`persist` is journaled and committed to the remote, `local` is kept in a
machine-local sidecar, `volatile` is memory-only, and `exclude` rejects access.
The built-in Tier 1 policy provides common `/tmp`, `/run`, cache, and log
defaults; Tier 0 persists all user paths.

## Using the API

```rust
use octopage::{Database, params};

let db = Database::open(octopage::github("OWNER/NAME", Some(&token))?, Default::default()).await?;
tokio::task::spawn_blocking(move || -> octopage::Result<()> {
    let conn = db.connect()?; // SQLite is synchronous: use connections off the async runtime
    conn.transaction(|tx| {
        tx.execute("UPDATE acct SET balance = balance - ?1 WHERE id = ?2", params![10, 1])?;
        tx.execute("UPDATE acct SET balance = balance + ?1 WHERE id = ?2", params![10, 2])?;
        Ok(())
    })?; // run again automatically if another client's commit got in first
    let then = conn.query("SELECT * FROM acct AS OF '2026-09-01'", params![])?;
    Ok(())
});
```

Transactions see one time throughout (`datetime('now')`), and `random()` and `randomblob()` draw from a seed
the changelog records, so a re-run or a replay computes the same values. `conn.run_transaction(&statements)`
runs a list of statements as one transaction, re-running them after a refused commit; `conn.replay(&changelog)`
runs a commit's changelog again. Writers that keep losing races take the advisory writer lease
(`refs/octopage/lease`) and the others wait for them.

The Phase 5 gate on real git, for an hour:
`$env:OCTOPAGE_BANK_SECONDS = "3600"; cargo test --release -p octopage --test bank -- --ignored --nocapture`.

## Maintenance

```powershell
octopage --repo YOUR_USER/octopage-spike fsck        # check every page (and SQLite's integrity_check)
octopage --repo YOUR_USER/octopage-spike stats       # size, growth, days until the size budget
octopage --repo YOUR_USER/octopage-spike settings --retention "keep_days 30" --live-limit-mb 800
octopage --repo YOUR_USER/octopage-spike maintain --rollover never
octopage --repo YOUR_USER/octopage-spike workflows install --cli-source https://github.com/YOUR_USER/octopage
```

- **The workflow.** `workflows install` commits `.github/workflows/octopage-maintenance.yml`. It runs
  `octopage maintain` weekly:
  - removes abandoned staging refs;
  - scans every page;
  - opens an issue two weeks before the repository reaches its size budget;
  - deletes a previous generation after its grace period;
  - rolls over when needed.
- **Its secrets**, both optional:
  - `OCTOPAGE_ADMIN_TOKEN`: a token that may create and delete repositories, for rollovers;
  - `OCTOPAGE_PASSPHRASE`: for full scans of an encrypted database.
- **Rollover.** `octopage rollover` moves every database in the repository to `NAME-g2` (then `-g3`, …),
  keeping only the history each one's retention keeps. Running clients follow by themselves.
  - Clients' tokens must be able to reach the new repository. A fine-grained token limited to selected
    repositories needs it added.
  - The old repository stays for the grace period (7 days by default).
- **Other commands:**
  - `octopage migrate --page-size 16384` moves a database to other pages in the same way; clients then open it
    again.
  - `octopage reconcile` repairs a history someone rewrote by hand.

## Python, Node and C

Each opens `OWNER/NAME` on github.com, the URL of any smart-HTTP git remote, or `:memory:`.

```python
import octopage  # DB-API 2.0; built with maturin from crates/octopage-python

conn = octopage.connect("OWNER/NAME", token, branch="main")
conn.execute("INSERT INTO notes(body) VALUES(?)", ("from Python",))
conn.commit()  # a git commit; conn.head is its id
rows = conn.execute("SELECT * FROM notes").fetchall()
```

```js
const { Database } = require('octopage'); // napi-rs: crates/octopage-node

const db = await Database.open('OWNER/NAME', { token, branch: 'main' });
const conn = await db.connect();
await conn.transaction(async (tx) => {  // runs again if another client's commit got in first
  await tx.execute('UPDATE acct SET balance = balance - 10 WHERE id = 1');
  await tx.execute('UPDATE acct SET balance = balance + 10 WHERE id = 2');
});
const notes = await conn.query('SELECT * FROM notes WHERE id = ?', [1]); // [{ id, body }]
```

- Python: calls release the GIL while the database works. Errors are the PEP 249 classes, plus
  `ConflictError` for a commit another client's beat.
- Node: every call returns a promise and runs on libuv's thread pool. Errors carry a `code` (`conflict`,
  `constraint`, `sql`, `locked`, …).
- C: `crates/octopage-ffi` builds a shared library, with the header generated at
  `crates/octopage-ffi/include/octopage.h` (`octo_open`, `octo_connect`, `octo_execute`, `octo_query`,
  `octo_run_transaction`, …). Every function returns a status; `octo_last_error()` says why.

## The service

`octopage-server` is the hosted API: users sign in with GitHub and install the OctoPage GitHub App on their
repositories, and applications call it with API keys. It serves the dashboard (`web/dashboard`, built with
`npm run build`) when `OCTOPAGE_DASHBOARD` points at it. Fly.io deployment is configured by `Dockerfile` and
`fly.toml`; the SDKs for calling it are in `sdk/typescript` and `sdk/python`.

```powershell
$env:GITHUB_APP_ID = "123456"; $env:GITHUB_APP_PRIVATE_KEY_FILE = "app.pem"
$env:GITHUB_WEBHOOK_SECRET = "..."; $env:GITHUB_CLIENT_ID = "..."; $env:GITHUB_CLIENT_SECRET = "..."
$env:OCTOPAGE_KMS = "local:<64 hex digits>"    # or aws:<region>:<key id>
cargo run --release -p octopage-server
```

```text
POST /v1/databases                  {"repository": "OWNER/NAME", "branch": "main", "create": true}
POST /v1/databases/{id}/query       {"sql": "SELECT * FROM notes WHERE id = ?", "params": [1]}
POST /v1/databases/{id}/execute     one statement, one commit
POST /v1/databases/{id}/batch       statements as one transaction
POST /v1/databases/{id}/transactions, …/{tx}/execute, …/{tx}/commit, …/{tx}/rollback
GET  /v1/databases/{id}/log, branches, POST merge; /v1/keys; /healthz, /readyz, /metrics
```

- **Tokens.** The service reaches repositories with the App's installation tokens, minted when needed. It
  stores no user tokens. API keys are stored hashed.
- **Writes.** Each database has one writer connection, and the service's own writes queue for it instead of
  racing. Queries run on a pool of readers.
- **Keys.** An encrypted database's key is wrapped by the service's key service. Alternatively, the user
  supplies a passphrase per session (`/unlock`).
- **Isolation.** Each repository's pages are cached apart, and each installation's GitHub requests have a
  budget of their own (`OCTOPAGE_BUDGET_PER_HOUR`, 4000 by default).
- **Configuration.** The variables are listed in `crates/octopage-server/src/main.rs`, and the routes in
  `src/api.rs`. Service metadata is kept in SQLite in `OCTOPAGE_DATA`.

## In the browser

`web/octopage-browser` runs read-only SQL on a database in a public repository, with no server. SQLite's
WebAssembly build reads pages from GitHub's raw CDN as queries need them, and caches them in IndexedDB. See
the browser package source for usage details.

## Checking the transport against GitHub

With a fine-grained token that has *Contents: read and write* on a throwaway repo:

```powershell
$env:OCTOPAGE_GITHUB_TOKEN = "github_pat_..."
cargo run -p octopage-git --example github_check -- --repo YOUR_USER/octopage-spike
```

It uses temporary refs, deletes them at the end, and signs in only with that token.

## Trying the key-value store on GitHub

```powershell
$env:OCTOPAGE_GITHUB_TOKEN = "github_pat_..."
cargo run -p octopage-kv -- --repo YOUR_USER/octopage-spike --branch refs/heads/kv init
cargo run -p octopage-kv -- --repo YOUR_USER/octopage-spike --branch refs/heads/kv put greeting hello
cargo run -p octopage-kv -- --repo YOUR_USER/octopage-spike --branch refs/heads/kv get greeting
cargo run -p octopage-kv -- --repo YOUR_USER/octopage-spike --branch refs/heads/kv log
cargo run --release -p octopage-kv -- --repo YOUR_USER/octopage-spike soak   # the Phase 2 gate
```

## Running the SQL soak on GitHub

Three concurrent SQL writers on a temporary branch, then every check of the Phase 3 gate; the branch is deleted
at the end:

```powershell
$env:OCTOPAGE_GITHUB_TOKEN = "github_pat_..."
cargo run --release -p octopage-sqlite --example sql_soak -- --repo YOUR_USER/octopage-spike
```

Locally, the full gate is
`$env:OCTOPAGE_SOAK_PER_WRITER = "334"; cargo test --release -p octopage-sqlite --test soak -- --nocapture`, and
`$env:OCTOPAGE_MODEL_STEPS = "3000"` makes the differential test (`--test model`) run longer.

## Layout

```
crates/            Rust workspace (engine crates are added phase by phase)
  octoblock-fs/       OBF1 file-system core: copy-on-write trees, pages, fsck, and reference model
  octoblock-wb/       write-back engine, journal, policy, leases, conflicts, compaction, VFS, daemon, CLI
  octopage-git/        git objects, packfiles, and the GitHub transport (push, fetch, refs, REST, CDN)
  octopage-pagestore/  pages in git blobs, the fan-out page map, caches, transactions, rebase, staging
  octopage-kv/         a key-value store on the page store, the octopage-kv CLI, and the soak test
  octopage-sqlite/     SQLite on the page store through a VFS: catalog, read-ahead, the SQL soak
  octopage/            the database API: connections, transactions, changelog, AS OF; SQLite's logic tests
  octopage-ops/        maintenance: rollover, retention, integrity scans, hygiene, size, migrate, reconcile
  octopage-cli/        the octopage shell and the maintenance commands
  octopage-ffi/        the C ABI (and its generated header)
  octopage-python/     the Python binding (PyO3, DB-API 2.0)
  octopage-node/       the Node.js binding (napi-rs)
  octopage-server/     the multi-tenant HTTP service: GitHub App, tenants, keys, webhooks, metrics
  octopage-conformance/ the SQL suite every interface runs, and the browser test
  octopage-testkit/    test helpers: a local GitHub-shaped git remote, round-trip counting, fault injection
web/octopage-browser/  read-only SQL in the browser (SQLite's WebAssembly build in a worker)
web/dashboard/     the service's dashboard (React, TypeScript, Vite)
sdk/               HTTP clients for the service: typescript/ and python/
deploy/, Dockerfile, fly.toml   the service's image and its Fly.io deployment
spike/             Phase 0 measurement harness and findings
tools/             Development tools; local_git_remote.py serves a GitHub-shaped git remote for tests
.github/workflows/ ci.yml: format, lint, test, image build; deploy.yml; release.yml
```

## Checks

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p octoblock-fs -p octoblock-wb
python spike/octospike.py selftest
```

The binding, SDK, browser and dashboard tests need Python 3.9+, Node 22+, a C compiler, and Edge or Chrome. They
run `npm install` in `web/octopage-browser`, `web/dashboard` and `sdk/typescript` the first time. OctoBlock's
multi-node chaos and end-to-end stress coverage is included in the `octoblock-wb` test suite.
