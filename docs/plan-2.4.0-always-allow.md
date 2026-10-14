# Plan 2.4.0 — persistent "always allow" with clamped wildcard profiles

Status: rev 2 — validated 2026-10-14, approved decisions in §7. Nothing here is implemented yet.

Evidence behind rev 2 (run folder `.delegate-kit/runs/always-allow/`): `core-design.md`,
`design-review.md`, `validate-git.md` (C1–C11), `validate-docker.md` (D1–D9),
`validate-kubectl.md` (K1–K8). References like "C3" or "D6" below point at those files.

## 1. What the user asked for

- A persistent list of commands that `run_with_env` auto-allows without a password prompt,
  surviving server restarts.
- **Every** successful master-password unlock (any tool) arms the list for that server process.
- Entries live **until manually changed** (no expiry, no 8 h re-arm).
- Wildcards, but only in a safe, clamped way, and only for git, docker and kubectl.
- Hooks and the user's own config must keep working "like a normal push".

**Truth in labelling (governs every dialog, tool result and doc string).** For an always-allow
entry the agent CAN obtain the injected values: hooks run the agent's tests, docker containers can
be inspected/logged, kubectl objects in the namespace can be queried. The pins in §4/§5 bound the
blast radius to the entry's `only_vars` and the approved remote/endpoint/cluster; they do not hide
the values. Every dialog and result says "the agent can obtain these values" and recommends
test-grade credentials.

## 2. Storage and integrity

- The list lives in the vault body under the reserved key `#always_allow`
  (`store.is_reserved_key`, `store.py:2074`; prefix `#`, `store.py:99`), sealed by the vault's
  AES-GCM: tampering makes the vault fail to open (`VaultTampered`); no separate hash/HMAC file.
  A plain hash next to a plaintext list was rejected (whoever edits the list recomputes it).
- Writing an entry re-encrypts the vault, so only a human with the password can add one.
- **Entry model**: `{id, kind, label, cwd, only_vars (sorted), shape, snapshot, created (ISO)}`;
  `id = sha256(canonical_json(kind, cwd, only_vars, shape))[:12]` (re-approval upserts the
  snapshot). `label` is server-generated (§4 anti-spoofing). `cwd` is the realpath-pinned
  directory. Optional per-entry fields: `monitored_paths` (exact kind, §5.0).
- **Rollback protection** (decision 7). Rolling `vault.enc` back to an older copy would silently
  re-arm an older list (the agent can copy files), so:
  - a second reserved key `#generation` (int) is part of the body. `_write_body_locked` bumps it on
    **every** body write (secrets included), never lowers it;
  - last-seen generation is kept (a) in memory for the process and (b) in a **sidecar file outside
    the vault directory** (`rollback.py`: per-user state dir, name derived from the vault salt
    hash; content `{vault_id, generation}`; no secrets; atomic replace). The sidecar is updated
    after each successful decode/write and never lowered;
  - on every unlock: `generation < max(memory, sidecar)` → **refuse to arm** (the vault itself
    still opens), warn in the tool result ("vault.enc is older than the last state this machine
    saw — always-allow entries were NOT armed; restore the newest copy or re-approve"), and keep
    refusing until a write by a human-approved flow raises the generation past the last-seen one;
  - first run after upgrade (no `#generation`) treats it as 0 and writes 1 on the next write;
    a missing sidecar with generation ≥ 1 is accepted (and the sidecar recreated) but noted in
    the unlock dialog;
  - **every unlock dialog lists the entries it is about to arm** (label + kind + vars), so an
    unexpected entry is visible to the human.
  - Residual: an attacker that also deletes the sidecar and restarts the server defeats this
    (§6); it raises the bar from "copy one file" to "also edit state the server holds in memory".
- Arming values live only in the per-process trust cache, encrypted (§4 "Memory").
- `manage_vault` listing returns **only** `id, kind, cwd, shape, label` — never snapshot hashes,
  remote URLs, kubeconfig material or hook inventories (resolves core-design OPEN item).

## 3. Lifecycle

1. **Add**: the `run_with_env` dialog gets a second checkbox "Always allow (survives restarts)"
   beside the 8 h one. **Unchecked by default**; the canonical pattern line (e.g.
   `git push origin <branch>`), the findings, the "the agent can obtain these values" notice and
   the approval-time snapshot summary (§5) are visible before the checkbox can be ticked
   (checkbox disabled until the pattern frame is rendered). After **3 denials of the same
   signature within 30 min** the checkbox is hidden for that signature for 30 min (cool-down;
   constants in `allowlist.py`). Always-allow wins over 8 h when both are ticked.
2. **Arm**: after a successful **master-password** unlock in this process (§4 "Arming"),
   `#always_allow` is read; each entry whose `check_snapshot` passes and whose rollback check
   passes is loaded into the trust cache (`trust.arm`) with only its `only_vars` values. Entries
   whose `kind` is unknown or whose snapshot no longer holds are disarmed with a reason.
3. **Use**: a matching call auto-allows (request `only_vars` ⊆ entry `only_vars`; only the
   request's subset is injected). Any snapshot mismatch → the normal dialog, which explains what
   changed; approving it re-snapshots the entry.
4. **Revoke**: `manage_vault` actions `always_allow_list` / `always_allow_remove`
   (password-gated: the list is inside the ciphertext). Remove rebuilds the armed set
   synchronously from the post-write body (§4 "Arming").

Never eligible (any tier, including exact): runs with `files`, `all_vars=True`, `background=True`,
`max_reads`, `materialize`; an empty `only_vars` (already refused at `mcp_server.py:1765`).
**Q7 check**: that refusal runs before matching and stays untouched; no entry can be created or
matched with zero vars, and a test asserts `only_vars=[]` never reaches `find_match`/auto-allow
(today it returns an error before any dialog opens; that is the required behaviour).

## 4. Common mechanics for every profile

- **Binary pin** (`profiles/_common.py: resolve_pinned_binary`): resolve the tool to an absolute
  path at approval (Windows: no cwd/PATH search of `.`; `.exe` only), record its SHA-256, execute
  that path, and re-hash before spawn. Mismatch → dialog. Any helper executables (credential
  helpers, hook runners recorded by the profile, compose plugin, kubectl exec plugin) are
  resolved to absolute paths and hashed the same way.
- **Env built from scratch** (`build_env`), not scrubbed: system essentials (`SystemRoot`,
  `windir`, `COMSPEC`, `PATHEXT`, `TEMP`/`TMP`, `USERPROFILE`/`HOME`/`HOMEDRIVE`/`HOMEPATH`,
  `APPDATA`/`LOCALAPPDATA`, `LANG`), a pinned `PATH` (approval-time list of system directories
  only; no user-writable entries), plus the request's `only_vars` values. Each profile adds its
  own pinned variables. `verdict.replace_env=True` makes this the complete child env.
- **Tool-control name denylist** (`store.is_tool_control_name`): an entry is refused (and
  `add_secret` refuses **new** names — existing secrets are never renamed, they just become
  ineligible for always-allow) when a vault var name is, case-insensitively:
  exact `PATH`, `PATHEXT`, `HOME`, `HOMEDRIVE`, `HOMEPATH`, `USERPROFILE`, `APPDATA`,
  `LOCALAPPDATA`, `TMP`, `TEMP`, `SYSTEMROOT`, `WINDIR`, `COMSPEC`, `REQUESTS_CA_BUNDLE`,
  `KUBECONFIG`, `KUBERC`, `CURL_CA_BUNDLE`; or prefix `GIT_`, `GCM_`, `DOCKER_`, `COMPOSE_`,
  `BUILDKIT_`, `BUILDX_`, `KUBE`, `KUBERNETES_`, `DOTNET_`, `XDG_`, `LD_`, `DYLD_`, `PYTHON`,
  `NODE_`, `SSL_CERT_`, `CURL_`, `SSH_`; or suffix `_PROXY`. (CHANGELOG: new behaviour at
  `add_secret`; tests cover both enforcement points.)
- **Argv grammar** (`tokenize_argv`): tokenised by the profile parser; every element must match a
  slot or an allowlisted flag. Spellings are fixed per flag: long value flags only as
  `--flag=value`; short value flags only as `-x VALUE` (two tokens). `-xVALUE`, `-x=VALUE`,
  `--flag VALUE`, flag-prefix abbreviations → dialog; the rewritten argv uses the canonical
  `--flag=value` form where a long name exists (K7: kubectl accepts `-nfoo`, `-n=foo`, `-o=name`,
  `-lapp=x`). No repeated flags, no NUL/CR/LF, no element starting with `-` unless allowlisted, no
  `@file`, no `--` from the agent (the server emits `--` where needed). Anything else → dialog
  (never a hard error, so the human can still approve a one-off run).
- **Version floors** (`vercmp`, refuse auto-allow below them; the normal dialog still works):
  - git: `git --version` numbers (ignore `.windows.N` suffix) must be **≥ 2.50.1, or** on a
    patched maintenance line: 2.43 ≥ .7, 2.44 ≥ .4, 2.45 ≥ .4, 2.46 ≥ .4, 2.47 ≥ .3, 2.48 ≥ .2,
    2.49 ≥ .1 (CVE-2025-48384, C11). Git for Windows numbering of the backports is unverified;
    implementer checks, floors live in one table. This machine has 2.45.1 → refused until
    upgraded.
  - Docker Compose: compare the tuple `(major, minor, patch) >= (2, 40, 2)` on
    `docker compose version --short` (strip leading `v`, ignore any `-desktop.N`-style suffix);
    every 5.x passes (D4; CVE-2025-62725; 3.x/4.x never existed). Never compare as strings.
  - Docker Desktop ≥ **4.44.3** (only checked when the server is Docker Desktop; read from
    `docker version --format '{{.Server.Platform.Name}}'`, e.g. `Docker Desktop 4.88.1 (237512)`;
    implementer confirms the field). BuildKit ≥ 0.12.5 (build tier only).
  - kubectl: any version; the kuberc credential-plugin policy is used only on ≥ 1.35, below which
    exec plugins are refused outright (K3).
- **Probes** (`run_probe`: every read-only helper command the profile runs to snapshot/verify:
  `git config`, `git remote get-url`, `docker compose config`, `docker context inspect`,
  `kubectl config view`, …): no vault secrets in env (sentinels where the profile needs
  interpolation), the **same pins and from-scratch env as the real run**, the pinned binary,
  cwd = a vault-owned empty directory (use `git -C`, `--project-directory`, stdin input for
  kubectl; also defeats Windows DLL side-loading from cwd), stdin closed, wall-clock timeout,
  stdout/stderr size cap, and **output never shown to the agent** (only derived verdicts/hashes
  and the human-facing dialog). Probes run only after the raw-file scans in §5.2 where applicable
  (D1: `compose config` itself fetches remote includes).
- **Re-check right before spawn** (`match.recheck()`), not only at arm time. Pins passed on the
  command line (`-c`/`GIT_CONFIG_*`, `--kubeconfig=`, `-f -`) close the TOCTOU window completely
  where possible; the remainder is listed in §6.
- **cwd and DLLs**: the entry's `cwd` is pinned by realpath (junction/symlink/8.3-name/case
  resolved via final-path-name; comparisons casefolded); a reparse point at `.git` is refused. On
  Windows `*.dll` files in the cwd (names + SHA-256) are snapshotted at approval and verified
  before spawn; profiles prefer the vault-owned cwd where the tool allows.
- **Dialog anti-spoofing**: the label is generated by the server (never taken from the agent);
  argv elements shown with `repr`-style escaping; any argv/cwd/label text containing bidi
  controls, zero-width characters or other non-printables (Unicode categories Cc, Cf, Cs, Co,
  Cn, Zl, Zp, plus U+2028/2029) makes the command ineligible for always-allow (the dialog still
  appears, escaped); the canonical pattern the entry will match is displayed, not just the
  literal command.
- **Redaction for armed values** (`mcp_server._redact_secrets`, `mcp_server.py:197`): for values
  injected by an always-allow match, additionally redact base64 (standard and urlsafe, padded and
  unpadded), hex (lower and upper), URL-encoded (`quote` and `quote_plus`), and the
  `upper()`/`lower()` forms of the raw value. Output of an always-allowed run is capped at
  **256 KiB per stream** (named constant; the truncation is reported in the result). Redaction
  stays best-effort (§6).
- **Memory**: `trust.py` replaces the xor obfuscation of cached values with a **per-process
  AES-GCM session key** (random 256-bit, never written to disk); values are decrypted only for the
  duration of a run and dropped afterwards (best-effort zeroising); the password and DEK are never
  retained.
- **Arming rules** (`store._notify_unlocked(body, fingerprint, method)`): the notify carries the
  unlock method (`"password"` or `"recovery"`). Recovery-key sessions never arm, **including the
  writes performed inside that session** (the method is propagated through `_write_body_locked`).
  Add/remove re-arm from the **post-write body**; remove disarms synchronously by rebuilding the
  whole armed set from that body, so a removed entry cannot stay armed.
- **Test-only relaxations** (needed because the dev machine fails the floors and tests use local
  bare repos / fake APIs): exposed as module-level attributes of `profiles/_common.py`
  (`RELAXATIONS`, default all-strict), changed only by test monkeypatching — no env var, no config
  file, no runtime switch. They are: git allowed protocols (default `"https"`; tests `"file:https"`
  with a local bare repo as remote, C7), skipping the https-only URL check, injecting version
  floors, skipping the "executable dir not user-writable" check, and kubectl accepting
  `http://127.0.0.1:<port>` servers (fake API). A test asserts the defaults are strict.

## 5. Profiles

### 5.0 exact (non-profile) entries — decision 5

Same keys as today's 8 h trust (`make_signature`, normalised to JSON) plus the stricter program
rules below. Argv is matched exactly; there are no wildcards.

- argv0 must be a **native PE (Windows) or ELF/Mach-O (POSIX) executable**: magic checked
  (`MZ` + PE signature / `\x7fELF`). Resolved to an absolute path **once, at approval** (Windows:
  PATH walk that skips `.`/relative entries and never searches cwd), SHA-256 recorded, executed by
  that absolute path and **never re-resolved**. The executable's directory (and the file) must
  not be user-writable (POSIX: not writable by the current uid and every parent root-owned;
  Windows: no write ACE for the current user / Users / Authenticated Users / Everyone). If the
  check cannot be performed → ineligible (fail closed).
- **Refused argv0**: shells/interpreters (`sh bash zsh dash cmd powershell pwsh py node perl ruby
  wsl`, `python*`) and the launcher denylist: `npm npx yarn pnpm bun deno pytest tox nox cargo make
  cmake ninja gradle gradlew mvn mvnw dotnet go uv poetry pipx pre-commit just task rake bundle
  composer java` (basename, `.exe` stripped, case-insensitive).
- **`.cmd` / `.bat` / `.ps1` argv0 are refused for every trust tier** (BatBadBut / `%VAR%`
  expansion via cmd.exe; `shutil.which` may resolve from cwd). This **includes the existing 8 h
  trust**: it is a behaviour change to call out in CHANGELOG and README. Interpretation: no trust
  of any kind (8 h or always) is offered or matched for such a command; a single dialog-approved
  run is unaffected.
- Windows only: `*.dll` in cwd snapshotted (§4).
- Optional per-entry **`monitored_paths`**: files/directories hashed at approval and verified at
  arm/recheck (drift → dialog). A built-in table pre-fills suggestions by argv0 basename: `gh`
  (its config dir, `GH_CONFIG_DIR` default), `aws` (`~/.aws/config`, `credentials`), `az`
  (`~/.azure`), `terraform` (`.terraformrc`, `terraform.rc`, `.terraform.d/plugins` listing),
  `curl` (`.curlrc`, `_curlrc`, `.netrc`). Table contents are indicative; implementer finalises.
- **Blunt warning line** in the dialog and tool result: "Exact entries pin the command line, not
  what the program does with the variables: its own config files, plugins and the files it reads
  can change its behaviour, and the agent can obtain these values."

### 5.1 git — `push`, `pull`, `fetch`, `ls-remote` (never `clone`)

Grammar (no agent tokens before the subcommand; no aliases). Final argv always carries `--`
before the remote (C8: `git fetch -- origin`, `git pull -- origin main` verified; push
`git push [-u] [--dry-run] --atomic -- origin refs/heads/main:refs/heads/main` is **NEEDS-IMPL-TEST**
because push was blocked during validation).

| Sub | Allowed | Rejected (→ dialog) |
|---|---|---|
| push | `[-u] [--dry-run] [--atomic] [--porcelain] <remote> <branch>...` — server rewrites each branch to `refs/heads/N:refs/heads/N` | `--force`, `-f`, `--force-with-lease*`, `--force-if-includes`, `--delete`, `--mirror`, `--all`, `--prune`, `--tags`, `--follow-tags`, `--repo`, `--receive-pack`, `--exec`, `--signed`, `-o`, `--push-option`, `--recurse-submodules`, `--no-verify`, any `+`/`:`/`*` refspec |
| fetch | `[--no-tags] [--tags] [--depth=N] <remote>` | `--upload-pack`, `--recurse-submodules`, `--multiple`, `--all`, `--refmap`, `--prune` |
| pull | `<remote> [<branch>]` — server adds `--ff-only --no-rebase --no-edit --no-recurse-submodules` | every flag |
| ls-remote | `[--heads] [--tags] [--refs] <remote>` | `--upload-pack`, `--exec`, patterns |

- Remote slot: `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, no `..`, no `.lock`, no trailing `.`. This is
  strictly narrower than git's own rules (C8). **The server must verify the remote is configured**:
  `git fetch -- nosuch` treats `nosuch` as a path/URL. Never a URL or path.
- Branch slot: `^[A-Za-z0-9][A-Za-z0-9_./-]{0,200}$` plus: no `..`, `//`, `/.`, `@{`, `.lock`
  suffix, trailing `/` or `.`; not `HEAD`/`@`. Optional per-entry branch glob (e.g. `feature/*`).
- **Pull** (C6): `--ff-only --no-rebase` suffices (no rebase, no merge commit, no `pre-rebase`
  hook even with `pull.rebase=true`); the `pull.rebase=false` pin is belt-and-braces.
- **Remote URL check** (not a pin — see conflict note below). Approval records the exact normalised
  URL (`https://github.com/owner/repo.git`; https only, no userinfo/port/`%`). Immediately before
  spawn, using the **same command-scope pins and env as the real run** (C3), run
  `git remote get-url --all <r>` (fetch/pull/ls-remote) and `git remote get-url --push --all <r>`
  (push): the output must be **exactly one line equal to the approved URL**. `--all` is mandatory:
  `remote.<r>.url`/`pushurl` are multi-valued, a second value is shown only with `--all`, and
  `git push` pushes to **all** of them; `insteadOf`/`pushInsteadOf` apply to both and are caught.
  *Conflict resolved*: design-review item 5 asked to pin `remote.<n>.url`/`pushurl` at command
  scope, but C3 shows a command-scope value **adds** a second URL rather than replacing. So the
  protection is: check-with-`--all` + the local-key allowlist below (local `pushurl`, `url.*`
  are refused) + hashed global/system config. The residual window is `.git/config` edited between
  check and spawn (§6).
- **Command-scope pins** via `GIT_CONFIG_COUNT/KEY_n/VALUE_n` (C1: beat local and global; command
  scope is always last): `core.fsmonitor=false` (C4: fetch/pull otherwise execute it),
  `core.sshCommand=` (empty), `core.pager=cat`, `core.editor=true`, `core.askPass=`,
  `core.hooksPath=<approved absolute path>`, `protocol.allow=never`, `protocol.https.allow=always`,
  `http.proxy=`, `http.extraHeader=`, `submodule.recurse=false`, `push.recurseSubmodules=no`,
  `fetch.recurseSubmodules=no`, `push.pushOption=`, `pull.rebase=false`, `push.gpgSign=false`,
  `transfer.credentialsInUrl=die`, `gc.auto=0`, `maintenance.auto=false`. Env adds
  `GIT_ALLOW_PROTOCOL=<allowed protocols, default "https">` (overrides config entirely, C7; tests
  use `file:https`), `GIT_TERMINAL_PROMPT=0`, `GIT_PROTOCOL_FROM_USER=0`. Plain local-path remotes
  are refused under `https`.
- **credential.helper** (C2): pinned as `credential.helper=` (empty reset) followed by one
  `credential.helper=<value>` per helper of the **effective ordered list recorded at approval**
  (global/system plus url-specific entries for the approved URL), each helper normalised to an
  absolute program path (git uses a leading absolute path as-is) and the binary hashed.
  `!shell` helpers and helpers that cannot be resolved → ineligible. The reset removes every lower
  helper including url-specific ones, but **config queries cannot prove it** (`--get-urlmatch`
  ignores the reset): verify behaviourally in an implementation test (loopback 401 server and
  marker-writing helper scripts, as in C2), never via `git config`.
- **Hooks run normally** (user requirement): `core.hooksPath` is pinned to the approved directory
  (today `C:/Users/josep/.config/review-gate/hooks` globally, or `.git/hooks`), and that tree is
  fingerprinted (names, modes, sizes, SHA-256; symlinks rejected if they escape). Change → dialog.
  Test (**NEEDS-IMPL-TEST**, C5): bare remote, pinned `hooksPath` with a `pre-push` marker hook, a
  conflicting local `core.hooksPath` hook → only the pinned one fires, argv = remote name + approved
  URL, stdin lists `refs/heads/N:refs/heads/N`. (Fetch/pull with pinned hooksPath confirmed: local
  hooks do not run.)
- **Config snapshot** — parse `git config --list --show-origin --show-scope -z` (C10) with
  `parse_git_config_z`:
  - record = `SCOPE NUL ORIGIN NUL KEY ["\n" VALUE] NUL`; scope ∈ {system, global, local, worktree,
    command}; origin = `file:PATH` or `command line:`; split VALUE only on the **first** `\n`;
    valueless key (no `\n`) is `None`, `key\n` + NUL is `""` — keep them distinct; section and
    variable names lower-cased, subsection case preserved; **last value wins per key** (shadowed
    lower-scope values are all listed; command scope last); included files keep the includer's
    scope and have their own origin; relative local origins (`file:.git/config`,
    `file:.git/../inc2.cfg`) resolve against the **work-tree top level**, not cwd; `includeIf` is
    already evaluated by git.
  - local/worktree scope may contain only the benign allowlist: `core.repositoryformatversion|
    filemode|bare|logallrefupdates|symlinks|ignorecase|autocrlf`, `remote.<r>.url|fetch`,
    `branch.*.remote|merge`, `user.*`, `extensions.*`. Any other local key (filters, merge/diff
    drivers, aliases, `url.*`, `pushurl`, `credential.*`, `submodule.*.update`, includes) → dialog;
    this applies regardless of pins (C9: a remote `.gitattributes` can name any local driver and a
    pin only overrides known names).
  - global/system keys that cannot be pinned are hashed, plus every `--show-origin` file,
    `.gitattributes`, `.git/info/attributes`, `.gitmodules`, `.lfsconfig`. `.git` must be a
    directory (no gitdir redirect, no reparse point), no `core.worktree`. `include.path`/UNC paths
    can trigger SMB authentication during probes → probe timeout, and UNC include paths refused.
  - `git remote`/`git config` probes do not trigger fsmonitor or hooks (Q6) but still run with the
    pinned env.
- **Env** is built from scratch (§4); the following are never passed (listed for tests):
  `GIT_CONFIG*` (except our own), `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`,
  `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_NAMESPACE`, `GIT_COMMON_DIR`,
  `GIT_EXEC_PATH`, `GIT_SSH*`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PROXY_COMMAND`,
  `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `PAGER`, `*EDITOR`, `VISUAL`, `GIT_TRACE*`, `GIT_SSL_*`,
  `GIT_CURL_*`, `SSL_CERT_*`, `CURL_CA_BUNDLE`, `*_proxy`, `XDG_CONFIG_HOME`, `GCM_*`, `GH_HOST`,
  `GH_CONFIG_DIR`, `GH_PATH`, `GH_ENTERPRISE_TOKEN`, `LD_*`, `DYLD_*`.
- Optional (Q5, not required): per-entry "clean worktree and pushed tip == HEAD" check for
  auditability. The dialog recommends test-tier vars (decision 2).

### 5.2 docker — compose lifecycle + image pull/push

- **Endpoint pin**: approval resolves the endpoint with `docker context inspect --format
  '{{.Endpoints.docker.Host}}'` run with `DOCKER_*` removed from env (D3: `DOCKER_HOST` otherwise
  leaks into `context inspect default`). Allowlist `npipe:////./pipe/docker_engine` /
  `npipe:////./pipe/dockerDesktopLinuxEngine` / `unix:///var/run/docker.sock` / rootless socket.
  The server always passes it as `-H <endpoint>` (D3: `-H` beats the current context for compose
  and build). Env drops `DOCKER_*`, `COMPOSE_*` (incl. `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME`),
  `BUILDKIT_*`, **`BUILDX_*`** (D3: `BUILDX_BUILDER` is honoured), proxies,
  `DOCKER_CONTENT_TRUST*`.
- **Plugin shadowing fix** (design-review 4): `~/.docker/cli-plugins/docker-compose.exe` would beat
  Program Files, so every docker invocation runs with `DOCKER_CONFIG=<vault-owned dir>` containing
  **only** a generated `config.json` (`auths` hosts with empty objects, `credsStore`,
  `credHelpers`; **no** `plugins`, `cliPluginsExtraDirs`, `proxies`, `HttpHeaders`, `contexts`,
  `cli-plugins`) plus the pinned `PATH` (system Docker dirs, which hold credential helpers).
  Inline credentials in `auths` (`auth`, `identitytoken`) → ineligible (credentials must come from
  the OS credential store). Additionally the actual compose plugin path is resolved
  (`docker info --format '{{json .ClientInfo.Plugins}}'`, run with the same DOCKER_CONFIG) and must
  sit in a system directory that is not user-writable; its SHA-256 is pinned.
- Allowed shapes (flag spellings per §4):
  - `docker compose [-f <file>]... [-p <name>] [--profile <p>]... up|down|pull|ps|logs [flags] [<service>...]`
  - `docker compose build [--pull] [--no-cache] [-q] [<svc>...]` (build tier, below)
  - `docker pull|push [--platform=<os/arch>] [-q] <image>`
- Compose global flags: `-f` (local regular file inside the project root, from the approved set),
  `-p` (= approved, `^[a-z0-9][a-z0-9_-]{0,62}$`), `--profile` (approved set), `--ansi`,
  `--progress`, `--dry-run`. Rejected: `--env-file`, `--project-directory` (the server adds it),
  `--compatibility`, `--parallel`, `--all-resources`, `-H`, `--context`, `--config`, `--tls*`.
- `up`: `-d --wait --wait-timeout --no-build --pull --no-recreate --force-recreate --no-deps
  --quiet-pull --no-color -t/--timeout --remove-orphans` (+ `--build` only in the build tier).
  Rejected: `-w/--watch`, `--menu`, `-y`, `--scale`, `--exit-code-from`, and the flags that exist
  in current Compose but are not in the grammar (D8): `--abort-on-container-exit/-failure`,
  `--always-recreate-deps`, `--attach`, `--attach-dependencies`, `--no-attach`, `--no-log-prefix`,
  `--no-start`, `--quiet-build`, `-V`, `--timestamps`.
- `down`: `-t/--timeout --remove-orphans` (no `-v/--volumes`, `--rmi`). `logs`: `-n/--tail=N
  --since --until -t/--timestamps --no-color --no-log-prefix` (no `-f`, `--index`). `pull`:
  `-q/--quiet --policy --ignore-pull-failures`. `ps`: `-a/--all --format --status` (no `--filter`,
  `--no-trunc`, `--orphans`, `-q`, `--services`). Service slot `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`,
  must exist in the model. docker `pull/push`: `--platform -q/--quiet` (no `-a/--all-tags`).
- **Raw-file scan first** (before any `compose config`, since `config` itself fetches remote
  includes, D1/D4; CVE-2025-62725). Parse YAML of each approved `-f` file and **recurse through the
  local include/extends chain** (`include[]` as string | `{path: string|list}`; `extends.file`). Refuse
  non-local references: `^[A-Za-z][A-Za-z0-9+.-]*://` (oci://, https://, git+…),
  `^[\w.-]+@[\w.-]+:`, `^(github|gitlab|bitbucket)\.com/`, `\.git(#|$)` in `include`,
  `extends.file`, `build`, `build.context`, and any `additional_contexts` value that is not a plain
  relative/absolute directory (https tarballs, `docker-image://`, `oci-layout://` all refused).
  The same patterns are re-applied to the interpolated JSON `build.context`/`additional_contexts`.
- **Trust anchor and TOCTOU approach (single approach; reconciles design-review item 5 with D2/D6)**:
  - **Anchor** = SHA-256 of the **sentinel-interpolated** model: `docker compose -H … --project-directory
    <project dir> <approved -f/-p/--profile flags> config` (default YAML output, D1/D2) run with every
    vault var in `only_vars` set to a constant, **distinct per-var sentinel**
    (`__VAULT_SENTINEL_<NAME>__`; real values are never printed). Covers `.env` of the project dir,
    overrides, parent discovery, `include`, `extends`, `env_file` (D1; with explicit `-f` the
    override file is not auto-loaded). Also recorded: SHA-256 of the same run with
    `--format json` (the lint input; both must match at recheck). Never `--no-interpolate`
    (D6: valueless `args: [X]` vanish from it) and never `config --environment`.
    `config` fails on sentinel in a typed field (`ports: ["${PORTV}:80"]`) → fail closed → dialog.
    stdout only (unset-variable warnings go to stderr).
  - **Execution**: right before spawn the server runs the sentinel twin **S**, then the
    real-value config **R** (same flags, real values for `only_vars`, output held only in memory,
    never logged/shown), then the sentinel twin **S′** again; it requires
    `hash(S) == hash(S′) == approved hash` (files cannot change unnoticed between S and R's reads
    beyond a read that would have to flip back) and then pipes **R** on stdin: `docker compose -H …
    --project-directory <approved dir> -p <approved name> -f - up …` (D2: faithful round trip,
    `$` escaped as `$$`, env_file inlined). `up`/`build` children get **no vault vars in env**
    (the values are already inside R). Non-`up` subcommands (`down`, `ps`, `logs`, `pull`,
    `build`) pipe **S** instead and receive no secrets at all. Registry auth comes from the OS
    credential store via the pinned helper.
  - Not covered (§6): bind-mounted directory contents, the Dockerfile and build context (the
    agent's own code, run without secrets), the images used by non-built services.
- **Model lint** (on the interpolated JSON of the approved sentinel run). Normalise before
  comparing: backslashes → `/`, casefold, `~` expanded, `//var/run/docker.sock` ≡
  `/var/run/docker.sock`, npipe source `\.\pipe\docker_engine` ≡ `//./pipe/docker_engine`.
  - *Class A — entry cannot be always-allowed* (one-off dialog run still possible): a sentinel
    anywhere under `services.*.build` (args, context, dockerfile, target, labels, …); any
    `build.secrets` source mapped to a top-level `secrets.<s>` whose `environment:` names a vault
    var (D6: output shows the var name, not the sentinel) or whose `file:` is set;
    `build.privileged`, `build.entitlements`, `build.network: host`; remote build contexts or
    `additional_contexts` (above); a Dockerfile `# syntax=` directive (CVE-2024-23653) — scan from
    the top of each buildable Dockerfile while lines match `^\s*#\s*(\w+)\s*=\s*(.*)$`, refuse on
    `(?i)^\s*#\s*syntax\s*=`, covering BOM/CRLF, `build.dockerfile_inline` and named
    `build.dockerfile` (D7); `--build-arg`, `--ssh`, `--secret`, `--push`, `--builder`.
  - *Class B — findings shown in the dialog with a warning marker, human-approved, hash-bound* (any
    change re-prompts): `privileged`, `cap_add`, `devices`, `device_cgroup_rules`, `gpus`,
    `network_mode`/`userns_mode: host`, `pid`/`ipc`/`uts`/`cgroup: host`, `cgroup_parent`,
    `security_opt`, `runtime`, `sysctls`, `volumes_from`, `credential_spec`, `use_api_socket`,
    `provider`, `models`, `post_start`/`pre_stop`, `develop.watch[].exec`; bind mounts (long and
    short forms both normalise to `type: bind`) of `/`, drive roots, home, the docker socket/pipe,
    or **any host bind mount, labelled "code reaches secrets"** (design-review 1); `type: npipe`;
    top-level `volumes.<v>.driver`/`driver_opts` (D5: a named volume with `o: bind, device: /`
    bypasses the bind lint); top-level `secrets.<s>.file` and `configs.<c>.file` (host-file reads).
- **Secrets only where needed**: vault vars are used only in the `config` run that produces R for
  `up` (and `up --build`); `pull`, `push`, `ps`, `logs`, `down`, `build` get none.
- **No image pinning** (decision 6): the lint does **not** require `image@sha256:` digests. The
  approval dialog and the tool result state: "Containers for non-built services run images the
  vault does not pin, and the agent can read container env and logs."
- **Build tier** (decision 3): `compose build [--pull] [--no-cache] [-q] [<svc>...]` and
  `up --build`, limited to the entry's approved buildable-service list (every service that would
  build must be in it). D6: because `compose up` builds an image that is missing even without
  `--build`, **every service with a `build:` section counts as buildable for `up`** unless
  `--no-build` is given. Build children get no vault vars (R/S piped as above) and the Class A
  lint guarantees no vault value is referenced under `build`. BuildKit gets no host env
  implicitly (D6 confirmed). v5 `compose build` delegates to Bake; no extra flags allowed.
- **Image slot** (`docker pull|push`): parsed by a port of distribution/reference; registry host
  exact-allowlisted (docker.io aliases normalised), namespace prefix allowlisted, tag regex per
  entry; `push` tag pattern excludes `latest` unless the entry says otherwise.
- Snapshotted at approval and verified at arm/recheck: the generated `DOCKER_CONFIG` content (keys
  from the user's `config.json`: `auths` hosts, `credsStore`, `credHelpers`, `currentContext`,
  `proxies`, `plugins`, `HttpHeaders`, `cliPluginsExtraDirs` — the last five are recorded but must
  be absent/empty in the vault copy; their presence in the user's file is a finding), the listings
  of `~/.docker/contexts` and `~/.docker/cli-plugins`, and SHA-256 of `docker.exe`, the compose
  plugin, and every credential helper binary.
- Exact-match only (no profile): `run`, `exec`, `cp`, `compose run|exec`, `docker build`, `login`,
  `tag`, `save`, `load`, `commit`, `context`, `plugin`, `system`.

### 5.3 kubectl — read-mostly + pinned apply

- **Vault-owned sanitised kubeconfig** (decision 4; a context switch needs re-approval). At
  approval run `kubectl config view --raw --minify --flatten --kubeconfig=<user file>
  --context=<ctx>` (always pass `--raw`; K2: flatten inlines cert data, other contexts absent;
  `config view` runs no exec plugin). The result is shown to the human and must contain: exactly
  one cluster/user/context, `https` server, no `insecure-skip-tls-verify`, no `proxy-url`, no
  `tls-server-name`, no `auth-provider`, no `tokenFile`/relative paths; an `exec` plugin only with
  an **absolute** command path (no bare/relative, K2), no `exec.env`, `exec.args` pinned
  (recorded and compared), SHA-256 of the plugin recorded and **re-verified right before spawn**
  (kubectl does not check content, K3).
  - *Where the copy lives (state plainly)*: it contains credentials (tokens, client keys, K2). It
    is stored **sealed inside the entry's snapshot** (AES-GCM body) and, per run, written to a
    mode-0600 file in a vault-owned private directory, hash-verified, passed as `--kubeconfig=`,
    and deleted after the run. While the run is alive the file is readable by the agent (same
    user): if the original kubeconfig is the user's own `~/.kube/config` this adds no exposure
    (intent-gating only); the vault never claims it hides cluster credentials. A kubeconfig that
    is itself a vault secret is **not supported** in 2.4.0 (a flattened copy on disk would be a
    leak window beyond the vault's guarantee).
  - Missing kubeconfig falls back silently to `http://localhost:8080` (K1) → existence and hash
    verified before spawn. `--kubeconfig` disables the `KUBECONFIG` merge (K1), repeats forbidden.
- **Server injects**: `--kubeconfig=<copy>`, `--context=<pinned>`, `--cache-dir=<fresh temp dir,
  removed after>` (K7: otherwise cache goes under HOME), `--request-timeout=30s` **and** its own
  wall-clock cap on the child (K7: a dead server still took ~10 s with the flag). `rollout status`
  always gets a capped `--timeout` (default 0s waits forever, K8, default cap 300 s); `logs`
  always gets `--tail` (default and max 5000) and `--limit-bytes` (default and max 10 MiB) when
  the agent omits them.
- **kuberc** (K3): on kubectl ≥ 1.35 with an exec plugin, the server writes a kuberc **byte-exactly
  from a template** (`apiVersion: kubectl.config.k8s.io/v1beta1`, `kind: Preference`,
  `credentialPluginPolicy: Allowlist`, `credentialPluginAllowlist: [{command: <abs path>}]`) with the
  path backslash-normalised and case exactly as `LookPath` returns it (forward slashes are a hard
  error), passes `--kuberc=<file>`, and sets **no** `KUBERC` env (`--kuberc` + `KUBERC=off` are
  mutually exclusive). Without an exec plugin: env `KUBERC=off` (exact lowercase; any other value
  is a file path). **Fail-open hazard**: a wrong `apiVersion` or a typo'd key only prints
  `kuberc: ignoring strict decoding error` and the policy is NOT applied → a self-test probe
  (`kubectl version --client --kuberc=<file>`, no cluster) at approval and arm time treats that
  stderr line as fatal (disarm); the same line in any real run's stderr marks the result as an
  error. Below 1.35: exec plugins refused entirely (the sanitiser rejects an `exec` stanza).
- **Exec-plugin env**: the plugin inherits kubectl's whole env (K4) — with the from-scratch env it
  sees only `only_vars` + system essentials, so `only_vars` must contain nothing the plugin must
  not see; the dialog says so.
- Allowed:

| Sub | Flags / slots |
|---|---|
| `get <kind> [<name>]` | `-n`, `-A`, `-l`, `-o` ∈ {wide,name,json,yaml}, `--no-headers`, `--show-labels` |
| `describe <kind> [<name>]` | `-n`, `-l` |
| `logs <pod\|kind/name>` | `-n`, `-c`, `--tail=N` (≤ 5000), `--since`, `--previous`, `--timestamps`, `--all-containers`, `--limit-bytes=N` |
| `rollout status <kind>/<name>` | `-n`, `--timeout` (capped) |
| `apply -f <file>` | `-n` (pinned), `--dry-run={client,server}`, `--validate=strict` |

- Kind slot is an allowlist (pods, deployments, replicasets, statefulsets, daemonsets, jobs,
  cronjobs, services, endpoints, endpointslices, ingresses, configmaps, events, namespaces, nodes,
  pvc, hpa, networkpolicies + short names). The server rejects, itself, what kubectl accepts (K7):
  comma lists (`pods,secrets`), qualified `x.v1.` forms, `kind/name` outside `logs`/`rollout`,
  multiple names. Never: secrets, serviceaccounts, RBAC, CSRs, webhooks, CRDs, `all`. Name =
  DNS-1123 subdomain, namespace = DNS-1123 label, selector = equality-only.
- Rejected everywhere: `--kubeconfig`, `--context`, `--cluster`, `--user`, `-s/--server`,
  `--token`, `--username`, `--password`, `--as*` (incl. `--as-uid`, `--as-user-extra`),
  `--certificate-authority`, `--client-*`, `--insecure*`, `--tls-server-name`, `--proxy-url`,
  `--profile*`, `--cache-dir`, `--kuberc`, `--request-timeout`, `--disable-compression`,
  `--match-server-version`, `--warnings-as-errors`, `-v/--v/--vmodule/--log-flush-frequency`.
  `get`: `--raw -w --watch-only --template -f -k -R --field-selector --chunk-size --sort-by
  --show-managed-fields --subresource --server-print -L`, and template/jsonpath/custom-columns/
  go-template/kyaml output. `logs`: `-f --prefix --all-pods -l --ignore-errors --max-log-requests
  --pod-running-timeout --since-time`. `rollout status`: `--revision -w`. `apply`: `-k --prune
  --force --overwrite --server-side --force-conflicts --applyset -R`, `-f` as URL/`-`/directory/
  UNC/symlink.
- **apply** (K6). The server reads the manifest file **once** and requires the bytes' SHA-256 to
  equal the approved hash. It then runs the **offline normaliser** `kubectl label --local -f - -o
  json zzz- --kubeconfig=<copy>` on those bytes (works with no network; K6) and parses its stdout
  as a stream of JSON documents (`json.JSONDecoder.raw_decode` loop; concatenated pretty objects,
  **not** a List). **Policy runs on that normaliser output** (it is what kubectl's own decoder
  sees: duplicate keys last-wins, YAML 1.1 coercions, anchors/merge keys resolved), while the
  **original approved bytes** are fed to `kubectl apply -f -` on stdin. Policy: namespaced kinds
  from an allowlist, `metadata.namespace` = pin (or absent with `-n` pinned); deny Secret, RBAC,
  ServiceAccount, CRD, webhooks, Namespace; in pod specs deny privileged, privilege escalation,
  `hostPath`, `host*`, `hostPort`, `capabilities.add`, secret/projected/token volumes,
  `secretKeyRef`, `envFrom.secretRef`, non-default `serviceAccountName`. A differential test feeds
  duplicate-key / `on` / `010` / anchor documents. **No offline apply**: `apply --dry-run=client`
  needs API discovery even for built-in kinds (K6 refuted), so apply tests use a loopback fake API
  (relaxation in §4).
- Never wildcarded: `exec cp port-forward proxy attach run debug edit delete patch replace create
  expose set label annotate taint cordon drain auth config certificate rollout(≠status) diff
  plugin kustomize wait top`; any unknown top-level word runs a `kubectl-<word>` plugin from PATH
  (K5) — the closed grammar plus the pinned `PATH` covers this. helm: no profile (exact only).
- Env adds nothing; drops `KUBECONFIG`, `KUBERC` (re-added as `off` only as above), `KUBECTL_*`
  (incl. `KUBECTL_KUBERC`), `KUBECACHEDIR`, `KUBE_EDITOR`, `KUBERNETES_*`, `POD_NAMESPACE`,
  proxies, `SSL_CERT_*`.

## 6. Residual risks (documented, not fixed)

- **Always-allowed values are obtainable by the agent.** Through pre-push/pre-commit **hooks and
  tests** it can edit (git), through **containers** it can start, inspect, exec into and log
  (docker `up` injects the values into container env; non-built images are not pinned), and
  through **cluster objects** it can apply and query (kubectl). Pins limit which values and where
  they go, not whether the agent can read them. Use test-grade credentials, minimal `only_vars`.
- Output redaction is best-effort even with the widened encodings (§4): any transformation the
  redactor does not model defeats it; the 256 KiB cap limits volume, not leakage.
- Rollback protection can be defeated by an attacker who also resets the sidecar and restarts the
  server; it does not stop restoration of an older vault by the human.
- Same ceiling as today's trust: code running as the user that edits `mcp_server.py` beats it.
- Trusted code still sees the injected secrets: the user's own hooks, the credential helper,
  compose services, exec credential plugins, exact-kind programs and whatever their own config
  files tell them to do. They are fingerprinted, not sandboxed.
- Content the agent controls legitimately: commits it pushes to the approved repo, images it
  pushes to the approved namespace, manifests that pass policy, app logs that echo secrets,
  Dockerfiles and build contexts (run without secrets).
- Short TOCTOU windows on inputs that cannot be pinned: `.git/config` between the remote-URL check
  and spawn, hook bodies, `.gitattributes`, bind-mount sources, Dockerfiles/build contexts.
- The kubectl sanitised kubeconfig copy is readable by the agent for the duration of a run (§5.3).
- Windows-only: DLLs outside the cwd (the exe's own directory is checked only for exact entries).

## 7. Decisions (user, FINAL, 2026-10-14)

1. git `push` stays clamped as in §5.1 (no `--force-with-lease`, no `--tags`, no `+`/`:` refspecs).
2. git credentials keep coming from the user's own helper (GCM). The vault vars an entry injects
   are for **pre-push hooks that run tests**. Consequence, shown in the approval dialog and in the
   tool result: a hook that runs the test suite executes repository code the agent can edit, so the
   injected vars are reachable by that code. The hooks dir is fingerprinted; the code it runs is
   not (it changes every commit). Approve only the vars the tests genuinely need.
3. docker build is allowed for an **approved list of services** per entry (`compose build` and
   `up --build`); build steps receive **no vault values**; the Dockerfile/context are not
   fingerprinted; remote contexts, `build.privileged|entitlements|network: host` and a Dockerfile
   `# syntax=` directive stay denied (§5.2 Class A, CVE-2024-23653).
4. kubectl uses the vault-owned sanitised kubeconfig; a context switch needs re-approval.
5. **Exact (non-profile) always-allow entries: native programs only.** argv0 must be a native
   PE/ELF executable, absolute path resolved and hashed at approval and never re-resolved, exe
   directory not user-writable; the launcher denylist (npm npx yarn pnpm bun deno pytest tox nox
   cargo make cmake ninja gradle gradlew mvn mvnw dotnet go uv poetry pipx pre-commit just task rake
   bundle composer java) and shells/interpreters are refused; `.cmd`/`.bat`/`.ps1` argv0 are
   refused for any trust tier **including the existing 8 h trust (behaviour change, call out)**.
   Plus cwd DLL snapshot on Windows, optional `monitored_paths` (built-in table) and the blunt
   warning line (§5.0).
6. **Docker: NO image pinning.** Instead the dialog and the tool result warn that containers for
   non-built services run images the vault does not pin, and that the agent can read container env
   and logs.
7. **Rollback protection**: monotonic generation counter in the body (reserved key) + last-seen
   generation in a sidecar file outside the vault (no secrets) and in memory; regression → refuse
   to arm and warn; every unlock dialog lists the entries it is about to arm (§2).

### Conflicts between sources and how rev 2 resolves them

- **Compose TOCTOU** (design-review 5 vs D2/D6): sentinel-YAML hash is the anchor/lint input
  (`--no-interpolate` rejected); real-value config R is piped to `up -f -`, bracketed by two
  sentinel twins that must equal the approved hash (§5.2).
- **git remote pins** (design-review 5 vs C3): command-scope `remote.<n>.url`/`pushurl` would add
  a second URL, so the URL is checked (`get-url --all`, one line) rather than pinned.
- **Flag spellings** (§4 "`--flag=value` only" vs `-n X` in tables): short flags take a separate
  token, long flags `=`; both canonicalised.
- **Q7** ("empty only_vars still dialogs"): code refuses before any dialog; refusal kept and
  tested to precede matching. **Image digests** (design-review 1) dropped per decision 6.
  **`add_secret` denylist** applies to new names only.

## 8. Implementation outline — module map

All new Python lives in `vault_lib/`. Work units (WU) are sized for separate agents; WU1 and WU2
first, in parallel, coupled only through the contract in 8.0.

### 8.0 Profile protocol (CONTRACT — from core-design item 3; change only via handback)

`vault_lib/profiles/__init__.py`:
- `Request(command, cwd, only_vars, timeout)` — frozen dataclass. `Verdict(ok, reason, argv, env,
  replace_env)`.
- Profile members: `kind: str`; `match(req) -> Optional[dict]` (JSON candidate shape, None if not
  this profile); `snapshot(req, candidate) -> dict` (before the dialog; probes per §4);
  `describe(req, candidate) -> str` (canonical pattern + findings + warnings);
  `check_snapshot(entry) -> (ok, reason)` (arm time, no concrete command);
  `verify(entry, req) -> Verdict`: `ok=False, reason=None` = not applicable; `ok=False,
  reason=str` = applies but drifted/refused; `ok=True` = final `argv` + `env`. `replace_env=True`:
  `env` is the complete child env (caller adds only_vars values on top); `False`: merge onto
  `os.environ`; `env=None`: `os.environ` + secrets.
- `REGISTRY`: ordered list, `exact` last.

### WU1 — core storage, arming, rollback (`store.py`, `trust.py`, `allowlist.py`, `rollback.py`)

- `store.py`: `register_unlock_listener(fn)`, `_notify_unlocked(body, fingerprint, method)`
  (swallows listener exceptions), called after v2 decode and v1 `_load_secrets_v1` in
  `load_vault_body_ex` (~2139), at the end of `_write_body_locked` (~2371–2454; written body +
  sha256 of new bytes), after `_change_password_locked` v2 (~2587) and
  `_reissue_recovery_key_locked` (~2771); `method="recovery"` for recovery unlocks and writes
  inside them. `#generation` bump in `_write_body_locked`. `is_tool_control_name`; `add_secret`.
- `rollback.py`: `read_last_seen`, `record_seen` (atomic, never lowers), `check(vault_id,
  body_generation) -> (ok, message)`.
- `trust.py`: `arm(key, snapshot, secrets, vault_fp)` (clear caches if `_cached_vault_fingerprint`
  differs; `_trusted[key] = {hashes, granted_wall, granted_mono, persistent: True}`), `disarm(key)`,
  `check_armed(key) -> (ok, reason)` (factored out of `check()`); `check()` skips TTL when
  `persistent`; keys `("always_allow", entry_id)`; `cache_secrets(..., fingerprint=)`; AES-GCM.
- `allowlist.py`: `add_entry`/`remove_entry` (`load_vault_body_ex` → mutate only `#always_allow` →
  `save_vault_body(expect_fingerprint)`, retry once on CAS `RuntimeError`); arming listener (fast
  return; skip if sha256(vault file) != fp; rollback check; rebuild `_status {id: (armed,
  reason)}`; unknown kind / `check_snapshot` failure / missing var → disarmed; `trust.arm`;
  `trust.disarm` vanished; lock; `reset()` for tests); `eligible(command, materialize,
  background, files, max_reads, all_vars)`; `find_match(req) -> Match(.entry, .verdict, .secrets,
  .label, .recheck())`; `make_offer(req) -> Offer(.pattern, .commit(password))` (holds the
  cool-down); `list_entries(password)`; `describe_state()`; `pending_arm_summary()`.
- Tests `tests/test_allowlist.py` (after `test_trust.py`, `_vault_workspace.py`): rollback,
  recovery exclusion, remove rebuilds armed set, cool-down, AES-GCM cache.

### WU2 — shared profile helpers (`profiles/_common.py`, `profiles/__init__.py`)

`resolve_pinned_binary`, `build_env`, `tokenize_argv`, `parse_version`/`meets_floor` (git table,
compose tuple, Desktop), `run_probe`, `hash_file`/`hash_tree`, `canonical_cwd`, `has_unsafe_text`,
`dir_not_user_writable`, `RELAXATIONS`; the 8.0 dataclasses and `REGISTRY`. Table-driven tests.

### WU3 — exact profile (`profiles/exact.py`)

§5.0 in full; the `.cmd/.bat/.ps1` predicate is exported for WU5's 8 h path.

### WU4 — redaction widening (`mcp_server._redact_secrets`, `runstore.py`)

Extra encodings for armed values + 256 KiB cap (§4); `test_redaction.py`, `test_run_output.py`.

### WU5 — server, GUI, manage_vault wiring (`mcp_server.py`, `gui.py`)

- `_run_with_env_core` (~1852–2003): `Request`; `eligible` first; `find_match` → `auto_ok`,
  `trust_info {auto_allowed, trust_note: "Auto-allowed by always-allow entry '<label>' (id)",
  always_allow: id}`; else `trust.check` with the disarm reason as `invalidated_reason`;
  `match.recheck()` right before `_run_command`; verdict argv/env; snapshot before the dialog
  beside `pre_hashes`; `always_allow=offer`; always-allow wins over 8 h; `.cmd` trust refusal;
  the empty-`only_vars` refusal (1765) stays first.
- `gui.unlock_for_run_dialog` (~2301): `always_allow=None` kwarg; checkbox beside trust
  (~2489–2513) per §3; hidden when `None` or `files`; `on_allow` commits `offer.commit(password)`
  after secrets load (`_show_error` on exception); outcome carries `always_allow`; every
  master-password unlock dialog lists `pending_arm_summary()`. `_tk_checks.py` absence check;
  headless via `LLM_ENV_VAULT_HEADLESS=1`; dialog tests via the `_tk_checks.py` child
  (`test_security_invariants.py` ~216).
- `manage_vault`: `gui._applicable_manage_actions` (2261) + `always_allow_list`/
  `always_allow_remove`; `manage_vault_dialog` action_defs; `_manage_vault_impl` (~1184–1390);
  catch `TooManyAttempts`, `WrongPassword`, `VaultCorrupted`, `VaultTampered`; docstring;
  `_manage_action_result_keys` (~2290); tests `test_gui_v2.py` (~285–466), `test_fmk_rotation.py`
  (~440), `test_manage_vault.py`.

### WU6–WU8 — profiles (`profiles/git.py`, `docker.py`, `kubectl.py`; `tests/test_profile_*.py`)

One unit per profile, implementing §5.1 / §5.2 / §5.3 against the 8.0 contract and WU2 helpers.
Every rejected flag/slot in the §5 tables is a table-driven test; plus snapshot drift per tracked
input, env construction, version floors, arming on each unlock path. Profile-specific tests: git
C2 behavioural helper check, C5 pre-push hook, C6 pull cases, C7/C8 push to a local bare remote;
docker S/R/S′ mismatch, nested-include scan, per-lint-finding cases; kubectl K6 differential
cases and a loopback fake API.

### WU9 — docs

README "Trusted commands" (always-allow, exact-entry limits, `.cmd` behaviour change,
truth-in-labelling), security posture doc (successor of §10: rollback, §6 risks), CHANGELOG 2.4.0
(`manage_vault` actions, `add_secret` name refusal, `.cmd` change, version floors), version bump
and plugin metadata per the repo's release routine.
