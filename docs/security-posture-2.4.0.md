# Security posture, 2.4.0

What persistent "always allow" entries promise, what they do not, and the residual risks.
It extends [2.0.0](security-posture-2.0.0.md); the invariant there (the master password never
touches disk; no file the agent can read holds a real value) is unchanged. User-facing description:
the README section "Trusted commands (always allow)".

---

## 1. What an entry is, and is not

An always-allow entry lets `run_with_env` skip the password dialog for a clamped family of commands
(git, docker, kubectl, or one exact native program). It is **intent gating, not a sandbox**. The
entry is sealed in the vault body (reserved key `#always_allow`, authenticated by the vault's
AES-GCM; only a human with the password can add one). It is armed by every master-password unlock
in the server process, loaded into the trust cache with only its own `only_vars` values, and never
armed by a recovery-key unlock (including writes made in that session).

Code running as your OS user, including the agent's own shell, can edit `mcp_server.py` or read
process memory. That is the same ceiling as the 8-hour trust and it is not defeated here.

## 2. The agent can obtain the values

For an always-allow run the agent can obtain the injected values. That is the premise of every
dialog and result string, not a bug:

- **git:** the pinned pre-push hook typically runs the test suite. Those tests are repository code
  the agent can edit, and they receive the injected variables. The hooks directory is hashed; the
  code it runs changes with every commit and is not.
- **docker:** `compose up` puts the values into container environments. The agent can start
  services, inspect, log and exec into them (the docker daemon can be inspected), and non-built
  images are **not pinned** (decision 6): whatever the registry serves runs with the values.
- **kubectl:** objects the agent applies (within the policy) and reads in the pinned namespace can
  carry or echo the values; app logs that echo secrets are returned.
- **exact:** the program's own config files, plugins and inputs can change what it does with the
  variables. The entry pins the command line, not the behaviour.
- **Output oracle:** a command can print a transformed value. Auto-allowed runs use strict
  redaction (exact, base64/base64url padded and unpadded, hex, `quote`/`quote_plus`, upper/lower
  forms, with base64 alignment variants) and a 256 KiB per-stream cap. This is best-effort: any
  transformation the redactor does not model defeats it, and the cap limits volume, not leakage.

**Mitigation:** use test-grade credentials and the smallest `only_vars`. Do not put a value behind
an entry if it would hurt in the agent's hands.

## 3. Pins bound the blast radius

Pins decide **which** values go **where**, not whether the agent can read them:

- Environment built from scratch (no inherited `GIT_*`, `DOCKER_*`, `COMPOSE_*`, `KUBE*`, proxies,
  `LD_*`, `PYTHON*`, ...); a `PATH` of system directories only; the program resolved to an absolute
  path and SHA-256 re-verified before every spawn. Vault variables whose names are on the
  tool-control denylist (`vault_lib/envnames.py`) are refused for entries, and new ones are refused
  by `add_secret`.
- Closed argv grammar per profile, canonical flag spellings, no `@file`, no repeated flags; anything
  outside it opens the normal dialog.
- Entries are re-checked at arm time and again right before each run; drift makes the dialog appear
  and explain what changed. The cwd is pinned by real path (junction, symlink, 8.3 name, case).
- Dialog anti-spoofing: server-generated label, escaped argv, no bidi/zero-width/non-printable
  text, the canonical pattern is shown.
- `manage_vault` listing exposes only `id, kind, cwd, shape, label`.

## 4. Rollback protection

An agent can copy files, so restoring an older `vault.enc` would silently re-arm an older list.

- **Generation:** `#generation` in the body, raised on every body write, never lowered.
- **Sidecar:** the highest generation seen, `{vault_id, generation}` (no secrets), in a per-user
  state folder outside the vault directory (`%LOCALAPPDATA%\llm-env-vault\rollback` on Windows,
  `$XDG_STATE_HOME` or `~/.local/state` elsewhere), atomic replace, never lowered.
- **In memory:** the same value is held by the server process.
- **On unlock:** `generation < max(memory, sidecar)` means nothing is armed, the tool result warns,
  and it stays that way until an approved write raises the generation past it. The vault still
  opens. A missing sidecar with generation >= 1 is accepted (and recreated). A vault from before
  2.4.0 has generation 0 and gets 1 on its next write.
- **Residual:** an attacker who also deletes the sidecar and restarts the server defeats this. It
  raises the bar from "copy one file" to "also edit state outside the vault". It does not stop a
  human restoring an old copy deliberately.

## 5. Residual risks (accepted)

- **Unpinnable git local keys.** Local/worktree git config may hold only a short benign allowlist,
  and command-scope pins beat the rest; but a remote `.gitattributes` can name any local filter or
  driver, so any other local key makes the command ineligible. `.git/config` can still be edited
  between the remote-URL check and the spawn (a short TOCTOU window), as can hook bodies,
  `.gitattributes` and `.gitmodules`.
- **Hooks run tests.** Hooks run normally by design (a user requirement); see section 2.
- **Images are unpinned.** See section 2. Dockerfiles and build contexts are the agent's own code;
  they run **without** vault values, but they are not fingerprinted. Bind-mount contents are not
  covered either.
- **The docker daemon can be inspected.** Whoever can reach the pinned endpoint (the agent included,
  as the same user) can read container env and logs outside the vault.
- **The kubeconfig copy on disk.** The sanitised kubeconfig contains the context's credentials. It
  is sealed in the entry and written to a **persistent, content-addressed** file in the per-user
  state folder (`.../llm-env-vault/kubectl`, user-only ACL / mode 0600 on a best-effort basis), and
  it is not deleted after each run. The agent runs as the same user and can read it. If the source
  is the user's own `~/.kube/config` this adds no exposure; the vault never claims to hide cluster
  credentials. A kubeconfig that is itself a vault secret is unsupported. An exec credential
  plugin inherits kubectl's whole environment (only `only_vars` plus system essentials).
- **Content the agent controls legitimately:** commits it pushes to the approved repo, images it
  pushes to the approved namespace, manifests that pass policy, application logs.
- **Trusted code sees the values:** user hooks, the credential helper, compose services, exec
  credential plugins and exact-kind programs are fingerprinted, not sandboxed.
- **kubectl default ServiceAccount token.** A pod that does not set `automountServiceAccountToken`
  gets the namespace's default ServiceAccount token. The plan allows the default ServiceAccount, and
  forcing `false` would break normal workloads. An explicit `automountServiceAccountToken: true` is
  refused.
- **Cool-down is per exact signature.** It is keyed on the whole signature, timeout included, so
  varying any argument resets it. The human still sees a dialog every time, so this is a convenience
  limit, not a bypass.
- **exact: directories are not hashed.** Hashing a directory argument is unbounded. Files named in
  arguments, in `--opt=file`, `@file` and `file,Entry` forms, and symlink targets (dangling ones
  included) are hashed.
- **docker: lint model and `only_vars`.** The host-escape lint runs on the sentinel model, not the
  real-value model, so vault values never appear in refusal text. The request's `only_vars` must
  equal the approved set, so a `${X:-default}` cannot make them diverge.
- **docker: non-`up` requests still name vault vars.** `run_with_env` requires `only_vars`, so the
  request must list vault variables even for `down`, `pull`, `ps`, `logs` and the like. The values
  are never injected (`inject_secrets=False`).
- **Timeouts kill the process tree, except for one run type.** On a timeout the whole process tree
  is killed for: a probe, an auto-allowed (always-allow) run, any run that sends stdin to the
  child, and a swap/materialize run (a bound run). Only an ordinary approved run with no files
  swapped, no stdin and no always-allow entry kills just the direct child: a process it started
  can outlive the timeout. Its `timeout_note` says so instead of claiming the tree.

## 6. Hardening from the 2.4.0 review

Behaviours you may notice as refusals; each opens the normal dialog instead of auto-allowing.

- **exact:** Windows proxy-execution tools are refused: `rundll32`, `regsvr32`, `mshta`, `wscript`,
  `cscript`, `msiexec`, `forfiles`, `cmstp`, `installutil`, `msbuild`.
- **exact:** more wrappers and interpreters are ineligible: `env`, `xargs`, `timeout`, `nice`,
  `nohup`, `php`, `lua`, `java`, `deno`, `bun`, `pypy`.
- **git:** a branch-less `pull` is not auto-allowed when the entry restricts branches.
- **docker** refuses:
  - socket-ancestor binds such as `/var/run`, `/run/user/<uid>` and `~/.docker`
  - four-slash npipe forms
  - Dockerfiles whose scan window ends before the first instruction
  - `env_file` paths containing `$`
  - a request whose `only_vars` set differs from the approved set
- **kubectl** refuses non-empty `imagePullSecrets` and `automountServiceAccountToken: true`.

## 7. Windows DLL side-loading

A program started from a directory can load `*.dll` files placed there. Mitigations:

- Probes (config and model reads) run with a vault-owned empty directory as cwd, using `git -C`,
  `--project-directory` and stdin input.
- At approval the `*.dll` files in the entry's cwd (names and SHA-256) are snapshotted and verified
  before each spawn; drift reverts to the dialog.
- Binaries are pinned by absolute path with `.exe` only; the cwd and `.` are never searched.

**Not covered:** DLLs outside the cwd, including the directory of the executable itself for
non-exact entries (exact entries require that directory to be not user-writable).
**Tests:** the cwd-DLL checks are **Windows-only** tests; they are skipped elsewhere, so that
behaviour is exercised only on Windows.

## 8. Minimum versions

Auto-allow is refused below these floors; the normal dialog still works.

- **git:** 2.50.1 or later, **or** a patched maintenance line: 2.43.7, 2.44.4, 2.45.4, 2.46.4,
  2.47.3, 2.48.2, 2.49.1 (CVE-2025-48384). `.windows.N` suffixes are ignored; Git for Windows
  numbering of the backports is unverified, so only 2.50.1+ is certain to be accepted on Windows.
  Example: **git 2.45.1 is below the floor** (it needs 2.45.4+ or 2.50.1), so git entries are
  refused until git is upgraded.
- **Docker Compose:** (2, 40, 2) or later, compared as a numeric tuple (CVE-2025-62725); every 5.x
  passes. **Docker Desktop:** 4.44.3 or later; **BuildKit:** 0.12.5 or later (build tier).
- **kubectl:** any version. Exec credential plugins are used only on 1.35 or later (kuberc
  allowlist); below that an exec stanza makes the kubeconfig ineligible.

## 9. Test-only relaxations

The dev machine fails the floors and tests use local bare repos and fake APIs, so
`profiles/_common.RELAXATIONS` (allowed git protocols, version floors, the writable-directory check,
loopback kubectl servers) can be changed by test monkeypatching only: no environment variable, no
config file, no runtime switch. A test asserts that the defaults are strict.
