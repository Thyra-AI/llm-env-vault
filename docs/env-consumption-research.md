# How programs consume `.env` values — and which of those paths the vault covers

> **Status: updated for 2.0.0.** This was written (2026-09-15) as the research behind
> `run_with_env`'s `swap` parameter. That parameter is **retired in 2.0.0** — it wrote real
> values into the project's own `.env`, which is the one thing the vault exists to prevent, and
> it was refused for `git` commands, which is the most common trigger there is (a pre-push hook
> whose tests read `.env`). The mechanism analysis below stands unchanged; what changed is the
> answer to mechanisms B-when-scrubbed and F, which is now §6's typed placeholders rather than
> swap. Sections that still describe swap's write path are kept as the record of why it existed
> and why it was not enough.

It answers one question:
**for every ordinary way an application or tool obtains a value that lives in a `.env` file,
does a vault-managed project still work — and if not, why not, and what closes the gap?**

The executable half of this research is `tests/test_consumption_matrix.py`. Every mechanism
below that can be exercised without network or a third-party daemon has a test there, run
against a real isolated vault, with the real `python-dotenv` and `pydantic-settings` that ship
as transitive dependencies of `mcp[cli]` (so they are on the tested path, not optional extras)
and with Node's built-in `--env-file` when `node` is on `PATH`.

Every third-party claim in the tables cites its primary source (official docs or the parser
source file). Claims that could not be pinned to a primary source are marked **UNVERIFIED** —
they are recorded so the gap is visible, not so it can be mistaken for a fact.

---

## 1. The six mechanisms

Strip away the tool names and there are only six ways a value gets from a `.env` file into a
running program. Everything in the per-tool tables is an instance of one of these.

| # | Mechanism | Who reads the file | Example | Status in 2.0.0 |
|---|---|---|---|---|
| **A** | **Inherit the process environment** | nobody — the child reads `os.environ` / `process.env` | `os.environ["DATABASE_URL"]`, `${VAR}` in a compose file, `docker run -e VAR`, Terraform `TF_VAR_x`, AWS/gcloud CLIs | **Works.** This is what `run_with_env` was built for. |
| **B** | **Load the file, env wins** | the app's loader, at startup, with `override=False` semantics | `load_dotenv()`, pydantic-settings `env_file`, Node `--env-file`, dotenv npm, Vite, Next, Bun, godotenv `Load`, dotenvy `dotenv()`, phpdotenv immutable, `just`, Taskfile, `uv run --env-file` | **Works while the variable is in the injected env** — the loader sees the placeholder in the file, sees the real value already in the environment, and keeps the environment. **Breaks** the moment something scrubs the environment before the loader runs (a test harness building a child env from an allowlist; `env -i`; `sops --pristine`). Then the file is the only source. **Closed in 2.0.0** by typed placeholders (§6): the scrubbed child loads the file and parses it, and the values it gets are placeholders. |
| **C** | **Load the file, file wins** | the app's loader, with explicit override | `load_dotenv(override=True)`, `dotenv.config({override:true})`, godotenv `Overload`, dotenvy `dotenv_override()`, Ruby `Dotenv.overload`, `just` `dotenv-override`, `dotenvx --overload`, tox `set_env = file\|.env`, `direnv`'s `dotenv` (always `export`), phpdotenv `createMutable` | **Not supported.** The placeholder in the file overwrites the real value that was injected. A typed placeholder parses but is still not the secret. |
| **D** | **Shell-source the file** | the shell itself | `source .env`, `set -a; . .env; set +a`, `export $(grep -v '^#' .env \| xargs)`, `make` `include .env` | **Not supported.** Same as C — the file is executed as assignments and clobbers the environment. |
| **E** | **Read the file as the *only* source** | a tool that never consults its own environment for these names | `docker run --env-file`, Compose `env_file:`, `kubectl create secret --from-env-file`, VS Code `launch.json` `envFile`, JetBrains EnvFile, `devcontainer.json` `runArgs --env-file` | **Breaks.** Nothing about the process environment reaches the consumer. `materialize` covers the subset of these that accept *any* path (Docker's `--env-file`, Compose's `--env-file`), but not the ones hard-wired to the canonical filename (Compose `env_file: .env`, an IDE's `envFile` setting), which are **not supported**. |
| **F** | **Typed parsing of the file** | a settings library that validates types at load time | pydantic-settings `port: int`, django-environ `env.int()`, Spring `.properties` | Broke even with no vault involvement at all: `SMTP_PORT="value 17"` is not an `int`. **Closed in 2.0.0** — see §6. |

Two things follow from the table:

1. **Mechanism A is the design.** Every mechanism that *can* be served by a process environment
   already is. The vault does not need to change how it injects.
2. **Mechanisms B-when-scrubbed, C, D and E were read as one requirement, and that was the
   mistake.** They look identical — a file at the canonical path must satisfy the consumer for
   the lifetime of the command — so 1.6.0 answered all four with `swap`, writing REAL values
   there. But B-when-scrubbed and F do not actually need a real value: a scrubbed test harness
   and a typed settings loader need the file to **parse**, not to be true. Only C, D and E need
   the value itself. Splitting them is what 2.0.0 does: typed placeholders (§6) close
   B-when-scrubbed and F with nothing on disk, and `materialize` — a fresh path, never the
   project's own file — remains the answer for E. C and D are not served, and are documented as
   unsupported rather than answered by writing secrets into a tracked file.

---

## 2. Per-tool precedence (process env vs `.env` file)

"Env wins" means: if `FOO` is set in the process environment *and* defined in `.env`, the
environment value is used. This is what makes mechanism B work under `run_with_env`.

### Python

| Tool | Reads `.env`? | Default precedence | Override switch | Source |
|---|---|---|---|---|
| python-dotenv `load_dotenv()` | yes; `find_dotenv()` walks up from cwd/caller | **env wins** (`override=False`) | `override=True` | [README](https://github.com/theskumar/python-dotenv#readme), [main.py](https://raw.githubusercontent.com/theskumar/python-dotenv/main/src/dotenv/main.py) |
| pydantic-settings `env_file=` | yes, via python-dotenv | **env wins** (init kwargs > env > dotenv > secrets dir > defaults) | none; `_env_file=None` disables the file | [docs](https://pydantic.dev/docs/validation/latest/concepts/pydantic_settings/) |
| Flask CLI | `.env` and `.flaskenv` if python-dotenv installed | env wins (python-dotenv default) | `FLASK_SKIP_DOTENV=1` disables | [Flask CLI docs](https://flask.palletsprojects.com/en/stable/cli/) |
| django-environ `read_env()` | path you pass | **env wins** | `overwrite=True` | [FAQ](https://django-environ.readthedocs.io/en/latest/faq.html) |
| environs | yes, via python-dotenv | env wins | `override=True` | [README](https://github.com/sloria/environs) |
| dynaconf `load_dotenv=True` | opt-in | env wins (`dotenv_override=False`) | `dotenv_override=True` | [docs](https://www.dynaconf.com/envvars/) |
| uvicorn `--env-file` | yes (needs python-dotenv) | not documented; targets the ASGI app, `UVICORN_*` keys excluded | — | [settings](https://uvicorn.dev/settings/) |
| honcho / foreman | `.env` beside the Procfile, or `-e` | **UNVERIFIED** — source (`environ.py` `e.update(env)`) suggests the file *can* overwrite the base env; docs are silent | — | [environ.py](https://raw.githubusercontent.com/nickstenning/honcho/main/honcho/environ.py) |
| pytest-dotenv | `env_files =` in `pytest.ini` | **env wins** | `env_override_existing_values = 1`; `--envfile` always overwrites | [README](https://github.com/quiqua/pytest-dotenv) |
| tox `set_env = file\|.env` | yes (tox ≥ 4) | **file wins** — `set_env` defines the venv's env by design | — | [config](https://tox.wiki/en/4.61.2/reference/config.html) |
| pipenv | auto on `shell`/`run` | env wins (python-dotenv default; **UNVERIFIED** for pipenv specifically) | `PIPENV_DONT_LOAD_ENV` | [docs](https://pipenv.pypa.io/en/latest/shell.html) |
| poetry | **no** (plugin only) | — | — | [plugin](https://pypi.org/project/poetry-dotenv-plugin/0.1.0a2) |
| uv `run --env-file` / `UV_ENV_FILE` | yes | **env wins** ("the value from the environment will take precedence") | `--no-env-file` | [docs](https://docs.astral.sh/uv/concepts/configuration-files/) |

### Node / JS

| Tool | Reads `.env`? | Default precedence | Override switch | Source |
|---|---|---|---|---|
| dotenv (npm) | `.env` in cwd | **env wins** ("we will never modify any environment variables that have already been set") | `override: true` | [README](https://github.com/motdotla/dotenv#readme) |
| Node ≥ 20.6 `--env-file`, `--env-file-if-exists`, `process.loadEnvFile()` | path given | **env wins** ("the value from the environment takes precedence") | none | [CLI docs](https://nodejs.org/api/cli.html#--env-fileconfig) |
| dotenv-cli | wraps dotenv | env wins | `-o` / `--override` | [README](https://github.com/motdotla/dotenv#readme) |
| dotenvx | yes | **env wins** | `--overload` | [docs](https://dotenvx.com/docs/advanced/run-overload) |
| Next.js `@next/env` | `.env.$(NODE_ENV).local` > `.env.local` > `.env.$(NODE_ENV)` > `.env` | **env wins** (highest of all) | none | [guide](https://nextjs.org/docs/pages/guides/environment-variables) |
| Vite `loadEnv` | `.env`, `.env.local`, `.env.[mode]`, `.env.[mode].local` | **env wins** — final loop copies matching `process.env` keys over file values | none | [env.ts](https://raw.githubusercontent.com/vitejs/vite/main/packages/vite/src/node/env.ts) |
| Create React App | same file order as Next | env wins | none | CRA docs |
| Nuxt | via c12 | env wins | none | Nuxt docs |
| Bun (built-in) | `.env`, `.env.{NODE_ENV}`, `.env.local` | **env wins** ("strictly prioritizes system environment variables") | `--no-env-file` disables | [docs](https://bun.com/docs/runtime/environment-variables), [#25100](https://github.com/oven-sh/bun/issues/25100) |
| Deno `--env-file` | path given (repeatable) | env wins | **UNVERIFIED** override flag | [docs](https://docs.deno.com/runtime/reference/env_variables/) |
| Astro, SvelteKit | via Vite `loadEnv` | env wins | none | [Astro](https://docs.astro.build/en/guides/environment-variables/), [SvelteKit](https://svelte.dev/docs/kit/$env-static-private) |
| pm2 | **no documented `env_file:`** — inline `env` blocks only | — | — | [docs](https://doc.pm2.io/en/runtime/guide/ecosystem-file/) |
| nodemon, cross-env, jest | no file reading of their own; delegate to dotenv | — | — | — |

### Containers / orchestration

| Tool | Source | Precedence | Source |
|---|---|---|---|
| `docker run --env-file` | file given | **file is the only source** for `KEY=value` lines; bare `KEY` pulls from the Docker CLI's env | [reference](https://docs.docker.com/reference/cli/docker/container/run/#env), [kvfile.go](https://raw.githubusercontent.com/docker/cli/master/pkg/kvfile/kvfile.go) |
| Compose `.env` (interpolation) | project-root `.env` or `--env-file` | **shell env > `--env-file` > `.env`** | [interpolation](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/) |
| Compose `env_file:` | path relative to compose file | file is the source; `environment:` overrides it for the same key | [reference](https://docs.docker.com/reference/compose-file/services/#env_file) |
| Compose `environment: - VAR` (bare) | — | pulls from the invoking shell | [how-to](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/) |
| `docker build --build-arg` / `--secret` | CLI literal / file by id | no `.env` parsing | — |
| `docker buildx bake` | **no native `.env`** | shell-exported vars only | [#1339](https://github.com/docker/buildx/discussions/1339) |
| Podman `--env-file` | file | same literal model as Docker | [#9446](https://github.com/containers/podman/issues/9446) |
| `kubectl create secret --from-env-file` | file | file is the source; bare `KEY` pulls from kubectl's env | [env_file.go](https://github.com/kubernetes/kubectl/blob/8d3b6cf1408476c8421eb5d4bf26b1d7badec47c/pkg/generate/versioned/env_file.go) |
| devcontainer `runArgs --env-file` | forwards to `docker run` | Docker's rules; `containerEnv` vs `runArgs` precedence **UNVERIFIED** | [spec](https://containers.dev/implementors/spec/) |
| Skaffold, Tilt | **UNVERIFIED** | | |

### Shell / task runners

| Tool | Behaviour | Source |
|---|---|---|
| `source .env`, `set -a; . .env; set +a` | shell executes the assignments — **file wins**, `$` and backticks expand in double quotes, arbitrary code runs | POSIX |
| `export $(grep -v '^#' .env \| xargs)` | file wins; breaks on spaces, empty values, inline comments | — |
| GNU `make` `include .env` + `export` | make's own syntax; **quotes are not stripped**, `#` and `$` are make syntax; makefile assignments win over env unless `make -e` | [manual](https://www.gnu.org/software/make/manual/html_node/Environment.html) |
| `just` `set dotenv-load` | env wins unless `set dotenv-override` | [manual](https://just.systems/man/en/dotenv-settings.html) |
| Taskfile `dotenv:` | OS env > task `env:` > dotenv (default; an experimental flag changes this) | [schema](https://taskfile.dev/docs/reference/schema), [experiment](https://taskfile.dev/docs/experiments/env-precedence) |
| mise `env._.file = ".env"` | delegates parsing to Rust `dotenvy` | [docs](https://mise.jdx.dev/environments/) |
| direnv `dotenv` stdlib | emits `export KEY=value` and evals it — **file wins** | [stdlib.sh](https://raw.githubusercontent.com/direnv/direnv/master/stdlib.sh) |
| envsubst | not a `.env` reader; expands `${VAR}` from the process env only | — |
| PowerShell | no native `.env` support | — |

### Other languages

| Tool | Default precedence | Override | Source |
|---|---|---|---|
| Go `godotenv` | **env wins** (`Load`) | `Overload` | [repo](https://github.com/joho/godotenv) |
| Rust `dotenvy` | **env wins** (`dotenv()`) | `dotenv_override()` | [docs.rs](https://docs.rs/dotenvy/latest/dotenvy/) |
| Ruby `dotenv` | **env wins** (`Dotenv.load`) | `Dotenv.overload`, `overwrite: true` | [rubydoc](https://rubydoc.info/gems/dotenv) |
| PHP `vlucas/phpdotenv` | **env wins** (`createImmutable`) | `createMutable` | [README](https://github.com/vlucas/phpdotenv/blob/master/README.md) |
| Laravel | env wins (immutable phpdotenv); `config:cache` stops reading `.env` entirely | — | [docs](https://laravel.com/docs/11.x/configuration) |
| Spring Boot | **no `.env` by default**; `spring.config.import=optional:file:.env[.properties]` parses as Java properties; final ordering vs `SYSTEM_ENVIRONMENT` **UNVERIFIED** | — | [docs](https://docs.spring.io/spring-boot/reference/features/external-config.html) |
| .NET `DotNetEnv` | clobbers unless `NoClobber()` (**default UNVERIFIED**) | — | [repo](https://github.com/tonerdo/dotnet-env) |
| .NET `Microsoft.Extensions.Configuration` | **no `.env` reading** | — | [MS Learn](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.environmentvariablesextensions.addenvironmentvariables) |
| Elixir dotenv, dotenv-java, flutter_dotenv (bundled asset) | **UNVERIFIED** / out of scope | | |

### IDE / test harness

| Tool | Behaviour | Source |
|---|---|---|
| VS Code `launch.json` `envFile` | reads the file; `envFile` vs `env` block precedence **UNVERIFIED** (community: envFile wins) | [docs](https://code.visualstudio.com/docs/debugtest/debugging-configuration), [#95371](https://github.com/microsoft/vscode/issues/95371) |
| VS Code Python `python.envFile` | default `${workspaceFolder}/.env`; leaks into new terminals per multiple open issues | [docs](https://code.visualstudio.com/docs/python/environments), [#23856](https://github.com/microsoft/vscode-python/issues/23856) |
| JetBrains EnvFile | reads the file; precedence **UNVERIFIED** | [plugin](https://plugins.jetbrains.com/plugin/7861-envfile) |
| Cursor / Windsurf | VS Code forks; assumed inherited, **UNVERIFIED** | — |

### Cloud / secret-manager CLIs (for comparison — these are *alternatives* to a `.env`)

| Tool | Behaviour | Source |
|---|---|---|
| 1Password `op run --env-file` | resolves `op://` refs in-memory; never modifies the file | [docs](https://developer.1password.com/docs/cli/secrets-environment-variables) |
| Doppler `doppler run` | env wins over Doppler secrets by default; `--mount .env --mount-max-reads 1` materializes an ephemeral file | [docs](https://docs.doppler.com/docs/cli) |
| `sops exec-env` | injects decrypted contents as env; `--pristine` drops ambient env | [docs](https://getsops.io/docs/usage/advanced/) |
| Vercel `vercel env pull` | *writes* `.env.local`; a materialization tool | [docs](https://vercel.com/docs/cli/env) |
| Wrangler `.dev.vars` | replaces `.env` entirely when present | [docs](https://developers.cloudflare.com/workers/development-testing/environment-variables/) |
| Serverless `useDotenv` | `process.env` > `.env` files; earlier array entries win | [docs](https://www.serverless.com/framework/docs/environment-variables) |
| AWS CLI, gcloud, Terraform | never read `.env` | — |

Notice that Doppler's `--mount` and 1Password's `op run` are the two closest analogues to what
the vault does, and both landed on the same shape: env injection by default, an ephemeral file
only when a consumer insists on one.

---

## 3. File syntax: why there is no universal quoting

The swap has to write a real value into a line that some unknown parser will read. The parsers
disagree on almost everything except the simplest case.

### `KEY="a b"` — who delivers `a b` and who delivers `"a b"`

| Parser | Delivers | Source |
|---|---|---|
| python-dotenv, node dotenv, Compose `env_file:`, bash `source`, godotenv, dotenvy, phpdotenv | `a b` | see §2 sources; [dotenvy parse.rs](https://raw.githubusercontent.com/allan2/dotenvy/master/dotenvy/src/parse.rs) |
| **`docker run --env-file`**, Podman | **`"a b"`** — "no interpolation, substitution or escaping is supported, and quotes are considered part of the key or value" | [kvfile.go](https://raw.githubusercontent.com/docker/cli/master/pkg/kvfile/kvfile.go) |
| **`kubectl --from-env-file`** | **`"a b"`** — `strings.SplitN(line, "=", 2)`, no stripping | [env_file.go](https://github.com/kubernetes/kubectl/blob/8d3b6cf1408476c8421eb5d4bf26b1d7badec47c/pkg/generate/versioned/env_file.go) |
| **GNU make `include`** | **`"a b"`** | [manual](https://www.gnu.org/software/make/manual/html_node/Environment.html) |

### `${VAR}` interpolation by default (a `$` in a secret gets mangled)

| Interpolates by default | Never interpolates |
|---|---|
| python-dotenv (`interpolate=True` default; `${NAME}` form only, bare `$NAME` is left alone; **in every quoting style, single quotes included** — verified against the installed 1.2.2 source, `resolve_variables` runs after parsing with no knowledge of quoting; only `interpolate=False` prevents it), Compose (`$VAR` and `${VAR}`, not in single quotes), Vite (dotenv-expand), godotenv, dotenvy (not in single quotes), phpdotenv (not in single quotes), bash `source` (not in single quotes) | node dotenv alone, `docker run --env-file`, kubectl, Node `--env-file` (**UNVERIFIED**) |

Single quotes disable interpolation in Compose, dotenvy, phpdotenv and bash — but **not** in
python-dotenv. `tests/test_consumption_matrix.py::test_B_python_dotenv_expands_brace_form_in_every_quoting_style`
pins that down, because the first draft of this document claimed otherwise. A secret containing
a literal `${...}` is therefore mangled by python-dotenv from a real `.env` too; the vault
neither causes nor can fix that.

### Escapes inside double quotes

| Parser | `\"` | `\\` | `\n` | `\$` |
|---|---|---|---|---|
| python-dotenv | unescaped | unescaped | newline | left as `\$` |
| node dotenv | **left as `\"`** | left | newline | left |
| dotenvy | unescaped | unescaped | newline | `$` |
| phpdotenv | unescaped | unescaped | newline | `$`; any other `\x` is a **parse error** |
| Compose | — | `\\` | newline | — |
| docker run / kubectl / make | literal | literal | literal | literal |

### `export KEY=value`

Accepted by python-dotenv, pydantic-settings, node dotenv, Compose, bash, `just`, godotenv
(dotenvy **UNVERIFIED**). **Rejected** by `docker run --env-file` and kubectl — the key fails
name validation.

### Multi-line double-quoted values

python-dotenv yes; node dotenv ≥ 15 yes; Compose **UNVERIFIED**; docker run no. The vault's
`install_migrate` already refuses to migrate a multi-line value, and `render_env_text` refuses to
write one, so the swap inherits a value set that is single-line by construction.

### The one representation every parser agrees on

**Unquoted, and the value contains none of: whitespace, `#`, `$`, `'`, `"`, `` ` ``, `\`.**
There is nothing to misinterpret. Most API keys, tokens and hashed passwords are in this set.
Outside it, the *correct* representation depends on which family reads the file — and only the
user knows that.

---

## 4. What the vault does with all of this

### Record the original style, replay it

`install_migrate` sees the user's original line. The user's tools were parsing that line
successfully before the vault touched it. So the vault now records, per variable per target
file, whether the original value was unquoted, single-quoted or double-quoted — in
`target_styles.json` beside `targets.json`, whose `{path: [names]}` shape is unchanged. When
`swap` writes a real value back, it re-emits the value in that same style, escaping only what
that style requires. For a variable with no recorded style (a registry written before 1.6.0, or
a name whose original line was already a placeholder), it falls back to the auto policy below.

This sidesteps the "which family" question for the common case: the file goes back to being,
byte-for-byte on the managed lines, what it was before migration.

### The auto policy, for when the style is unknown

1. Unquoted if the value is in the universal-safe set above.
2. Otherwise single-quoted if the value contains no `'` — literal in every parser that honours
   quotes (and immune to interpolation in all of them except python-dotenv's `${...}` form);
   wrong only for the three literal parsers, where any quoted representation is wrong anyway.
   The tool result notes it.
3. Otherwise double-quoted with `\"` and `\\` escaped. Node dotenv will deliver the `\"`
   literally; the tool result says so.

The faithful re-emission for a recorded style is the exact inverse of what migration parsed:
a double-quoted original gets only its `"` re-escaped (a `\n` the user wrote stays two
characters, as their loader always saw it), a single-quoted original gets only its `'`
re-escaped, an unquoted original goes back raw unless it would now misparse (leading or
trailing whitespace, a `whitespace #` sequence), in which case the auto policy takes over.

Values containing a newline are refused — the run stops before the command starts and nothing
is written — exactly as `materialize` refuses them.

### What `swap` will not do

- Touch a file that is not a registered `install_migrate` target. Only lines whose name is in
  that target's own registered set are rewritten; everything else — comments, other variables,
  indentation, `export` prefixes, line endings — passes through untouched, exactly as
  `resync_targets` does.
- Run in the background. A detached process has no exit moment at which to restore the
  placeholders, and a `.env` full of real values left behind indefinitely is the outcome this
  tool exists to prevent.
- Rewrite a line whose current value is not the placeholder it expects. A hand-edited real value
  is reported as a conflict, not overwritten.
- Leave real values behind after a crash without a record. Every swap is journaled before the
  first byte is written, and the journal is reconciled at the next server start, the next
  `vault_status`, `resync_targets` or `run_with_env` call — using a per-line digest so a value the
  *user* typed during the run is never mistaken for one the vault wrote.

---

## 5. Recipes by consumer

| You run… | Call |
|---|---|
| `python app.py` reading `os.environ`; `docker compose up` with `${VAR}` interpolation; anything under mechanism A or B | `run_with_env(command=[...], only_vars=[...])` |
| **pytest whose tests build a scrubbed child env**, or any typed settings loader (pydantic-settings, django-environ, Spring) that must PARSE `.env` | `retype_placeholders()` once. Nothing at run time — the file parses on its own, with the vault not involved. See §6. |
| `docker run --env-file .env.runtime` (a fresh path) | `run_with_env(..., materialize=".env.runtime", max_reads=1)` — the file is emptied the moment docker has read it |
| `docker compose up` with `env_file: .env.runtime` | `run_with_env(..., materialize=".env.runtime", max_reads=2)` — compose reads it twice |
| `kubectl create secret --from-env-file .env.runtime` | `run_with_env(..., materialize=".env.runtime", max_reads=1)`; note kubectl keeps quotes literally |
| An IDE debug session that reads `envFile` | launch the IDE itself through the vault so every terminal and debug session inherits the real env: `run_with_env(command=["code", "."], background=True, only_vars=[...])` |
| `load_dotenv(override=True)`, `source .env`, or a tool hard-wired to read the canonical `.env` and nothing else | **Not supported.** Point the tool at a materialize path if it accepts one; otherwise change the tool. 1.6–1.7 answered this with `swap=`, which is retired — see the header. |

---

## 6. Implemented in 2.0.0: typed placeholders (mechanism F, and B-when-scrubbed)

`SMTP_PORT="value 17"` fails `int` validation in pydantic-settings, django-environ and Spring
even when the vault is not involved in the run at all — the placeholder-only file is simply not
parseable as the types the app declares. A **typed placeholder** preserves the shape of the
value and nothing else, so the file parses:

| Real value looks like | Placeholder for index N | Notes |
|---|---|---|
| an integer | `N` | the index number stays visible, as `"value N"` established |
| `0` or `1` | `0` | never the real bit — that is one bit of content |
| true/false/yes/no/on/off | `false` | never the real truthiness |
| a float | `N.0` | |
| `<scheme>://…` | `<scheme>://placeholder-N.invalid` | scheme kept: `PostgresDsn` rejects `https://`. `.invalid` is reserved by RFC 2606 and can never resolve, so a placeholder that escapes into a real config fails closed |
| an email address | `placeholder-N@example.invalid` | |
| `[…]` / `{…}` | `[]` / `{}` | |
| anything else | `"value N"` | an opaque string has no shape to preserve, so it is unchanged |

**What this discloses:** the TYPE of each value, and a URL's scheme. Never content. The bool of
a variable that is really `true` renders `false`; a port of `2525` renders its index number.
`placeholder_style: "opaque"` opts out entirely.

**The deferral reason, and how it was answered.** This was deferred from 1.6.0 partly because it
"widens the `PLACEHOLDER_VALUE_RE` that `resync_targets`' conflict detection relies on". That
turned out to be the wrong fix rather than a blocker: a regex loose enough to match `17` cannot
tell a placeholder from a real port, so widening it would have broken the guard no matter how
carefully it was written. **The regex is unchanged.** Detection is index-aware and exact
instead — a line is one of ours if it matches the legacy regex, or if it equals the one string
this name's number and shape render to. That is stricter than 1.x for a typed name and
identical for an untyped one.

**Two consequences worth knowing:**

- *Numbers are never recycled.* A freed index number handed to a different variable is the only
  way a placeholder already written into a file can come to mean something else, and for a typed
  one that drift is unrecoverable — `SMTP_PORT=17` where 17 is now someone else's number cannot
  be told from a real port. 2.0 retires numbers instead of reusing them.
- *A shape tombstone outlives its secret.* `placeholder_shapes.json` is never pruned when a
  secret is removed. Without the entry, a typed placeholder left behind for a departed name is
  indistinguishable from a real value, and `resync_targets`' data-loss guard would silently stop
  counting the very lines it protects.

**What it does not fix.** Mechanisms C and D (a loader that lets the file win, a shell that
sources it) and any reader hard-wired to the canonical `.env`: those need the real value, and a
correctly-parsing placeholder is still not the secret. `materialize` serves the subset that
accepts a path. A test that assumes *no* `.env` exists at all (asserting "unset" while a real
file is on disk) is a non-hermetic test, and no vault behaviour can make it pass — it would fail
identically against the original real `.env`.

**Acceptance.** `tests/test_consumption_matrix.py` runs a real `pydantic-settings` class with
typed fields against a placeholder-only file using plain `subprocess.run` — no vault, no
injection, no dialog. The control (legacy placeholders) fails with "should be a valid integer"
and "should be a valid boolean"; the typed file loads. The scrubbed-harness case, which is what
a pre-push hook does and what `swap=` was refused for, is covered the same way.

---

## 7. Sources consulted for this document

All URLs are inline above. Docker's env-file parser has moved from `moby/moby`'s
`opts/envfile.go` to `docker/cli`'s `pkg/kvfile` — cite the latter for current behaviour.
Research date: 2026-09-15.
