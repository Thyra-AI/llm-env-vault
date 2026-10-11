# Thyra Vault web (Turborepo)

The only user interface of Thyra Vault (the `thyra-vault` plugin): the consent dialogs an assistant
triggers and the app you open yourself. pnpm workspaces + Turborepo.

The page holds **no vault logic**. The Python server (`src/webui/`) sends it *screens*
(titles, text, fields, buttons, as i18n keys plus parameters); the page draws them and reports
which button was pressed. So adding or changing a dialog is a Python change in
`src/webui/flows.py`, and the React app only needs new strings.

```bash
pnpm install
pnpm build:embed    # typecheck + build, then copy to ../src/web_dist (committed)
pnpm typecheck && pnpm lint
```

There is no mock gallery any more: the page is only useful talking to the Python server, and it
is always the real one. To work on it with live reload of the build, in two terminals:

```bash
pnpm --filter web exec vite build --watch      # rebuilds apps/web/dist on every save
THYRA_VAULT_WEB_ASSETS=web/apps/web/dist python -m src.webui_demo app     # a throwaway vault
```

(`webui_demo --list` shows every dialog, e.g. `unlock-run`, `first-run`, `recovery-key`.) Reload the
window after a rebuild. Run the demo from the repository root, with the repo's Python dependencies.

| Path | Purpose |
|---|---|
| `apps/web` | Vite + React app: `LiveSession` (talks to Python), `ScreenView` (renders any dialog screen), `components/app/` (the app: lock screen, list, generator, settings) |
| `packages/ui` | `@workspace/ui`: shadcn/ui (radix-nova) plus animated registry components, theme, `globals.css` |
| `packages/i18n` | `@workspace/i18n`: en, it, fr, de, es, pt-PT, pt-BR, the same set as the Thyra platform |

## Screen protocol

`apps/web/src/protocol.ts` is the TypeScript mirror of `src/webui/schema.py`. Blocks:
`text`, `notice`, `code`, `items`, `keyBox`, `copy`, `menu`, `itemHeader`, `fields`, `history`.
Fields: `password`, `text`, `textarea`, `checkbox`. A screen may also carry `app` (the app frame) and `toast`. Every string is `{ key, params }`; untrusted text (paths, commands, variable names) is
sanitised in Python and rendered as text, never HTML.

Add a string: add the key to **all seven** `packages/i18n/src/locales/*/translation.json` files.
`tests/test_webui_flows.py` and `tests/test_appflow*.py` drive the flows. Keep the seven files in step: every locale must have exactly the keys of `en`, with the same `{{placeholders}}`.

## Components

Always shadcn first, then the animated registries, in this order of preference:
`@shadcn` > `@reui` > `@magicui` > `@motion-primitives` > `@kokonutui` > `@cult-ui` / `@coss` / `@aceternity`.

```bash
node scripts/shadcn-add.mjs button @magicui/blur-fade
```

`scripts/shadcn-add.mjs` does what `shadcn add` does (resolves registry dependencies, rewrites
imports to `@workspace/ui/*`, swaps icons for lucide, installs npm deps) but downloads items with
curl, because the public registries sometimes answer 403 to the shadcn CLI's Node HTTP client.
Prefer `pnpm dlx shadcn@latest add` when it works.

In use: shadcn button, input, input-group, field, checkbox, alert, badge, card, dropdown-menu,
select, progress, item, sonner, spinner, label, separator, textarea, toggle, toggle-group, tooltip; Magic UI `animated-theme-toggler`, `border-beam`;
Motion Primitives `transition-panel`, `animated-group`; Kokonut UI `use-copy-to-clipboard`;
ReUI password patterns (`c-input-group-35`, `c-input-23`).

## Production build

`pnpm build:embed` writes `src/web_dist/`, which the plugin ships so users need no Node.
Because the plugin directory validator rejects what it cannot inspect, the build is **unminified,
sourcemap-free and binary-free**: no font files (a system font stack, with Public Sans, Archivo and
IBM Plex Mono used when installed) and no inlined assets. It also gets a strict
`Content-Security-Policy` meta tag at build time, and the Python server sends the same policy as a
header.

Preferences (language, theme) are stored per origin, and each dialog uses a fresh random port, so
they do not carry from one dialog to the next; the browser's own language and colour scheme apply.
