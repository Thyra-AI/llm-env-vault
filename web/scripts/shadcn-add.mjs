#!/usr/bin/env node
// Installs shadcn-registry items (official @shadcn + third-party registries such as
// @magicui, @reui, @motion-primitives, @kokonutui, @cult-ui) into packages/ui,
// the same way `shadcn add` does. Items are downloaded with curl because the public
// registries sometimes answer 403 to the CLI's Node HTTP client.
//
//   node scripts/shadcn-add.mjs button @magicui/blur-fade @reui/stepper
import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// Registry content is UNTRUSTED. Item files are written verbatim into packages/ui/src (so they
// end up in the shipped bundle: review every generated diff), and dependency names go to `pnpm add`.
const SAFE_DEP = /^(@[a-z0-9~][a-z0-9._~-]*\/)?[a-z0-9~][a-z0-9._~-]*(@[\w.^~<>=*-]+)?$/

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const uiSrc = path.join(root, 'packages/ui/src')
const STYLE = 'radix-nova'

const REGISTRIES = {
  '@shadcn': (n) => [`https://ui.shadcn.com/r/styles/${STYLE}/${n}.json`],
  '@magicui': (n) => [`https://magicui.design/r/${n}`, `https://magicui.design/r/${n}.json`],
  '@reui': (n) => [`https://reui.io/r/${STYLE}/${n}.json`, `https://reui.io/r/base-nova/${n}.json`],
  '@motion-primitives': (n) => [`https://motion-primitives.com/c/${n}.json`],
  '@kokonutui': (n) => [`https://kokonutui.com/r/${n}.json`],
  '@cult-ui': (n) => [`https://cult-ui.com/r/${n}.json`],
  '@coss': (n) => [`https://coss.com/ui/r/${n}.json`],
  '@aceternity': (n) => [`https://ui.aceternity.com/registry/${n}.json`],
}

const seen = new Set()
const npmDeps = new Set()
const written = []

function curl(url) {
  try {
    return JSON.parse(execFileSync('curl', ['-sfL', '--max-time', '30', url], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }))
  } catch {
    return null
  }
}

function fetchItem(spec) {
  if (/^https?:\/\//.test(spec)) return { item: curl(spec), label: spec }
  const m = spec.match(/^(@[\w-]+)\/(.+)$/)
  const [ns, name] = m ? [m[1], m[2]] : ['@shadcn', spec]
  const urls = REGISTRIES[ns]?.(name)
  if (!urls) throw new Error(`Unknown registry ${ns}`)
  for (const u of urls) {
    const item = curl(u)
    if (item?.name) return { item, label: `${ns}/${name}` }
  }
  return { item: null, label: `${ns}/${name}` }
}

// shadcn's CLI swaps <IconPlaceholder lucide="X" tabler="..."/> for the project's icon library (lucide here).
function swapIcons(src) {
  const names = new Set()
  let out = src.replace(/<IconPlaceholder\b([\s\S]*?)\/>/g, (m, attrs) => {
    const name = attrs.match(/lucide="(\w+)"/)?.[1]
    if (!name) return m
    names.add(name)
    const rest = attrs.replace(/\s+(lucide|tabler|hugeicons|phosphor|remixicon)="[^"]*"/g, '')
    return `<${name}${rest}/>`
  })
  out = out.replace(/import \{ IconPlaceholder \} from "[^"]+"\n?/, '')
  if (names.size) {
    const imp = `import { ${[...names].sort().join(', ')} } from "lucide-react"\n`
    out = /^"use client"\n/.test(out) ? out.replace(/^("use client"\n+)/, `$1${imp}`) : imp + out
  }
  return out
}

function rewrite(src) {
  return swapIcons(src)
    .replace(/from (["'])cn\1/g, 'from "@workspace/ui/lib/utils"')
    .replace(/@\/registry\/[^/'"]+\/ui\//g, '@workspace/ui/components/')
    .replace(/@\/registry\/[^/'"]+\/hooks\//g, '@workspace/ui/hooks/')
    .replace(/@\/registry\/[^/'"]+\/lib\//g, '@workspace/ui/lib/')
    .replace(/@\/registry\/[^/'"]+\/(components|blocks|examples)\//g, '@workspace/ui/components/')
    .replace(/@\/components\/ui\//g, '@workspace/ui/components/')
    .replace(/@\/components\//g, '@workspace/ui/components/')
    .replace(/@\/hooks\//g, '@workspace/ui/hooks/')
    .replace(/@\/lib\//g, '@workspace/ui/lib/')
}

function destFor(file) {
  const base = path.basename(file.path)
  if (file.type === 'registry:hook') return path.join(uiSrc, 'hooks', base)
  if (file.type === 'registry:lib') return path.join(uiSrc, 'lib', base)
  return path.join(uiSrc, 'components', base)
}

function add(spec) {
  const { item, label } = fetchItem(spec)
  if (seen.has(label)) return
  seen.add(label)
  if (!item) {
    console.error(`  ✗ ${label}: not found`)
    process.exitCode = 1
    return
  }
  for (const dep of item.registryDependencies ?? []) add(dep)
  for (const d of [...(item.dependencies ?? []), ...(item.devDependencies ?? [])]) {
    if (d === 'cn' || d.startsWith('shadcn@') || d === 'tw-animate-css') continue
    if (!SAFE_DEP.test(d)) {
      // The registry is third-party input: a "dependency" like `--config=...`, `github:x/y`
      // or a tarball URL would be handed to `pnpm add`. Plain registry names only.
      console.error(`  ✗ ${label}: refusing dependency ${JSON.stringify(d)} (not a plain package name)`)
      process.exitCode = 1
      continue
    }
    npmDeps.add(d)
  }
  for (const f of item.files ?? []) {
    if (!f.content) continue
    const dest = destFor(f)
    mkdirSync(path.dirname(dest), { recursive: true })
    writeFileSync(dest, rewrite(f.content))
    written.push(path.relative(root, dest))
  }
  const extra = []
  if (item.css && Object.keys(item.css).length) extra.push('css')
  if (item.cssVars && Object.keys(item.cssVars).length) extra.push('cssVars')
  console.log(`  ✓ ${label}${extra.length ? `  (needs manual merge: ${extra.join(', ')})` : ''}`)
  if (extra.length) console.log(JSON.stringify({ css: item.css, cssVars: item.cssVars }))
}

const specs = process.argv.slice(2)
if (!specs.length) {
  console.error('usage: node scripts/shadcn-add.mjs <item> [...]')
  process.exit(2)
}
for (const s of specs) add(s)

if (npmDeps.size) {
  const list = [...npmDeps]
  console.log(`\nInstalling: ${list.join(' ')}`)
  execFileSync('pnpm', ['--filter', '@workspace/ui', 'add', ...list], { cwd: root, stdio: 'inherit' })
}
console.log(`\n${written.length} file(s) written to packages/ui/src`)
