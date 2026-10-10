#!/usr/bin/env node
// Copies the production build of apps/web into ../thyra_vault/web_dist, which the
// Python server (thyra_vault/webui/server.py) serves. The result is committed, so
// users of the plugin never need Node: `git clone` is the whole install.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const src = path.join(root, 'apps/web/dist')
const dest = path.resolve(root, '../thyra_vault/web_dist')

if (!existsSync(path.join(src, 'index.html'))) {
  console.error('apps/web/dist is missing: run `pnpm build` first.')
  process.exit(1)
}
rmSync(dest, { recursive: true, force: true })
mkdirSync(dest, { recursive: true })
cpSync(src, dest, { recursive: true })

let files = 0
let bytes = 0
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name)
    if (statSync(p).isDirectory()) walk(p)
    else {
      files += 1
      bytes += statSync(p).size
    }
  }
}
walk(dest)
console.log(`embedded ${files} files (${(bytes / 1024).toFixed(0)} KiB) into ${path.relative(root, dest)}`)
