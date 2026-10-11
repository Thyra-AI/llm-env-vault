import { WORDS } from './wordlist'

/** Mirrors thyra_vault/webui/prefs.py DEFAULT_GENERATOR (the server validates the same ranges). */
export interface GeneratorOptions {
  mode: 'password' | 'passphrase' | 'username'
  length: number
  upper: boolean
  lower: boolean
  digits: boolean
  symbols: boolean
  minDigits: number
  minSymbols: number
  avoidAmbiguous: boolean
  words: number
  separator: string
  capitalize: boolean
  includeNumber: boolean
}

export const LENGTH_RANGE = { min: 5, max: 128 } as const
export const WORDS_RANGE = { min: 3, max: 20 } as const

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const DIGITS = '0123456789'
const SYMBOLS = '!@#$%^&*'
const AMBIGUOUS = /[Il1O0o]/g

/** Uniform integer in [0, max) from the platform CSPRNG, without modulo bias. */
function randomInt(max: number): number {
  if (!Number.isInteger(max) || max < 1 || max > 2 ** 32) throw new RangeError('max out of range')
  const limit = Math.floor(2 ** 32 / max) * max
  const buf = new Uint32Array(1)
  do crypto.getRandomValues(buf)
  while (buf[0] >= limit)
  return buf[0] % max
}

const pick = (set: string) => set[randomInt(set.length)]

function shuffle<T>(items: T[]): T[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    ;[items[i], items[j]] = [items[j], items[i]]
  }
  return items
}

const clean = (set: string, avoid: boolean) => (avoid ? set.replace(AMBIGUOUS, '') : set)

function generatePassword(o: GeneratorOptions): string {
  const sets = [
    o.upper && clean(UPPER, o.avoidAmbiguous),
    o.lower && clean(LOWER, o.avoidAmbiguous),
    o.digits && clean(DIGITS, o.avoidAmbiguous),
    o.symbols && SYMBOLS,
  ].filter((s): s is string => !!s)
  // With every class switched off, fall back to letters and digits rather than return nothing.
  const pool = (sets.length ? sets : [clean(LOWER, o.avoidAmbiguous), clean(DIGITS, o.avoidAmbiguous)]).join('')
  const length = Math.min(LENGTH_RANGE.max, Math.max(LENGTH_RANGE.min, Math.round(o.length)))

  const chars: string[] = []
  if (o.digits) for (let i = 0; i < o.minDigits; i++) chars.push(pick(clean(DIGITS, o.avoidAmbiguous)))
  if (o.symbols) for (let i = 0; i < o.minSymbols; i++) chars.push(pick(SYMBOLS))
  // One of each chosen class first, so "include" means "contains at least one".
  for (const s of sets) if (chars.length < length) chars.push(pick(s))
  while (chars.length < length) chars.push(pick(pool))
  return shuffle(chars.slice(0, length)).join('')
}

function generatePassphrase(o: GeneratorOptions): string {
  const count = Math.min(WORDS_RANGE.max, Math.max(WORDS_RANGE.min, Math.round(o.words)))
  const words = Array.from({ length: count }, () => WORDS[randomInt(WORDS.length)])
  const shown = o.capitalize ? words.map((w) => w[0].toUpperCase() + w.slice(1)) : words
  if (o.includeNumber) {
    const i = randomInt(shown.length)
    shown[i] += pick(DIGITS)
  }
  return shown.join(o.separator)
}

const ADJECTIVES = ['brave', 'calm', 'clever', 'eager', 'gentle', 'lucky', 'mighty', 'quiet', 'swift', 'witty', 'bold', 'bright']
const NOUNS = ['falcon', 'harbor', 'maple', 'comet', 'ember', 'otter', 'pebble', 'raven', 'summit', 'thistle', 'willow', 'zephyr']

function generateUsername(): string {
  const two = `${pick(DIGITS)}${pick(DIGITS)}`
  return `${ADJECTIVES[randomInt(ADJECTIVES.length)]}${NOUNS[randomInt(NOUNS.length)]}${two}`
}

export function generate(o: GeneratorOptions): string {
  if (o.mode === 'passphrase') return generatePassphrase(o)
  if (o.mode === 'username') return generateUsername()
  return generatePassword(o)
}

type Piece = { text: string; kind: 'letter' | 'digit' | 'symbol' }

/** Split into runs so digits and symbols can be coloured, as password managers do. */
export function pieces(value: string): Piece[] {
  const out: Piece[] = []
  for (const ch of value) {
    const kind = /[0-9]/.test(ch) ? 'digit' : /[A-Za-z]/.test(ch) ? 'letter' : 'symbol'
    const last = out[out.length - 1]
    if (last && last.kind === kind) last.text += ch
    else out.push({ text: ch, kind })
  }
  return out
}
