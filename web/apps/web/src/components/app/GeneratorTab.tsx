import { Copy, RefreshCw } from 'lucide-react'
import { motion, useAnimationControls } from 'motion/react'
import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { Checkbox } from '@workspace/ui/components/checkbox'
import { Input } from '@workspace/ui/components/input'
import { Label } from '@workspace/ui/components/label'
import { ToggleGroup, ToggleGroupItem } from '@workspace/ui/components/toggle-group'
import { cn } from '@workspace/ui/lib/utils'
import { generate, LENGTH_RANGE, pieces, WORDS_RANGE, type GeneratorOptions } from './generator'

const MODES = ['password', 'passphrase', 'username'] as const

function NumberField({ label, value, min, max, onChange, hint }: { label: string; value: number; min: number; max: number; onChange: (n: number) => void; hint?: string }) {
  const id = useId()
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        value={Number.isFinite(value) ? value : ''}
        onChange={(e) => onChange(e.target.value === '' ? NaN : Number(e.target.value))}
        onBlur={() => onChange(Math.min(max, Math.max(min, Number.isFinite(value) ? Math.round(value) : min)))}
        className="h-10 rounded-xl"
      />
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

function Option({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: React.ReactNode }) {
  const id = useId()
  return (
    <div className="flex items-center gap-2">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onChange(v === true)} />
      <Label htmlFor={id} className="text-sm font-normal">{children}</Label>
    </div>
  )
}

interface GeneratorTabProps {
  initial: GeneratorOptions
  onPersist: (options: GeneratorOptions) => void
  /** Copy through the server, so the clipboard is wiped on a timer like every other copy. */
  onCopy: (text: string) => void
}

/** Password / passphrase / username generator. Runs entirely in the page: it never touches the vault. */
export function GeneratorTab({ initial, onPersist, onCopy }: GeneratorTabProps) {
  const { t } = useTranslation()
  const [opts, setOpts] = useState<GeneratorOptions>(initial)
  const [value, setValue] = useState(() => generate(initial))
  const spin = useAnimationControls()
  const persistTimer = useRef<number | undefined>(undefined)

  const set = <K extends keyof GeneratorOptions>(key: K, v: GeneratorOptions[K]) => setOpts((o) => ({ ...o, [key]: v }))

  const clamp = (n: number, lo: number, hi: number) => (Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : lo)
  const regenerate = useCallback(() => {
    setValue(generate({ ...opts, length: clamp(opts.length, LENGTH_RANGE.min, LENGTH_RANGE.max), words: clamp(opts.words, WORDS_RANGE.min, WORDS_RANGE.max) }))
  }, [opts])

  // New value whenever an option changes; remember the options (debounced) so the next launch starts here.
  const first = useRef(true)
  useEffect(() => {
    if (first.current) {
      first.current = false
      return
    }
    regenerate()
    window.clearTimeout(persistTimer.current)
    persistTimer.current = window.setTimeout(
      () => onPersist({ ...opts, length: clamp(opts.length, LENGTH_RANGE.min, LENGTH_RANGE.max), words: clamp(opts.words, WORDS_RANGE.min, WORDS_RANGE.max) }),
      700,
    )
    return () => window.clearTimeout(persistTimer.current)
  }, [opts])

  const copy = () => onCopy(value)

  return (
    <div className="flex flex-col gap-4 px-4 pt-3 pb-5">
      <ToggleGroup
        type="single"
        value={opts.mode}
        onValueChange={(v) => v && set('mode', v as GeneratorOptions['mode'])}
        variant="outline"
        className="w-full rounded-xl"
        aria-label={t('vaultApp.tabs.generator')}
      >
        {MODES.map((m) => (
          <ToggleGroupItem key={m} value={m} className="h-9 flex-1 text-sm">
            {t(`vaultApp.generator.${m}`)}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>

      <div className="flex items-center gap-2 rounded-xl border bg-card p-3">
        <output aria-live="polite" className="min-w-0 flex-1 font-mono text-base leading-relaxed break-all">
          {pieces(value).map((p, i) => (
            <span key={i} className={cn(p.kind === 'digit' && 'text-primary', p.kind === 'symbol' && 'text-amber-500')}>
              {p.text}
            </span>
          ))}
        </output>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={t('vaultApp.generator.regenerate')}
          onClick={() => {
            regenerate()
            void spin.start({ rotate: [0, 360], transition: { duration: 0.45, ease: 'easeOut' } })
          }}
        >
          <motion.span animate={spin} className="flex">
            <RefreshCw aria-hidden />
          </motion.span>
        </Button>
        <Button type="button" variant="ghost" size="icon" aria-label={t('vaultApp.generator.copy')} onClick={copy}>
          <Copy aria-hidden />
        </Button>
      </div>

      {opts.mode === 'password' && (
        <>
          <section className="flex flex-col gap-3 rounded-xl border bg-card p-4">
            <h2 className="text-sm font-semibold">{t('vaultApp.generator.options')}</h2>
            <NumberField label={t('vaultApp.generator.length')} value={opts.length} min={LENGTH_RANGE.min} max={LENGTH_RANGE.max} onChange={(n) => set('length', n)}
              hint={t('vaultApp.generator.lengthHint', LENGTH_RANGE)} />
          </section>
          <section className="flex flex-col gap-3 rounded-xl border bg-card p-4">
            <h2 className="text-sm font-semibold">{t('vaultApp.generator.include')}</h2>
            <div className="grid grid-cols-2 gap-x-3 gap-y-2.5">
              <Option checked={opts.upper} onChange={(v) => set('upper', v)}>A-Z</Option>
              <Option checked={opts.lower} onChange={(v) => set('lower', v)}>a-z</Option>
              <Option checked={opts.digits} onChange={(v) => set('digits', v)}>0-9</Option>
              <Option checked={opts.symbols} onChange={(v) => set('symbols', v)}>!@#$%^&*</Option>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <NumberField label={t('vaultApp.generator.minNumbers')} value={opts.minDigits} min={0} max={9} onChange={(n) => set('minDigits', n)} />
              <NumberField label={t('vaultApp.generator.minSpecial')} value={opts.minSymbols} min={0} max={9} onChange={(n) => set('minSymbols', n)} />
            </div>
            <Option checked={opts.avoidAmbiguous} onChange={(v) => set('avoidAmbiguous', v)}>{t('vaultApp.generator.avoidAmbiguous')}</Option>
          </section>
        </>
      )}

      {opts.mode === 'passphrase' && (
        <section className="flex flex-col gap-3 rounded-xl border bg-card p-4">
          <h2 className="text-sm font-semibold">{t('vaultApp.generator.options')}</h2>
          <div className="grid grid-cols-2 gap-3">
            <NumberField label={t('vaultApp.generator.words')} value={opts.words} min={WORDS_RANGE.min} max={WORDS_RANGE.max} onChange={(n) => set('words', n)} />
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="gen-sep">{t('vaultApp.generator.separator')}</Label>
              <Input id="gen-sep" value={opts.separator} maxLength={1} onChange={(e) => set('separator', e.target.value.slice(0, 1))} className="h-10 rounded-xl font-mono" />
            </div>
          </div>
          <Option checked={opts.capitalize} onChange={(v) => set('capitalize', v)}>{t('vaultApp.generator.capitalize')}</Option>
          <Option checked={opts.includeNumber} onChange={(v) => set('includeNumber', v)}>{t('vaultApp.generator.includeNumber')}</Option>
        </section>
      )}
    </div>
  )
}
