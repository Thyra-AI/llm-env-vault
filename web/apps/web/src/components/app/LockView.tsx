import { FolderLock, LifeBuoy, X } from 'lucide-react'
import { motion } from 'motion/react'
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { Spinner } from '@workspace/ui/components/spinner'
import { CheckField, Notice, PasswordField, ThyraLogo, useMsg } from '@/components/molecules'
import type { FormValues, Screen } from '@/protocol'

/** The padlock with the "***__" bar: original artwork in the Thyra palette. */
function LockIllustration() {
  return (
    <motion.svg
      viewBox="0 0 120 120"
      className="size-28"
      role="img"
      aria-hidden
      initial={{ opacity: 0, y: 10, scale: 0.94 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ type: 'spring', stiffness: 220, damping: 22 }}
    >
      <path d="M38 52V38a22 22 0 0 1 44 0v14" fill="none" stroke="var(--primary)" strokeWidth="9" strokeLinecap="round" />
      <rect x="20" y="50" width="80" height="58" rx="14" fill="var(--primary)" opacity="0.22" />
      <rect x="20" y="50" width="80" height="58" rx="14" fill="none" stroke="var(--primary)" strokeWidth="4" />
      <rect x="28" y="68" width="64" height="22" rx="11" fill="#f5b301" />
      <g fill="var(--background)" fontFamily="ui-monospace, monospace" fontSize="17" fontWeight="700" textAnchor="middle">
        <text x="40" y="86">*</text>
        <text x="55" y="86">*</text>
        <text x="70" y="86">*</text>
      </g>
      <rect x="76" y="82" width="9" height="3.2" rx="1.6" fill="var(--background)" />
    </motion.svg>
  )
}

interface LockViewProps {
  screen: Screen
  busy: boolean
  onAction: (actionId: string, values: FormValues) => void
}

/** Locked / first-run screen. The page only collects what the server asked for. */
export function LockView({ screen, busy, onAction }: LockViewProps) {
  const { t } = useTranslation()
  const { msg, error } = useMsg()
  const app = screen.app
  const [values, setValues] = useState<FormValues>({ password: '', confirm: '', recovery: false })
  const [pending, setPending] = useState<string | null>(null)
  const form = useRef<HTMLFormElement>(null)
  const firstRun = app?.view === 'lock' && app.firstRun

  useEffect(() => {
    setPending(null)
    if (screen.error && 'raw' in screen.error) setValues((v) => ({ ...v, password: '' }))
    form.current?.querySelector<HTMLInputElement>('input')?.focus()
  }, [screen.id])

  const fire = (id: string) => {
    if (busy) return
    setPending(id)
    onAction(id, values)
    // Never keep the password around once it has been sent.
    if (id === 'continue') setValues((v) => ({ ...v, password: '', confirm: '' }))
  }
  const primary = screen.actions.find((a) => a.variant === 'primary')
  const secondary = screen.actions.filter((a) => a.variant !== 'primary')
  const field = (name: string) => screen.fields.find((f) => f.name === name)

  return (
    <form
      ref={form}
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        if (screen.defaultAction) fire(screen.defaultAction)
      }}
      className="mx-auto flex min-h-dvh w-full max-w-sm flex-col gap-5 px-5 py-6"
    >
      <header className="flex items-center justify-between">
        <ThyraLogo />
      </header>

      <div className="flex flex-col items-center gap-3 text-center">
        <LockIllustration />
        <h1 className="font-heading text-2xl font-semibold tracking-tight">{msg(screen.title)}</h1>
        {app?.view === 'lock' && (
          <p className="flex max-w-full items-center gap-1.5 text-sm text-muted-foreground" title={app.location}>
            <FolderLock className="size-4 shrink-0" aria-hidden />
            <span className="truncate">{app.location}</span>
          </p>
        )}
      </div>

      {screen.blocks.map((b, i) =>
        b.type === 'text' ? (
          <p key={i} className="text-sm text-muted-foreground">{msg(b.msg)}</p>
        ) : null,
      )}

      <div className="flex flex-col gap-4">
        {field('password') && (
          <PasswordField
            label={msg(field('password')!.label)}
            value={String(values.password ?? '')}
            onChange={(v) => setValues((s) => ({ ...s, password: v }))}
            autoComplete={firstRun ? 'new-password' : 'current-password'}
            autoFocus
            strength={firstRun}
            invalid={!!screen.error}
          />
        )}
        {field('confirm') && (
          <PasswordField
            label={msg(field('confirm')!.label)}
            value={String(values.confirm ?? '')}
            onChange={(v) => setValues((s) => ({ ...s, confirm: v }))}
            autoComplete="new-password"
            showToggle={false}
            invalid={!!screen.error}
          />
        )}
        {field('recovery') && (
          <CheckField checked={values.recovery === true} onCheckedChange={(v) => setValues((s) => ({ ...s, recovery: v }))}>
            {msg(field('recovery')!.label)}
          </CheckField>
        )}
        {screen.error && <Notice tone="danger">{error(screen.error)}</Notice>}
      </div>

      <div className="flex flex-col gap-3">
        {primary && (
          <motion.div whileTap={{ scale: 0.985 }}>
            <Button type="button" size="lg" className="h-11 w-full rounded-xl text-sm font-semibold" disabled={busy} onClick={() => fire(primary.id)}>
              {busy && pending === primary.id && <Spinner aria-hidden />}
              {busy && pending === primary.id ? t('common.working') : msg(primary.label)}
            </Button>
          </motion.div>
        )}
        {secondary.length > 0 && <p className="text-center text-sm text-muted-foreground">{t('vaultApp.lock.or')}</p>}
        {secondary.map((a) => (
          <Button key={a.id} type="button" variant="outline" className="h-11 w-full rounded-xl" disabled={busy} onClick={() => fire(a.id)}>
            {a.id === 'recover' ? <LifeBuoy aria-hidden /> : <X aria-hidden />}
            {msg(a.label)}
          </Button>
        ))}
      </div>
      {screen.defaultAction && <button type="submit" className="sr-only" tabIndex={-1} aria-hidden />}
    </form>
  )
}
