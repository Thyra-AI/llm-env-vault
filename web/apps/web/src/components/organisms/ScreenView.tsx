import { useEffect, useRef, useState } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { Spinner } from '@workspace/ui/components/spinner'
import { BlockView, ICONS, CheckField, PasswordField, TextareaField, TextField, useMsg } from '@/components/molecules'
import { Notice } from '@/components/molecules/Notice'
import type { Field, FormValues, Screen } from '@/protocol'
import { DialogWindow } from './DialogWindow'

function blank(fields: Field[]): FormValues {
  return Object.fromEntries(fields.map((f) => [f.name, f.type === 'checkbox' ? false : (f.initial ?? '')]))
}

interface ScreenViewProps {
  screen: Screen
  busy: boolean
  onAction: (actionId: string, values: FormValues) => void
}

/**
 * Renders one screen sent by a Python flow. The page owns no vault logic: it
 * shows what it is told, collects the form, and reports which button was
 * pressed. Mount it with `key={screen.title.key}` so a new step starts with
 * fresh fields while an error on the same step keeps what was typed.
 */
export function ScreenView({ screen, busy, onAction }: ScreenViewProps) {
  const { t } = useTranslation()
  const { msg, error } = useMsg()
  const [values, setValues] = useState<FormValues>(() => blank(screen.fields))
  const [pending, setPending] = useState<string | null>(null)
  const formRef = useRef<HTMLFormElement>(null)

  // A new screen has arrived (same step, or the next one).
  useEffect(() => {
    setPending(null)
    if (!screen.error) return
    // A message that came from the vault itself (e.g. wrong password) means the
    // password just typed is no good: clear it rather than leave it on screen.
    if ('raw' in screen.error) {
      setValues((v) => {
        const next = { ...v }
        for (const f of screen.fields) if (f.type === 'password') next[f.name] = ''
        return next
      })
    }
    formRef.current?.querySelector<HTMLInputElement>('input:not([type=checkbox])')?.focus()
  }, [screen.id])

  const set = (name: string, value: string | boolean) => setValues((v) => ({ ...v, [name]: value }))
  const fire = (id: string) => {
    if (busy) return
    setPending(id)
    onAction(id, values)
  }

  const invalid = !!screen.error
  const body = [
    ...screen.blocks.map((b, i) => <BlockView key={`b${i}`} block={b} onMenu={(id) => fire(`menu:${id}`)} />),
    ...screen.fields.map((f) => {
      if (f.type === 'password') {
        return (
          <PasswordField
            key={f.name}
            label={msg(f.label)}
            value={String(values[f.name] ?? '')}
            onChange={(v) => set(f.name, v)}
            autoComplete={f.new ? 'new-password' : 'current-password'}
            autoFocus={f.autofocus}
            showToggle={f.toggle}
            strength={f.strength}
            invalid={invalid}
          />
        )
      }
      if (f.type === 'textarea') {
        return (
          <TextareaField key={f.name} label={msg(f.label)} value={String(values[f.name] ?? '')} onChange={(v) => set(f.name, v)}
            rows={f.rows} mono={f.mono} autoFocus={f.autofocus} />
        )
      }
      if (f.type === 'text') {
        return (
          <TextField key={f.name} label={msg(f.label)} value={String(values[f.name] ?? '')} onChange={(v) => set(f.name, v)}
            mono={f.mono} placeholder={f.placeholder} autoFocus={f.autofocus} />
        )
      }
      return (
        <CheckField key={f.name} checked={values[f.name] === true} onCheckedChange={(v) => set(f.name, v)}>
          {msg(f.label)}
        </CheckField>
      )
    }),
    ...(screen.error ? [<Notice key="error" tone="danger">{error(screen.error)}</Notice>] : []),
  ]

  const actions = screen.actions.map((a) => {
    const primaryish = a.variant !== 'outline'
    return (
      <Button
        key={a.id}
        type="button"
        variant={a.variant === 'primary' ? 'default' : a.variant === 'danger' ? 'destructive' : 'outline'}
        disabled={busy}
        onClick={() => fire(a.id)}
      >
        {busy && pending === a.id && primaryish && <Spinner aria-hidden />}
        {busy && pending === a.id && primaryish ? t('common.working') : msg(a.label)}
      </Button>
    )
  })

  return (
    <form
      ref={formRef}
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        if (screen.defaultAction) fire(screen.defaultAction)
      }}
    >
      <DialogWindow
        title={msg(screen.title)}
        icon={ICONS[screen.icon]}
        step={screen.step}
        badge={screen.badge ? msg(screen.badge) : undefined}
        tone={screen.tone === 'danger' ? 'danger' : 'default'}
        actions={actions}
      >
        {body}
      </DialogWindow>
      {screen.defaultAction && <button type="submit" className="sr-only" tabIndex={-1} aria-hidden />}
    </form>
  )
}
