import { useId } from 'react'
import { Field, FieldLabel } from '@workspace/ui/components/field'
import { Textarea } from '@workspace/ui/components/textarea'
import { cn } from '@workspace/ui/lib/utils'

interface TextareaFieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  rows?: number
  mono?: boolean
  autoFocus?: boolean
}

/** Multi-line input (notes, private keys). Spell-check and autofill stay off: the text is often a secret. */
export function TextareaField({ label, value, onChange, rows = 4, mono, autoFocus }: TextareaFieldProps) {
  const id = useId()
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Textarea
        id={id}
        value={value}
        rows={rows}
        onChange={(e) => onChange(e.target.value)}
        className={cn('max-h-64 resize-y', mono && 'font-mono text-xs')}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
      />
    </Field>
  )
}
