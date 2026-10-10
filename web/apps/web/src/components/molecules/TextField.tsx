import { useId } from 'react'
import { Field, FieldLabel } from '@workspace/ui/components/field'
import { Input } from '@workspace/ui/components/input'
import { cn } from '@workspace/ui/lib/utils'

interface TextFieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  mono?: boolean
  placeholder?: string
  autoFocus?: boolean
}

export function TextField({ label, value, onChange, mono, placeholder, autoFocus }: TextFieldProps) {
  const id = useId()
  return (
    <Field>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn(mono && 'font-mono')}
        placeholder={placeholder}
        autoFocus={autoFocus}
        autoComplete="off"
        autoCapitalize="off"
        spellCheck={false}
      />
    </Field>
  )
}
