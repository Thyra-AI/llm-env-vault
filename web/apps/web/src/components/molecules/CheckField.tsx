import { useId, type ReactNode } from 'react'
import { Checkbox } from '@workspace/ui/components/checkbox'
import { Field, FieldLabel } from '@workspace/ui/components/field'

export function CheckField({ children, checked, onCheckedChange }: { children: ReactNode; checked: boolean; onCheckedChange: (v: boolean) => void }) {
  const id = useId()
  return (
    <Field orientation="horizontal">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onCheckedChange(v === true)} />
      <FieldLabel htmlFor={id} className="cursor-pointer font-normal leading-snug">
        {children}
      </FieldLabel>
    </Field>
  )
}
