import { Eye, EyeOff, Lock } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useId, useState } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Field, FieldLabel } from '@workspace/ui/components/field'
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupInput } from '@workspace/ui/components/input-group'
import { PasswordStrength } from './PasswordStrength'

interface PasswordFieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  autoComplete?: string
  autoFocus?: boolean
  showToggle?: boolean
  strength?: boolean
  invalid?: boolean
}

/** Password input: shadcn Field + InputGroup, visibility toggle pattern from @reui/c-input-group-35. */
export function PasswordField({ label, value, onChange, autoComplete = 'current-password', autoFocus, showToggle = true, strength, invalid }: PasswordFieldProps) {
  const { t } = useTranslation()
  const id = useId()
  const [visible, setVisible] = useState(false)
  const Icon = visible ? EyeOff : Eye
  return (
    <Field data-invalid={invalid ? true : undefined}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <InputGroup>
        <InputGroupAddon>
          <Lock aria-hidden />
        </InputGroupAddon>
        <InputGroupInput
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          spellCheck={false}
          autoCapitalize="off"
          aria-invalid={invalid ? true : undefined}
        />
        {showToggle && (
          <InputGroupAddon align="inline-end">
            <InputGroupButton size="icon-xs" aria-label={visible ? t('common.hide') : t('common.show')} aria-pressed={visible} onClick={() => setVisible((v) => !v)}>
              <AnimatePresence initial={false} mode="wait">
                <motion.span
                  key={String(visible)}
                  initial={{ opacity: 0, scale: 0.6, rotate: -20 }}
                  animate={{ opacity: 1, scale: 1, rotate: 0 }}
                  exit={{ opacity: 0, scale: 0.6, rotate: 20 }}
                  transition={{ duration: 0.12 }}
                  className="flex"
                >
                  <Icon aria-hidden />
                </motion.span>
              </AnimatePresence>
            </InputGroupButton>
          </InputGroupAddon>
        )}
      </InputGroup>
      {strength && <PasswordStrength value={value} />}
    </Field>
  )
}
