import { motion } from 'motion/react'
import { useTranslation } from '@workspace/i18n'
import { cn } from '@workspace/ui/lib/utils'

/** Four-segment strength meter. Pattern adapted from @reui/c-input-23. */
function scorePassword(pw: string): number {
  return [pw.length >= 12, /[a-z]/.test(pw) && /[A-Z]/.test(pw), /\d/.test(pw), /[^A-Za-z0-9]/.test(pw)].filter(Boolean).length
}

const tone = ['bg-border', 'bg-destructive', 'bg-amber-500', 'bg-amber-500', 'bg-emerald-500']

export function PasswordStrength({ value }: { value: string }) {
  const { t } = useTranslation()
  const score = scorePassword(value)
  const label = score <= 1 ? t('strength.weak') : score <= 3 ? t('strength.fair') : t('strength.strong')
  return (
    <div className="flex flex-col gap-1.5" role="group" aria-label={t('strength.label')}>
      <div className="flex gap-1" role="progressbar" aria-valuemin={0} aria-valuemax={4} aria-valuenow={score}>
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-1 flex-1 overflow-hidden rounded-full bg-border">
            <motion.div
              className={cn('h-full rounded-full', tone[score])}
              initial={false}
              animate={{ width: i < score ? '100%' : '0%' }}
              transition={{ type: 'spring', stiffness: 260, damping: 28 }}
            />
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground" aria-live="polite">
        {t('strength.label')}: <span className="font-medium text-foreground">{value ? label : '–'}</span>
      </p>
    </div>
  )
}
