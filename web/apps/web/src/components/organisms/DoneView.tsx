import { CircleCheck, CircleSlash, Clock3, OctagonAlert } from 'lucide-react'
import { useTranslation } from '@workspace/i18n'
import { Card, CardContent } from '@workspace/ui/components/card'
import type { DoneStatus } from '@/protocol'

const VARIANTS = {
  approved: { icon: CircleCheck, tone: 'text-emerald-600 dark:text-emerald-400', key: 'done.approved' },
  declined: { icon: CircleSlash, tone: 'text-muted-foreground', key: 'done.declined' },
  timeout: { icon: Clock3, tone: 'text-amber-600 dark:text-amber-400', key: 'done.timeout' },
  closed: { icon: CircleSlash, tone: 'text-muted-foreground', key: 'done.closed' },
  error: { icon: OctagonAlert, tone: 'text-destructive', key: 'done.error' },
} as const

export function DoneView({ reason, status }: { reason: string; status: DoneStatus }) {
  const { t } = useTranslation()
  const variant = VARIANTS[reason === 'completed' ? (status ?? 'declined') : ((reason in VARIANTS ? reason : 'error') as keyof typeof VARIANTS)]
  const Icon = variant.icon
  return (
    <Card role="status" className="mx-auto w-full max-w-md">
      <CardContent className="flex flex-col items-center gap-3 py-8 text-center">
        <Icon className={`size-10 ${variant.tone}`} aria-hidden />
        <p className="font-heading text-lg font-semibold">{t(variant.key)}</p>
        <p className="text-sm text-muted-foreground">{t('done.hint')}</p>
      </CardContent>
    </Card>
  )
}
