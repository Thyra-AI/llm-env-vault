import { CircleCheck, Info, OctagonAlert, TriangleAlert } from 'lucide-react'
import type { ReactNode } from 'react'
import { Alert, AlertDescription } from '@workspace/ui/components/alert'
import { cn } from '@workspace/ui/lib/utils'

const tones = {
  info: { icon: Info, className: 'border-primary/25 bg-primary/10 text-foreground [&>svg]:text-primary' },
  warning: { icon: TriangleAlert, className: 'border-amber-500/30 bg-amber-500/10 text-amber-950 dark:text-amber-100 [&>svg]:text-amber-600 dark:[&>svg]:text-amber-400' },
  success: { icon: CircleCheck, className: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-950 dark:text-emerald-100 [&>svg]:text-emerald-600 dark:[&>svg]:text-emerald-400' },
  danger: { icon: OctagonAlert, className: '' },
} as const

export function Notice({ tone = 'info', children }: { tone?: keyof typeof tones; children: ReactNode }) {
  const { icon: Icon, className } = tones[tone]
  return (
    <Alert variant={tone === 'danger' ? 'destructive' : 'default'} className={cn(className)}>
      <Icon aria-hidden />
      <AlertDescription className={cn(tone !== 'danger' && 'text-current')}>{children}</AlertDescription>
    </Alert>
  )
}
