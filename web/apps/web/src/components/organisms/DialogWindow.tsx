import type { LucideIcon } from 'lucide-react'
import { Lock } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from '@workspace/i18n'
import { Badge } from '@workspace/ui/components/badge'
import { BorderBeam } from '@workspace/ui/components/border-beam'
import { AnimatedGroup } from '@workspace/ui/components/animated-group'
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@workspace/ui/components/card'
import { Progress } from '@workspace/ui/components/progress'
import { cn } from '@workspace/ui/lib/utils'

interface DialogWindowProps {
  title: string
  icon?: LucideIcon
  step?: { current: number; total: number }
  badge?: string
  tone?: 'default' | 'danger'
  children: ReactNode
  actions?: ReactNode
}

const BEAM = {
  default: { from: '#2553F9', to: '#94B8F9' },
  danger: { from: '#e5484d', to: '#ffb3bd' },
}

/** Shared chrome of every vault dialog: header, animated body, action row. */
export function DialogWindow({ title, icon: Icon = Lock, step, badge, tone = 'default', children, actions }: DialogWindowProps) {
  const { t } = useTranslation()
  return (
    <Card role="region" aria-labelledby="dialog-title" className="relative mx-auto w-full max-w-md gap-0 overflow-hidden py-0">
      <BorderBeam size={140} duration={9} colorFrom={BEAM[tone].from} colorTo={BEAM[tone].to} />
      <CardHeader className="flex flex-row items-center gap-2.5 border-b bg-muted/40 px-4 py-2.5 text-xs text-muted-foreground">
        <Icon className="size-4" aria-hidden />
        <span className="font-mono">{t('app.name')}</span>
        <span className="ml-auto flex items-center gap-2">
          {badge && <Badge variant="secondary">{badge}</Badge>}
          {step && <span>{t('common.step', step)}</span>}
        </span>
      </CardHeader>
      {step && <Progress value={(step.current / step.total) * 100} className="h-0.5 rounded-none" aria-label={t('common.step', step)} />}
      <CardContent className="flex flex-col gap-4 p-5">
        <CardTitle id="dialog-title" className={cn('text-lg leading-tight font-semibold', tone === 'danger' && 'text-destructive')}>
          {title}
        </CardTitle>
        <AnimatedGroup preset="blur-slide" className="flex flex-col gap-4">
          {children}
        </AnimatedGroup>
      </CardContent>
      {actions && <CardFooter className="flex flex-col-reverse gap-2 border-t-0 bg-transparent px-5 pt-0 pb-5 sm:flex-row sm:justify-end [&>*]:w-full sm:[&>*]:w-auto">{actions}</CardFooter>}
    </Card>
  )
}
