import { MotionConfig } from 'motion/react'
import { useTranslation } from '@workspace/i18n'
import { Card, CardContent } from '@workspace/ui/components/card'
import { Toaster } from '@workspace/ui/components/sonner'
import { ThemeProvider } from '@workspace/ui/hooks/use-theme'
import { HAS_LAUNCH } from '@/api'
import { AppShell, LiveSession } from '@/components/organisms'

function NoSession() {
  const { t } = useTranslation()
  return (
    <AppShell>
      <Card className="mx-auto w-full max-w-md">
        <CardContent className="py-6 text-center text-sm text-muted-foreground">{t('session.none')}</CardContent>
      </Card>
    </AppShell>
  )
}

export default function App() {
  return (
    <MotionConfig reducedMotion="user">
      <ThemeProvider>
        {HAS_LAUNCH ? <LiveSession /> : <NoSession />}
        <Toaster position="bottom-center" offset={84} mobileOffset={84} />
      </ThemeProvider>
    </MotionConfig>
  )
}
