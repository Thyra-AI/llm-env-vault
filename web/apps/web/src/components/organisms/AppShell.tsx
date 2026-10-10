import type { ReactNode } from 'react'
import { AnimatedThemeToggler } from '@workspace/ui/components/animated-theme-toggler'
import { useTheme } from '@workspace/ui/hooks/use-theme'
import { LanguageSwitcher, ThyraLogo } from '@/components/molecules'

interface AppShellProps {
  children: ReactNode
}

export function AppShell({ children }: AppShellProps) {
  const { theme, setTheme } = useTheme()
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="sticky top-0 z-10 flex items-center gap-3 border-b bg-background/80 px-4 py-3 backdrop-blur">
        <ThyraLogo />
        <div className="ml-auto flex items-center gap-2">
          <LanguageSwitcher />
          <AnimatedThemeToggler
            theme={theme}
            onThemeChange={setTheme}
            variant="circle"
            className="inline-flex size-8 items-center justify-center rounded-lg border bg-background hover:bg-muted [&_svg]:size-4"
          />
        </div>
      </header>
      <main className="flex flex-1 items-start justify-center px-4 py-8 sm:items-center sm:py-12">
        <div className="w-full max-w-md">{children}</div>
      </main>
    </div>
  )
}
