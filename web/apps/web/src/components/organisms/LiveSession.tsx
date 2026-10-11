import { useEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@workspace/i18n'
import { Card, CardContent } from '@workspace/ui/components/card'
import { Spinner } from '@workspace/ui/components/spinner'
import { TransitionPanel } from '@workspace/ui/components/transition-panel'
import { useTheme } from '@workspace/ui/hooks/use-theme'
import { openSession, SessionError, type Client } from '@/api'
import type { FormValues, View } from '@/protocol'
import { useAutoLock } from '@/components/app/useAutoLock'
import { VaultApp } from '@/components/app/VaultApp'
import { useMsg } from '@/components/molecules'
import { AppShell } from './AppShell'
import { DoneView } from './DoneView'
import { ScreenView } from './ScreenView'

type State = { kind: 'loading' } | { kind: 'view'; view: View } | { kind: 'invalid' } | { kind: 'lost' } | { kind: 'ended' }

const HEARTBEAT_MS = 5000
/** Consecutive failed heartbeats (about 15 s) before the page treats the session as over. */
const MAX_MISSED = 3

/** Connects to the Python server that launched this page and shows its screens. */
export function LiveSession() {
  const { t, i18n } = useTranslation()
  const { error: errorText } = useMsg()
  const { setTheme } = useTheme()
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState(0)
  const client = useRef<Client | null>(null)
  const lastTitle = useRef<string | null>(null)
  const finished = useRef(false)
  const screenId = useRef<string | null>(null)
  const autoLockMinutes = useRef<number | null>(null)

  /** The server is gone (or not ours any more): drop everything and stop talking to that port. */
  const endSession = () => {
    finished.current = true
    client.current?.forget()
    client.current = null
    screenId.current = null
    autoLockMinutes.current = null
    setState({ kind: 'ended' })
    try {
      window.close()
    } catch {
      /* a tab not opened by script cannot be closed: the ended notice stays */
    }
  }

  const show = (view: View) => {
    if ('done' in view) finished.current = true
    screenId.current = 'screen' in view ? view.screen.id : null
    if ('screen' in view && view.screen.app?.view === 'home') autoLockMinutes.current = view.screen.app.prefs.autoLockMinutes
    if ('screen' in view && view.screen.app?.view === 'lock') autoLockMinutes.current = null
    if ('screen' in view && lastTitle.current !== view.screen.title.key) {
      lastTitle.current = view.screen.title.key
      setStep((s) => s + 1)
    }
    setState({ kind: 'view', view })
  }

  useEffect(() => {
    let alive = true
    let timer: number | undefined
    let missed = 0
    openSession()
      .then(async (c) => {
        client.current = c
        show(await c.screen())
        timer = window.setInterval(() => {
          // Once the dialog is over the server is *meant* to go away: stop
          // pinging, and never let a failed ping replace the result screen.
          if (finished.current) return window.clearInterval(timer)
          c.ping().then(
            () => {
              missed = 0
            },
            (e) => {
              if (!alive || finished.current) return
              missed += 1
              if (e instanceof SessionError || missed >= MAX_MISSED) endSession()
            },
          )
        }, HEARTBEAT_MS)
      })
      .catch((e) => alive && setState({ kind: e instanceof SessionError ? 'invalid' : 'lost' }))
    const onHide = () => client.current?.closing()
    addEventListener('pagehide', onHide)
    return () => {
      alive = false
      window.clearInterval(timer)
      removeEventListener('pagehide', onHide)
    }
  }, [])

  const current = state.kind === 'view' && 'screen' in state.view ? state.view.screen : null

  // A one-shot message from the server (copied, saved...), shown once per screen.
  useEffect(() => {
    const m = current?.toast
    if (!m) return
    const text = errorText(m.msg)
    ;(m.tone === 'error' ? toast.error : m.tone === 'warning' ? toast.warning : m.tone === 'success' ? toast.success : toast.info)(text)
  }, [current?.id])

  // The app keeps language and theme on the server (every launch has a new origin).
  const language = current?.app?.prefs.language
  const themePref = current?.app?.prefs.theme
  useEffect(() => {
    if (language && i18n.language !== language) void i18n.changeLanguage(language)
  }, [language])
  useEffect(() => {
    if (!themePref) return
    setTheme(themePref === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : themePref)
  }, [themePref])

  const onAction = async (action: string, values: FormValues) => {
    const c = client.current
    if (!c || state.kind !== 'view' || !('screen' in state.view)) return
    setBusy(true)
    try {
      show(await c.act(state.view.screen.id, action, values))
    } catch (e) {
      if (!finished.current) endSession()
    } finally {
      setBusy(false)
    }
  }

  // Idle lock for EVERY screen of the app (item view, forms, manage...): drop what
  // is on screen at once (a revealed secret must not outlive the limit), then tell
  // the server, which locks and sends the lock screen.
  const idleLock = async () => {
    const c = client.current
    const id = screenId.current
    if (!c || !id || finished.current) return
    setState({ kind: 'loading' })
    try {
      show(await c.act(id, 'autolock', {}))
    } catch {
      if (!finished.current) endSession()
    }
  }
  useAutoLock(autoLockMinutes.current, () => void idleLock())

  if (state.kind === 'loading') {
    return (
      <AppShell>
        <p className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <Spinner aria-hidden /> {t('session.loading')}
        </p>
      </AppShell>
    )
  }
  if (state.kind === 'ended') {
    return (
      <AppShell>
        <DoneView reason="closed" status={null} />
      </AppShell>
    )
  }
  if (state.kind === 'invalid' || state.kind === 'lost') {
    return (
      <AppShell>
        <Card role="alert" className="mx-auto w-full max-w-md">
          <CardContent className="py-6 text-center text-sm">{state.kind === 'invalid' ? t('session.invalid') : t('done.error')}</CardContent>
        </Card>
      </AppShell>
    )
  }
  const view = state.view
  if ('done' in view) {
    return (
      <AppShell>
        <DoneView reason={view.reason} status={view.status} />
      </AppShell>
    )
  }

  // TransitionPanel shows children[activeIndex]; a sparse array lets the index
  // grow with every new step so each step gets its own enter/exit animation.
  const panels: React.ReactNode[] = []
  const isApp = !!view.screen.app
  panels[step] = isApp
    ? <VaultApp key={view.screen.title.key} screen={view.screen} busy={busy} onAction={onAction} />
    : <ScreenView key={view.screen.title.key} screen={view.screen} busy={busy} onAction={onAction} />
  const panel = (
    <TransitionPanel
      activeIndex={step}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      variants={{
        enter: { opacity: 0, y: 16, filter: 'blur(6px)' },
        center: { opacity: 1, y: 0, filter: 'blur(0px)' },
        exit: { opacity: 0, y: -8, filter: 'blur(4px)' },
      }}
    >
      {panels}
    </TransitionPanel>
  )
  // The app is its own full-window frame; the plain dialogs sit in the shared shell.
  return isApp ? panel : <AppShell>{panel}</AppShell>
}
