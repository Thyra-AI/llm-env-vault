import { useEffect, useRef } from 'react'

/**
 * Calls `onIdle` after `minutes` without any input (pointer, key, wheel, touch).
 * Mounted once for the whole session, so item views, forms and dialogs are
 * covered, not only the list. The server enforces the same limit; this makes it
 * prompt. If `onIdle` has not changed the screen, it fires again a full period later.
 */
export function useAutoLock(minutes: number | null, onIdle: () => void) {
  const callback = useRef(onIdle)
  callback.current = onIdle
  useEffect(() => {
    if (minutes === null) return
    const arm = () =>
      window.setTimeout(() => {
        callback.current()
        timer = arm()
      }, minutes * 60_000)
    let timer = arm()
    const reset = () => {
      window.clearTimeout(timer)
      timer = arm()
    }
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const
    for (const e of events) addEventListener(e, reset, { passive: true })
    return () => {
      window.clearTimeout(timer)
      for (const e of events) removeEventListener(e, reset)
    }
  }, [minutes])
}
