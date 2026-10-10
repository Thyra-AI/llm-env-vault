import { useTranslation } from '@workspace/i18n'
import type { ErrorMsg, Msg } from '@/protocol'

/** Resolve a server message (i18n key + params) to a string. */
export function useMsg() {
  const { t } = useTranslation()
  return {
    msg: (m: Msg) => t(m.key, m.params as Record<string, string | number> | undefined) as string,
    error: (e: ErrorMsg) => ('raw' in e ? e.raw : (t(e.key, e.params as Record<string, string | number> | undefined) as string)),
  }
}
