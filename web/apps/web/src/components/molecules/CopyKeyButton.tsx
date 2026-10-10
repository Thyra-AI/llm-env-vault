import { Copy } from 'lucide-react'
import { useRef } from 'react'
import { toast } from 'sonner'
import { useTranslation } from '@workspace/i18n'
import { Button } from '@workspace/ui/components/button'
import { useCopyToClipboard } from '@workspace/ui/hooks/use-copy-to-clipboard'

/**
 * Copy the recovery key, then wipe the clipboard after `clearSeconds`.
 *
 * The clipboard is readable by every process running as this user, so the
 * window is kept short -- long enough to paste into the confirm field, not long
 * enough to still be there later (same policy as the native dialog). If the
 * browser will not let us read the clipboard back to check it is still our key,
 * we wipe anyway: failing towards leaving the key behind would be worse.
 */
export function CopyKeyButton({ value, clearSeconds }: { value: string; clearSeconds: number }) {
  const { t } = useTranslation()
  const timer = useRef<number | undefined>(undefined)
  const { copyToClipboard } = useCopyToClipboard({
    onCopy: () => {
      toast.success(t('toast.copied'), { description: t('recoveryKey.copy', { seconds: clearSeconds }) })
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(async () => {
        try {
          const current = await navigator.clipboard.readText().catch(() => value)
          if (current === value) await navigator.clipboard.writeText('')
        } catch {
          /* clipboard unavailable */
        }
      }, clearSeconds * 1000)
    },
  })
  return (
    <Button type="button" variant="outline" size="sm" className="self-start" onClick={() => copyToClipboard(value)}>
      <Copy aria-hidden /> {t('recoveryKey.copy', { seconds: clearSeconds })}
    </Button>
  )
}
