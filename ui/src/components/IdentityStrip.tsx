import { type ReactNode, useEffect, useRef, useState } from 'react'
import { t } from '../i18n'

type Props = {
  serverName: string
  tokenPreview: string
  tokenPresent: boolean
  clientId?: string
  publicIp?: string
  online?: boolean
  onCopyToken: () => void
  /** Extra detail shown only when the strip is expanded (e.g. live meters). */
  children?: ReactNode
}

/** U5: compact header - status dot + machine name; ID, IP, token copy and meters open on click. */
export function IdentityStrip({
  serverName,
  tokenPresent,
  clientId,
  publicIp,
  online = false,
  onCopyToken,
  children,
}: Props) {
  const host = serverName.trim() || '-'
  const ip = (publicIp || '').trim() || '-'
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className="identity-strip" ref={ref}>
      <button
        type="button"
        className="identity-toggle"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        data-tooltip={online ? t('motor_online') : t('motor_offline')}
      >
        <span className={`identity-dot ${online ? 'ok' : 'down'}`} aria-hidden="true" />
        <span className="identity-host">{host}</span>
        <span className="identity-caret" aria-hidden="true">{open ? '\u25B4' : '\u25BE'}</span>
      </button>
      {open && (
        <div className="identity-pop" role="dialog" aria-label={t('identity_device')}>
          <dl>
            {clientId ? (
              <>
                <dt>{t('identity_id')}</dt>
                <dd className="mono">#{clientId}</dd>
              </>
            ) : null}
            <dt>{t('identity_ip')}</dt>
            <dd className="mono">{ip}</dd>
          </dl>
          {children ? <div className="identity-pop-meters">{children}</div> : null}
          <button type="button" className="btn ghost sm" disabled={!tokenPresent} onClick={onCopyToken}>
            {t('btn_copy_token')}
          </button>
        </div>
      )}
    </div>
  )
}
