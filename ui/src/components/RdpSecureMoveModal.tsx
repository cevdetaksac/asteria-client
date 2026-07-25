import { useEffect, useState } from 'react'
import { t } from '../i18n'

export type RdpMoveInfo = {
  protected: boolean
  current_port: number
  secure_port: number
  standard_port?: number
  admin?: boolean
  pending?: boolean
  pending_mode?: string
  pending_from?: number
  pending_to?: number
  seconds_left?: number
  confirm_seconds?: number
}

type Phase = 'intro' | 'countdown'

type Props = {
  info: RdpMoveInfo
  busy: boolean
  onClose: () => void
  onBegin: () => Promise<void>
  onConfirm: () => Promise<void>
  onCancel: () => Promise<void>
  secondsLeft: number
}

export function RdpSecureMoveModal({
  info,
  busy,
  onClose,
  onBegin,
  onConfirm,
  onCancel,
  secondsLeft,
}: Props) {
  const pending = Boolean(info.pending)
  const [phase, setPhase] = useState<Phase>(pending ? 'countdown' : 'intro')

  useEffect(() => {
    setPhase(pending ? 'countdown' : 'intro')
  }, [pending])

  const fromPort = info.pending_from || (info.protected ? info.secure_port : info.current_port || 3389)
  const toPort =
    info.pending_to ||
    (info.protected ? info.standard_port || 3389 : info.secure_port || 53389)
  const mode = info.pending_mode || (info.protected ? 'rollback' : 'secure')

  return (
    <div className="modal-backdrop" role="presentation" onClick={phase === 'intro' ? onClose : undefined}>
      <div
        className="modal-card rdp-move-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="rdp-move-title"
        onClick={(event) => event.stopPropagation()}
      >
        <p className="eyebrow">{t('rdp_move_eyebrow')}</p>
        <h2 id="rdp-move-title">{t('rdp_move_title')}</h2>

        {phase === 'intro' && (
          <>
            <p className="muted">{t('rdp_move_intro')}</p>
            <ol className="rdp-steps">
              <li>{t('rdp_move_step1', { from: fromPort, to: toPort })}</li>
              <li>{t('rdp_move_step2', { to: toPort, seconds: info.confirm_seconds || 60 })}</li>
              <li>{t('rdp_move_step3')}</li>
              <li>{t('rdp_move_step4', { from: fromPort })}</li>
            </ol>
            {!info.admin && (
              <p className="error-inline">{t('rdp_move_need_admin')}</p>
            )}
            <div className="btn-row modal-actions">
              <button type="button" className="btn ghost" disabled={busy} onClick={onClose}>
                {t('btn_cancel')}
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy || info.admin === false}
                onClick={() => void onBegin()}
              >
                {t('rdp_move_start', { to: toPort })}
              </button>
            </div>
          </>
        )}

        {phase === 'countdown' && (
          <>
            <p className="muted">
              {t('rdp_move_waiting', { to: toPort, mode: mode === 'secure' ? t('rdp_move_mode_secure') : t('rdp_move_mode_standard') })}
            </p>
            <div className="rdp-countdown" aria-live="polite">
              <strong className="mono">{secondsLeft}</strong>
              <span>{t('rdp_move_seconds')}</span>
            </div>
            <p className="muted">{t('rdp_move_reconnect_hint', { to: toPort })}</p>
            <div className="btn-row modal-actions">
              <button type="button" className="btn ghost" disabled={busy} onClick={() => void onCancel()}>
                {t('rdp_move_abort')}
              </button>
              <button type="button" className="btn" disabled={busy || secondsLeft <= 0} onClick={() => void onConfirm()}>
                {t('rdp_move_confirm')}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
