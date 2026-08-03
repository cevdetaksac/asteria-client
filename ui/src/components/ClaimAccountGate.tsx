import { type FormEvent, useState } from 'react'
import { BrandLockup } from './Brand'
import { PasswordInput } from './PasswordInput'
import { t } from '../i18n'

type Props = {
  pinEnabled: boolean
  busy: boolean
  error: string
  onLink: (email: string, password: string, pin: string) => void
  onOpenDashboard: () => void
  onOpenRegister: () => void
}

export function ClaimAccountGate({
  pinEnabled,
  busy,
  error,
  onLink,
  onOpenDashboard,
  onOpenRegister,
}: Props) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pin, setPin] = useState('')

  const pinOk = pin.length >= 4
  const canSubmit = Boolean(email.trim() && password && pinOk && !busy)

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!canSubmit) return
    onLink(email.trim(), password, pin)
  }

  return (
    <div className="claim-gate" role="dialog" aria-modal="true" aria-labelledby="claim-title">
      <div className="claim-gate-card">
        <BrandLockup mode="square" />
        <p className="eyebrow">{t('claim_eyebrow')}</p>
        <h2 id="claim-title">{t('claim_title')}</h2>
        <p className="muted claim-blurb">{t('claim_blurb')}</p>

        <aside className="claim-risk" role="note">
          <strong>{t('claim_risk_title')}</strong>
          <ul>
            <li>{t('claim_risk_auto')}</li>
            <li>{t('claim_risk_remote')}</li>
            <li>{t('claim_risk_recovery')}</li>
          </ul>
        </aside>

        <form className="claim-form" onSubmit={submit}>
          <label className="modal-field">
            <span>{t('settings_email_ph')}</span>
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t('settings_email_ph')}
              disabled={busy}
              autoFocus
            />
          </label>
          <label className="modal-field">
            <span>{t('settings_password_ph')}</span>
            <PasswordInput
              value={password}
              onChange={setPassword}
              placeholder={t('settings_password_ph')}
              disabled={busy}
            />
          </label>
          <label className="modal-field">
            <span>{pinEnabled ? t('account_pin_reauth') : t('claim_pin_new')}</span>
            <PasswordInput
              value={pin}
              onChange={setPin}
              placeholder={pinEnabled ? t('lock_pin_ph') : t('claim_pin_new_ph')}
              numeric
              disabled={busy}
            />
          </label>
          {!pinEnabled && <p className="field-help">{t('claim_pin_help')}</p>}

          {error && (
            <aside className="lock-error" role="alert">
              {error}
            </aside>
          )}

          <div className="btn-row modal-actions">
            <button type="submit" className="btn" disabled={!canSubmit}>
              {busy ? t('claim_linking') : t('claim_submit')}
            </button>
          </div>
        </form>

        <div className="claim-alt">
          <p className="muted">{t('claim_alt_blurb')}</p>
          <div className="btn-row">
            <button type="button" className="btn ghost sm" disabled={busy} onClick={onOpenDashboard}>
              {t('claim_open_dashboard')}
            </button>
            <button type="button" className="btn ghost sm" disabled={busy} onClick={onOpenRegister}>
              {t('claim_create_account')}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
