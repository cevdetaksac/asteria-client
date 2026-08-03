import { type FormEvent, useState } from 'react'
import { PasswordInput } from './PasswordInput'
import { t } from '../i18n'

type Props = {
  email: string
  busy: boolean
  error: string
  codeSent: boolean
  mailConfirmAvailable: boolean | null
  onClose: () => void
  onRequestCode: (password: string, pin: string) => void
  onConfirm: (password: string, pin: string, code: string, emailConfirm: string) => void
}

export function AccountActionModal({
  email,
  busy,
  error,
  codeSent,
  mailConfirmAvailable,
  onClose,
  onRequestCode,
  onConfirm,
}: Props) {
  const [password, setPassword] = useState('')
  const [pin, setPin] = useState('')
  const [code, setCode] = useState('')
  const [emailConfirm, setEmailConfirm] = useState('')

  const emailMatches =
    emailConfirm.trim().toLowerCase() === String(email || '').trim().toLowerCase()
  const pinOk = pin.length >= 4

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (busy || !password || !pinOk || !emailMatches) return
    if (mailConfirmAvailable === false) {
      onConfirm(password, pin, '', emailConfirm.trim())
      return
    }
    if (!codeSent) {
      onRequestCode(password, pin)
      return
    }
    if (!code.trim()) return
    onConfirm(password, pin, code.trim(), emailConfirm.trim())
  }

  const primaryDisabled =
    busy ||
    !password ||
    !pinOk ||
    !emailMatches ||
    (Boolean(codeSent || mailConfirmAvailable !== false) && codeSent && !code.trim())

  const primaryLabel = (() => {
    if (busy) {
      if (!codeSent && mailConfirmAvailable !== false) return t('account_unlink_sending')
      return t('account_unlinking')
    }
    if (mailConfirmAvailable === false) return t('btn_unlink_account')
    if (!codeSent) return t('account_unlink_send_code')
    return t('btn_unlink_account')
  })()

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <form
        className="modal-card account-action-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="account-action-title"
        onSubmit={submit}
        onClick={(event) => event.stopPropagation()}
      >
        <p className="eyebrow">{t('account_security_eyebrow')}</p>
        <h2 id="account-action-title">{t('account_unlink_title')}</h2>
        <p className="muted">{t('account_unlink_blurb', { email: email || '—' })}</p>
        <p className="muted">{t('account_unlink_mail_note')}</p>

        <label className="modal-field">
          <span>{t('account_unlink_email_confirm')}</span>
          <input
            type="email"
            autoComplete="off"
            value={emailConfirm}
            onChange={(e) => setEmailConfirm(e.target.value)}
            placeholder={email || t('settings_email_ph')}
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
          <span>{t('account_pin_reauth')}</span>
          <PasswordInput
            value={pin}
            onChange={setPin}
            placeholder={t('lock_pin_ph')}
            numeric
            disabled={busy}
          />
        </label>

        {(codeSent || mailConfirmAvailable === true) && (
          <label className="modal-field">
            <span>{t('account_unlink_code')}</span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\s+/g, ''))}
              placeholder={t('account_unlink_code_ph')}
              disabled={busy || !codeSent}
            />
          </label>
        )}

        {mailConfirmAvailable === false && (
          <aside className="claim-risk soft" role="note">
            {t('account_unlink_fallback_note')}
          </aside>
        )}

        {error && (
          <aside className="lock-error" role="alert">
            {error}
          </aside>
        )}

        <div className="btn-row modal-actions">
          <button type="button" className="btn ghost" disabled={busy} onClick={onClose}>
            {t('btn_cancel')}
          </button>
          <button type="submit" className="btn danger" disabled={primaryDisabled}>
            {primaryLabel}
          </button>
        </div>
      </form>
    </div>
  )
}
