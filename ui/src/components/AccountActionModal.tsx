import { type FormEvent, useState } from 'react'
import { PasswordInput } from './PasswordInput'
import { t } from '../i18n'

type Props = {
  email: string
  busy: boolean
  error: string
  /** True after cloud accepted unlink_request and mailed the confirm link. */
  linkSent: boolean
  onClose: () => void
  onRequestLink: (password: string, pin: string, emailConfirm: string) => void
}

export function AccountActionModal({
  email,
  busy,
  error,
  linkSent,
  onClose,
  onRequestLink,
}: Props) {
  const [password, setPassword] = useState('')
  const [pin, setPin] = useState('')
  const [emailConfirm, setEmailConfirm] = useState('')

  const emailMatches =
    emailConfirm.trim().toLowerCase() === String(email || '').trim().toLowerCase()
  const pinOk = pin.length >= 4

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (busy || linkSent || !password || !pinOk || !emailMatches) return
    onRequestLink(password, pin, emailConfirm.trim())
  }

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

        {linkSent ? (
          <>
            <aside className="claim-risk soft" role="status">
              <strong>{t('account_unlink_link_sent_title')}</strong>
              <p style={{ margin: '8px 0 0' }}>
                {t('account_unlink_link_sent_body', { email: email || '—' })}
              </p>
            </aside>
            <p className="muted" style={{ marginTop: 12 }}>
              {t('account_unlink_link_sent_wait')}
            </p>
            {error && (
              <aside className="lock-error" role="alert">
                {error}
              </aside>
            )}
            <div className="btn-row modal-actions">
              <button type="button" className="btn" disabled={busy} onClick={onClose}>
                {t('btn_close')}
              </button>
            </div>
          </>
        ) : (
          <>
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

            {error && (
              <aside className="lock-error" role="alert">
                {error}
              </aside>
            )}

            <div className="btn-row modal-actions">
              <button type="button" className="btn ghost" disabled={busy} onClick={onClose}>
                {t('btn_cancel')}
              </button>
              <button
                type="submit"
                className="btn danger"
                disabled={busy || !password || !pinOk || !emailMatches}
              >
                {busy ? t('account_unlink_sending') : t('account_unlink_send_link')}
              </button>
            </div>
          </>
        )}
      </form>
    </div>
  )
}
