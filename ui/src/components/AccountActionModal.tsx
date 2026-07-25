import { type FormEvent, useState } from 'react'
import { PasswordInput } from './PasswordInput'
import { t } from '../i18n'

type Props = {
  email: string
  busy: boolean
  error: string
  onClose: () => void
  onConfirm: (password: string, pin: string) => void
}

export function AccountActionModal({ email, busy, error, onClose, onConfirm }: Props) {
  const [password, setPassword] = useState('')
  const [pin, setPin] = useState('')

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!busy && password && pin.length >= 4) onConfirm(password, pin)
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
        <p className="muted">
          {t('account_unlink_blurb', { email: email || '—' })}
        </p>

        <label className="modal-field">
          <span>{t('settings_password_ph')}</span>
          <PasswordInput
            value={password}
            onChange={setPassword}
            placeholder={t('settings_password_ph')}
            autoFocus
          />
        </label>
        <label className="modal-field">
          <span>{t('account_pin_reauth')}</span>
          <PasswordInput
            value={pin}
            onChange={setPin}
            placeholder={t('lock_pin_ph')}
            numeric
          />
        </label>

        {error && <aside className="lock-error" role="alert">{error}</aside>}

        <div className="btn-row modal-actions">
          <button type="button" className="btn ghost" disabled={busy} onClick={onClose}>
            {t('btn_cancel')}
          </button>
          <button type="submit" className="btn danger" disabled={busy || !password || pin.length < 4}>
            {busy ? t('account_unlinking') : t('btn_unlink_account')}
          </button>
        </div>
      </form>
    </div>
  )
}
