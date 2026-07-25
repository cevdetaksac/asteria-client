import { type FormEvent } from 'react'
import { BrandLockup } from './Brand'
import { PasswordInput } from './PasswordInput'
import { t } from '../i18n'

type Props = {
  ready: boolean
  pin: string
  onPinChange: (value: string) => void
  onUnlock: (event: FormEvent) => void
  error: string
  accountLinked: boolean
  accountEmail: string
  onOpenDashboard: () => void
  lang: string
  onLang: (next: 'tr' | 'en') => void
}

export function LockScreen({
  ready,
  pin,
  onPinChange,
  onUnlock,
  error,
  accountLinked,
  accountEmail,
  onOpenDashboard,
  lang,
  onLang,
}: Props) {
  const badge =
    accountLinked && accountEmail
      ? t('lock_linked_badge_email', { email: accountEmail })
      : accountLinked
        ? t('lock_linked_badge')
        : ''

  return (
    <main className="lock-screen">
      <div className="lock-ambient" aria-hidden="true" />
      <div className="lock-card">
        <div className="lock-lang">
          <button
            type="button"
            className={`btn ghost sm ${lang === 'tr' ? 'on' : ''}`}
            onClick={() => onLang('tr')}
          >
            TR
          </button>
          <button
            type="button"
            className={`btn ghost sm ${lang === 'en' ? 'on' : ''}`}
            onClick={() => onLang('en')}
          >
            EN
          </button>
        </div>

        <BrandLockup mode="wide" />
        <p className="eyebrow lock-eyebrow">{t('control_center')}</p>

        {!ready ? (
          <div className="lock-body">
            <h2>{t('lock_preparing')}</h2>
          </div>
        ) : (
          <div className="lock-body">
            <h2>{t('lock_title')}</h2>
            <p className="lock-prompt">{t('lock_prompt')}</p>
            <p className="lock-meta muted">{t('lock_pin_hint')}</p>

            {accountLinked ? (
              <div className="lock-callout linked" role="status">
                <span className="lock-callout-badge">{badge}</span>
                <p>{t('lock_pin_dashboard_hint')}</p>
                <button type="button" className="btn ghost sm" onClick={onOpenDashboard}>
                  {t('lock_open_dashboard')}
                </button>
              </div>
            ) : (
              <div className="lock-callout warn" role="note">
                <p>{t('lock_unlinked_note')}</p>
              </div>
            )}

            <form className="lock-form" onSubmit={onUnlock}>
              <PasswordInput
                value={pin}
                onChange={onPinChange}
                placeholder={t('lock_pin_ph')}
                ariaLabel={t('lock_pin_ph')}
                numeric
                autoFocus
              />
              <button type="submit" className="lock-submit" disabled={pin.length < 4}>
                {t('lock_unlock')}
              </button>
            </form>

            {error && (
              <aside className="lock-error" role="alert">
                {error}
              </aside>
            )}
          </div>
        )}

        <p className="lock-foot muted">{t('lock_foot')}</p>
      </div>
    </main>
  )
}
