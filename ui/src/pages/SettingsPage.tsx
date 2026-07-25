import { type FormEvent, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { PasswordInput } from '../components/PasswordInput'
import { t } from '../i18n'
import { asRecord } from '../lib'

type Props = {
  pinEnabled: boolean
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onSession: () => void
}

type FieldKey =
  | 'alert_email_enabled'
  | 'instant_email_for_critical'
  | 'daily_digest_enabled'
  | 'auto_block_enabled'
  | 'auto_block_threshold'
  | 'auto_block_duration_hours'
  | 'webhook_enabled'
  | 'webhook_url'

type Field = { key: FieldKey; kind: 'bool' | 'int' | 'str'; labelKey: string }

const FIELDS: Field[] = [
  { key: 'alert_email_enabled', kind: 'bool', labelKey: 'settings_field_email' },
  { key: 'instant_email_for_critical', kind: 'bool', labelKey: 'settings_field_critical' },
  { key: 'daily_digest_enabled', kind: 'bool', labelKey: 'settings_field_digest' },
  { key: 'auto_block_enabled', kind: 'bool', labelKey: 'settings_field_autoblock' },
  { key: 'auto_block_threshold', kind: 'int', labelKey: 'settings_field_threshold' },
  { key: 'auto_block_duration_hours', kind: 'int', labelKey: 'settings_field_duration' },
  { key: 'webhook_enabled', kind: 'bool', labelKey: 'settings_field_webhook' },
  { key: 'webhook_url', kind: 'str', labelKey: 'settings_field_webhook_url' },
]

function nestedGet(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key]
    return undefined
  }, obj)
}

function nestedSet(obj: Record<string, unknown>, path: string, value: unknown): Record<string, unknown> {
  const parts = path.split('.')
  const root = { ...obj }
  let cursor: Record<string, unknown> = root
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i]
    const next = asRecord(cursor[key])
    cursor[key] = { ...next }
    cursor = cursor[key] as Record<string, unknown>
  }
  cursor[parts[parts.length - 1]] = value
  return root
}

export function SettingsPage({ pinEnabled, onToast, onSession }: Props) {
  const [draft, setDraft] = useState<Record<string, unknown>>({})
  const [pin, setPin] = useState('')
  const [pinCurrent, setPinCurrent] = useState('')
  const [busy, setBusy] = useState(false)
  const [linked, setLinked] = useState(false)
  const [accountEmail, setAccountEmail] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [accountPin, setAccountPin] = useState('')

  const load = async () => {
    const result = await motorBridge.cloud('GET', 'threats/config')
    if (result.ok && result.data && typeof result.data === 'object') {
      setDraft(result.data as Record<string, unknown>)
    }
  }

  const loadAccount = async () => {
    const result = await motorBridge.account('status')
    if (result.ok) {
      setLinked(Boolean(result.linked))
      setAccountEmail(String(result.email || ''))
    }
  }

  useEffect(() => {
    void load()
    void loadAccount()
  }, [])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    try {
      const patch: Record<string, unknown> = {}
      for (const field of FIELDS) {
        const value = nestedGet(draft, field.key)
        if (value !== undefined) {
          Object.assign(patch, nestedSet({}, field.key, value))
        }
      }
      const result = await motorBridge.cloud('POST', 'threats/config', patch)
      onToast(result.ok ? t('toast_settings_saved') : String(result.error || 'save'), result.ok ? 'ok' : 'err')
      await load()
    } finally {
      setBusy(false)
    }
  }

  const setPinAction = async () => {
    const result = await motorBridge.pin('set', pin, pinCurrent)
    onToast(result.ok ? t('toast_pin_saved') : String(result.reason || result.error || 'PIN'), result.ok ? 'ok' : 'err')
    if (result.ok) {
      setPin('')
      setPinCurrent('')
      onSession()
    }
  }

  const clearPin = async () => {
    const result = await motorBridge.pin('clear', '', pinCurrent || pin)
    onToast(result.ok ? t('toast_pin_cleared') : String(result.reason || result.error || 'PIN'), result.ok ? 'ok' : 'err')
    if (result.ok) onSession()
  }

  const submitAccount = async (action: 'link' | 'unlink') => {
    const targetEmail = action === 'unlink' ? accountEmail : email
    if (!targetEmail || !password) {
      onToast(t('toast_need_creds'), 'err')
      return
    }
    if (!accountPin) {
      onToast(t('account_pin_required'), 'err')
      return
    }
    setBusy(true)
    try {
      const result = await motorBridge.account(action, targetEmail, password, accountPin)
      onToast(
        result.ok
          ? action === 'link'
            ? t('toast_link_ok')
            : t('toast_unlink_ok')
          : result.error === 'pin_verification_failed'
            ? t('account_pin_wrong')
            : String(result.error || 'account'),
        result.ok ? 'ok' : 'err',
      )
      if (result.ok) {
        setPassword('')
        setAccountPin('')
        await loadAccount()
        onSession()
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('settings_eyebrow')}</p>
          <h2>{t('settings_title')}</h2>
          <p className="muted">{t('settings_blurb')}</p>
        </div>
        <button type="button" className="btn ghost" onClick={() => void motorBridge.shell('open_servers')}>
          {t('btn_servers_web')}
        </button>
      </div>

      <article className="panel">
        <p className="eyebrow">{t('settings_account')}</p>
        <h3>
          {linked
            ? t('settings_linked', { email: accountEmail ? `: ${accountEmail}` : '' })
            : t('settings_not_linked')}
        </h3>
        <p className="muted">{t('settings_account_blurb')}</p>
        <div className="inline-form" style={{ marginTop: 12 }}>
          {!linked && (
            <input
              type="email"
              placeholder={t('settings_email_ph')}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
            />
          )}
          <PasswordInput value={password} onChange={setPassword} placeholder={t('settings_password_ph')} />
          <PasswordInput
            value={accountPin}
            onChange={setAccountPin}
            placeholder={t('account_pin_reauth')}
            numeric
          />
          <button type="button" className="btn" disabled={busy || linked} onClick={() => void submitAccount('link')}>
            {t('btn_link_account')}
          </button>
          <button type="button" className="btn danger" disabled={busy || !linked} onClick={() => void submitAccount('unlink')}>
            {t('btn_unlink_account')}
          </button>
        </div>
      </article>

      <form className="settings-form" onSubmit={(e) => void save(e)} style={{ marginTop: 24 }}>
        {FIELDS.map((field) => {
          const value = nestedGet(draft, field.key)
          return (
            <label key={field.key} className="field">
              <span>{t(field.labelKey)}</span>
              {field.kind === 'bool' ? (
                <input
                  type="checkbox"
                  checked={Boolean(value)}
                  onChange={(e) => setDraft((prev) => nestedSet(prev, field.key, e.target.checked))}
                />
              ) : (
                <input
                  type={field.kind === 'int' ? 'number' : 'text'}
                  value={value == null ? '' : String(value)}
                  onChange={(e) =>
                    setDraft((prev) =>
                      nestedSet(
                        prev,
                        field.key,
                        field.kind === 'int' ? Number(e.target.value) : e.target.value,
                      ),
                    )
                  }
                />
              )}
            </label>
          )
        })}
        <button type="submit" className="btn" disabled={busy}>{t('btn_save')}</button>
      </form>

      <article className="panel" style={{ marginTop: 24 }}>
        <p className="eyebrow">{t('settings_pin')}</p>
        <h3>{pinEnabled ? t('settings_pin_set') : t('settings_pin_none')}</h3>
        <p className="muted">{t('settings_pin_desc')}</p>
        {linked && (
          <div className="lock-callout linked" style={{ marginTop: 12, marginBottom: 12 }} role="status">
            <p style={{ marginBottom: 0 }}>{t('settings_pin_dashboard_hint')}</p>
          </div>
        )}
        <div className="inline-form">
          {pinEnabled && (
            <PasswordInput
              value={pinCurrent}
              onChange={setPinCurrent}
              placeholder={t('settings_pin_current')}
              numeric
            />
          )}
          <PasswordInput
            value={pin}
            onChange={setPin}
            placeholder={t('settings_pin_new')}
            numeric
            autoComplete="new-password"
          />
          <button type="button" className="btn" onClick={() => void setPinAction()}>{t('btn_save')}</button>
          {pinEnabled && (
            <button type="button" className="btn danger" onClick={() => void clearPin()}>{t('btn_remove')}</button>
          )}
        </div>
      </article>
    </section>
  )
}
