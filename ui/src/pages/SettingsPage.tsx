import { type FormEvent, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { PasswordInput } from '../components/PasswordInput'
import { Switch } from '../components/Switch'
import { t } from '../i18n'
import { asRecord } from '../lib'
import { invalidate } from '../data/shared'
import { DEFAULT_BLOCK_RULES, normalizeBlockRules, FIELDS, nestedGet, nestedSet, openDash, mapSettingsAccountError, type BlockRule } from './settings/fields'
import { useBusy } from '../hooks/useBusy'


type Props = {
  pinEnabled: boolean
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onSession: () => void
}

export function SettingsPage({ pinEnabled, onToast, onSession }: Props) {
  const [draft, setDraft] = useState<Record<string, unknown>>({})
  const [blockRules, setBlockRules] = useState<BlockRule[]>(DEFAULT_BLOCK_RULES)
  const [pin, setPin] = useState('')
  const [pinCurrent, setPinCurrent] = useState('')
  const [busy, run] = useBusy()
  const [cfgReady, setCfgReady] = useState(false)
  const [linked, setLinked] = useState(false)
  const [accountEmail, setAccountEmail] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [accountPin, setAccountPin] = useState('')
  const [tab, setTab] = useState<
    | 'account'
    | 'settings_sec_email'
    | 'settings_sec_autoblock'
    | 'settings_sec_silent'
    | 'settings_sec_webhook'
    | 'rules'
    | 'pin'
  >('rules')

  const load = async () => {
    invalidate('cloud:threats/config')
      const result = await motorBridge.cloud('GET', 'threats/config')
    if (result.ok && result.data && typeof result.data === 'object') {
      const data = result.data as Record<string, unknown>
      setDraft(data)
      const prot = asRecord(data.protection)
      setBlockRules(normalizeBlockRules(prot?.block_rules))
    } else {
      setBlockRules(DEFAULT_BLOCK_RULES)
    }
    setCfgReady(true)
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

  const updateRule = (service: string, patch: Partial<BlockRule>) => {
    setBlockRules((prev) =>
      prev.map((row) => (row.service === service ? { ...row, ...patch } : row)),
    )
  }

  const save = async (event: FormEvent) => {
    event.preventDefault()
    return run(async () => {
      const patch: Record<string, unknown> = {}
      for (const field of FIELDS) {
        const value = nestedGet(draft, field.key)
        if (value !== undefined) {
          Object.assign(patch, nestedSet({}, field.key, value))
        }
      }
      patch.protection = {
        block_rules: blockRules.map((row) => ({
          id: row.id,
          name: row.name,
          enabled: row.enabled,
          service: row.service,
          event: row.event,
          threshold: Math.max(1, Math.min(100, Math.floor(Number(row.threshold) || 1))),
          window_seconds: Math.max(60, Math.min(86400, Math.floor(Number(row.window_seconds) || 1800))),
          action: row.action || 'block_ip',
          alert: row.alert !== false,
          severity: row.severity || 'high',
        })),
      }
      const result = await motorBridge.cloud('POST', 'threats/config', patch)
      onToast(result.ok ? t('toast_settings_saved') : t('toast_error_generic'), result.ok ? 'ok' : 'err')
      await load()
    })
  }

  const setPinAction = async () => {
    const result = await motorBridge.pin('set', pin, pinCurrent)
    onToast(result.ok ? t('toast_pin_saved') : t('toast_pin_failed'), result.ok ? 'ok' : 'err')
    if (result.ok) {
      setPin('')
      setPinCurrent('')
      onSession()
    }
  }

  const clearPin = async () => {
    const result = await motorBridge.pin('clear', '', pinCurrent || pin)
    onToast(result.ok ? t('toast_pin_cleared') : t('toast_pin_failed'), result.ok ? 'ok' : 'err')
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
    return run(async () => {
      if (action === 'unlink') {
        const result = await motorBridge.account('unlink_request', targetEmail, password, accountPin)
        if (!result.ok) {
          const code = String(result.error || '')
          onToast(
            code === 'pin_verification_failed'
              ? t('account_pin_wrong')
              : code === 'invalid_credentials'
                ? t('claim_bad_credentials')
                : code === 'missing_confirm_code'
                  ? t('account_unlink_need_mail_first')
                  : mapSettingsAccountError(code),
            'err',
          )
          return
        }
        onToast(t('toast_unlink_link_sent'))
        setPassword('')
        setAccountPin('')
        // Wait until the user clicks the email magic-link (cloud completes unlink).
        for (let i = 0; i < 90; i++) {
          await new Promise((resolve) => window.setTimeout(resolve, 4000))
          const st = await motorBridge.account('status')
          if (st.ok && !st.linked) {
            onToast(t('toast_unlink_ok'))
            await loadAccount()
            onSession()
            return
          }
        }
        onToast(t('account_unlink_link_sent_wait'), 'ok')
        return
      }

      const result = await motorBridge.account(action, targetEmail, password, accountPin)
      onToast(
        result.ok
          ? t('toast_link_ok')
          : result.error === 'pin_verification_failed'
            ? t('account_pin_wrong')
            : mapSettingsAccountError(String(result.error || 'account')),
        result.ok ? 'ok' : 'err',
      )
      if (result.ok) {
        setPassword('')
        setAccountPin('')
        await loadAccount()
        onSession()
      }
    })
  }

  const sections = FIELDS.reduce<string[]>((acc, field) => {
    if (!acc.includes(field.sectionKey)) acc.push(field.sectionKey)
    return acc
  }, [])

  type SettingsTab =
    | 'account'
    | 'settings_sec_email'
    | 'settings_sec_autoblock'
    | 'settings_sec_silent'
    | 'settings_sec_webhook'
    | 'rules'
    | 'pin'

  const tabMeta: Array<[SettingsTab, string]> = [
    ['rules', t('settings_tab_rules')],
    ['settings_sec_autoblock', t('settings_tab_autoblock')],
    ['settings_sec_email', t('settings_tab_email')],
    ['settings_sec_silent', t('settings_tab_silent')],
    ['settings_sec_webhook', t('settings_tab_webhook')],
    ['account', t('settings_tab_account')],
    ['pin', t('settings_tab_pin')],
  ]

  const renderFields = (sectionKey: string) =>
    FIELDS.filter((f) => f.sectionKey === sectionKey).map((field) => {
      const value = nestedGet(draft, field.key)
      const label = t(field.labelKey)
      return (
        <div key={field.key} className={`settings-row${!cfgReady ? ' loading' : ''}`}>
          <div className="settings-row-copy">
            <span className="field-label">{label}</span>
            <p className="field-help">
              {t(field.helpKey)}{' '}
              <button type="button" className="field-dash-link" onClick={() => openDash(field.dash)}>
                {t('settings_dash_link')}
              </button>
            </p>
          </div>
          <div className="settings-row-control">
            {field.kind === 'bool' ? (
              <Switch
                checked={Boolean(value)}
                loading={!cfgReady}
                disabled={busy || !cfgReady}
                label={label}
                onChange={(next) => setDraft((prev) => nestedSet(prev, field.key, next))}
              />
            ) : field.kind === 'choice' ? (
              <select
                disabled={!cfgReady || busy}
                value={value == null ? '' : String(value)}
                onChange={(e) => setDraft((prev) => nestedSet(prev, field.key, e.target.value))}
              >
                {(field.choices || []).map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {t(opt.labelKey)}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type={field.kind === 'int' ? 'number' : field.kind === 'time' ? 'text' : 'text'}
                inputMode={field.kind === 'time' ? 'numeric' : undefined}
                placeholder={field.kind === 'time' ? t('settings_time_ph') : undefined}
                min={field.min}
                max={field.max}
                disabled={!cfgReady || busy}
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
          </div>
        </div>
      )
    })

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

      <nav className="page-tabs" aria-label={t('settings_title')}>
        {tabMeta.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={`page-tab${tab === id ? ' active' : ''}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === 'account' && (
        <article className="panel settings-panel">
          <p className="eyebrow">{t('settings_account')}</p>
          <h3>
            {linked
              ? t('settings_linked', { email: accountEmail ? `: ${accountEmail}` : '' })
              : t('settings_not_linked')}
          </h3>
          <p className="muted">{t('settings_account_blurb')}</p>
          {linked && (
            <p className="muted u-mt8">{t('account_unlink_mail_note')}</p>
          )}
          <div className="settings-account-form">
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
            <div className="btn-row">
              <button type="button" className="btn" disabled={busy || linked} onClick={() => void submitAccount('link')}>
                {t('btn_link_account')}
              </button>
              <button type="button" className="btn danger" disabled={busy || !linked} onClick={() => void submitAccount('unlink')}>
                {t('btn_unlink_account')}
              </button>
            </div>
          </div>
        </article>
      )}

      {tab === 'pin' && (
        <article className="panel settings-panel">
          <p className="eyebrow">{t('settings_pin')}</p>
          <h3>{pinEnabled ? t('settings_pin_set') : t('settings_pin_none')}</h3>
          <p className="muted">{t('settings_pin_desc')}</p>
          {linked && (
            <div className="lock-callout linked u-mt12 u-mb12" role="status">
              <p className="u-mb0">{t('settings_pin_dashboard_hint')}</p>
            </div>
          )}
          <div className="settings-account-form">
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
            <div className="btn-row">
              <button type="button" className="btn" onClick={() => void setPinAction()}>{t('btn_save')}</button>
              {pinEnabled && (
                <button type="button" className="btn danger" onClick={() => void clearPin()}>{t('btn_remove')}</button>
              )}
            </div>
          </div>
        </article>
      )}

      {(tab === 'settings_sec_email' ||
        tab === 'settings_sec_autoblock' ||
        tab === 'settings_sec_silent' ||
        tab === 'settings_sec_webhook' ||
        tab === 'rules') && (
        <form className="settings-form" onSubmit={(e) => void save(e)}>
          {!cfgReady && <p className="muted status-loading-hint">{t('status_section_loading')}</p>}
          {tab !== 'rules' && sections.includes(tab) && (
            <article className="panel settings-panel">
              <p className="eyebrow">{t(tab)}</p>
              <div className="settings-rows">{renderFields(tab)}</div>
            </article>
          )}
          {tab === 'rules' && (
            <article className="panel settings-panel">
              <p className="eyebrow">{t('settings_sec_block_rules')}</p>
              <p className="muted u-mb12">{t('settings_block_rules_blurb')}</p>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>{t('settings_br_service')}</th>
                      <th>{t('settings_br_enabled')}</th>
                      <th>{t('settings_br_threshold')}</th>
                      <th>{t('settings_br_window')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blockRules.map((row) => (
                      <tr key={row.id || row.service}>
                        <td className="mono">{row.service}</td>
                        <td>
                          <Switch
                            checked={row.enabled}
                            loading={!cfgReady}
                            disabled={busy || !cfgReady}
                            label={row.service}
                            onChange={(next) => updateRule(row.service, { enabled: next })}
                          />
                        </td>
                        <td>
                          <input
                            type="number"
                            min={1}
                            max={100}
                            disabled={!cfgReady || busy}
                            value={row.threshold}
                            onChange={(e) =>
                              updateRule(row.service, { threshold: Math.max(1, Number(e.target.value) || 1) })
                            }
                            className="u-w88"
                          />
                        </td>
                        <td>
                          <input
                            type="number"
                            min={1}
                            max={1440}
                            disabled={!cfgReady || busy}
                            value={Math.max(1, Math.round(row.window_seconds / 60))}
                            onChange={(e) => {
                              const mins = Math.max(1, Math.min(1440, Number(e.target.value) || 30))
                              updateRule(row.service, { window_seconds: mins * 60 })
                            }}
                            className="u-w88"
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          )}
          <div className="settings-save-bar">
            <button type="submit" className="btn" disabled={busy}>{t('btn_save')}</button>
          </div>
        </form>
      )}
    </section>
  )
}
