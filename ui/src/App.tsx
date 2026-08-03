import { type FormEvent, useCallback, useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from './bridge'
import { AccountActionModal } from './components/AccountActionModal'
import { AboutModal, type AboutInfo } from './components/AboutModal'
import { BrandSidebar } from './components/Brand'
import { ClaimAccountGate } from './components/ClaimAccountGate'
import { HeaderMenu, type MenuAction } from './components/HeaderMenu'
import { IdentityStrip } from './components/IdentityStrip'
import { LiveMeters } from './components/LiveMeters'
import { LockScreen } from './components/LockScreen'
import { currentLang, loadI18n, subscribeI18n, t } from './i18n'
import type { PageId } from './lib'
import { navItems } from './nav'
import { IpListPage } from './pages/IpListPage'
import { LayersPage } from './pages/LayersPage'
import { ServicesPage } from './pages/ServicesPage'
import { SettingsPage } from './pages/SettingsPage'
import { StatusPage } from './pages/StatusPage'
import { ThreatPage } from './pages/ThreatPage'
import { ToolsPage } from './pages/ToolsPage'

type UpdateBanner = {
  phase?: string
  to_version?: string
  from_version?: string
  progress?: number
  detail?: string
  error?: string
  can_abort?: boolean
}

function isGuiLockedPayload(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false
  const row = value as Record<string, unknown>
  return row.error === 'gui_locked' || row.reason === 'gui_locked'
}

export default function App() {
  const [locked, setLocked] = useState<boolean | null>(null)
  const [pinEnabled, setPinEnabled] = useState(false)
  const [accountLinked, setAccountLinked] = useState(false)
  const [accountEmail, setAccountEmail] = useState('')
  const [serverName, setServerName] = useState('')
  const [tokenPreview, setTokenPreview] = useState('')
  const [tokenPresent, setTokenPresent] = useState(false)
  const [clientId, setClientId] = useState('')
  const [pin, setPin] = useState('')
  const [online, setOnline] = useState(false)
  const [status, setStatus] = useState<MotorStatus | null>(null)
  const [statusLoading, setStatusLoading] = useState(true)
  const [statusHydrated, setStatusHydrated] = useState(false)
  const [error, setError] = useState('')
  const [updatedAt, setUpdatedAt] = useState('')
  const [page, setPage] = useState<PageId>('status')
  const [toast, setToast] = useState<{ msg: string; kind: 'ok' | 'err' } | null>(null)
  const [banner, setBanner] = useState<UpdateBanner | null>(null)
  const [updateStuck, setUpdateStuck] = useState(false)
  const [recoverBusy, setRecoverBusy] = useState(false)
  const [lang, setLang] = useState(currentLang())
  const [, setI18nTick] = useState(0)
  const [about, setAbout] = useState<AboutInfo | null>(null)
  const [unlinkOpen, setUnlinkOpen] = useState(false)
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountError, setAccountError] = useState('')
  const [claimBusy, setClaimBusy] = useState(false)
  const [claimError, setClaimError] = useState('')
  const [unlinkLinkSent, setUnlinkLinkSent] = useState(false)

  useEffect(() => subscribeI18n(() => {
    setLang(currentLang())
    setI18nTick((n) => n + 1)
  }), [])

  const showToast = useCallback((msg: string, kind: 'ok' | 'err' = 'ok') => {
    setToast({ msg, kind })
    window.setTimeout(() => setToast(null), 3600)
  }, [])

  const enterLockScreen = useCallback(() => {
    setLocked(true)
    setStatus(null)
    setStatusHydrated(false)
    setStatusLoading(false)
    setBanner(null)
    setOnline(false)
    setError('')
    setPin('')
  }, [])

  const refreshSession = useCallback(async () => {
    const session = await motorBridge.session()
    const nextLocked = Boolean(session.locked)
    setLocked(nextLocked)
    setPinEnabled(Boolean(session.pin_enabled))
    setAccountLinked(Boolean(session.account_linked))
    setAccountEmail(String(session.account_email || ''))
    setServerName(String(session.server_name || ''))
    setTokenPreview(String(session.token_preview || ''))
    setTokenPresent(Boolean(session.token_present))
    setClientId(String(session.client_id || ''))
    if (nextLocked) {
      setStatus(null)
      setBanner(null)
      setError('')
    }
    return session
  }, [])

  const runShell = useCallback(
    async (action: string, okMsg: string) => {
      try {
        const result = await motorBridge.shell(action)
        if (isGuiLockedPayload(result)) {
          enterLockScreen()
          void refreshSession()
          return
        }
        showToast(result.ok ? okMsg : t('toast_error_generic'), result.ok ? 'ok' : 'err')
      } catch (reason) {
        showToast(reason instanceof Error ? reason.message : String(reason), 'err')
      }
    },
    [enterLockScreen, refreshSession, showToast],
  )

  const refreshBanner = useCallback(async () => {
    try {
      const result = await motorBridge.update_banner('status')
      if (isGuiLockedPayload(result)) {
        enterLockScreen()
        return
      }
      const st = result.status
      setBanner(st && typeof st === 'object' ? (st as UpdateBanner) : null)
    } catch {
      setBanner(null)
    }
  }, [enterLockScreen])

  const checkUpdates = useCallback(async () => {
    try {
      const result = await motorBridge.shell('check_updates')
      if (isGuiLockedPayload(result)) {
        enterLockScreen()
        void refreshSession()
        return
      }
      if (!result.ok && result.error) {
        showToast(String(result.detail || result.error || t('toast_update_failed')), 'err')
        void refreshBanner()
        return
      }
      if (result.update_available) {
        if (result.busy || result.in_flight) {
          showToast(t('toast_update_available', { latest: String(result.latest || result.tag || '') }))
          void refreshBanner()
          return
        }
        if (result.started) {
          showToast(t('toast_update_available', { latest: String(result.latest || result.tag || '') }))
        } else {
          showToast(String(result.detail || t('toast_update_start_failed')), 'err')
        }
        void refreshBanner()
        return
      }
      showToast(
        t('toast_update_current', {
          version: String(result.installed || status?.version || '—'),
        }),
      )
    } catch (reason) {
      showToast(reason instanceof Error ? reason.message : String(reason), 'err')
    }
  }, [enterLockScreen, refreshBanner, refreshSession, showToast, status?.version])

  const openAbout = useCallback(async () => {
    try {
      const result = await motorBridge.shell('about')
      if (isGuiLockedPayload(result)) {
        enterLockScreen()
        void refreshSession()
        return
      }
      if (!result.ok) {
        showToast(String(result.error || t('toast_error_generic')), 'err')
        return
      }
      setAbout({
        version: String(result.version || status?.version || ''),
        website: String(result.website || 'https://asteria.run'),
        github: String(result.github || ''),
        log_path: String(result.log_path || ''),
      })
    } catch (reason) {
      showToast(reason instanceof Error ? reason.message : String(reason), 'err')
    }
  }, [enterLockScreen, refreshSession, showToast, status?.version])

  const mapAccountError = useCallback((result: { error?: unknown; reason?: unknown }) => {
    const code = String(result.error || result.reason || 'account')
    if (code === 'pin_required') return t('account_pin_required')
    if (code === 'pin_verification_failed' || code === 'pin_set_failed') return t('account_pin_wrong')
    if (code === 'invalid_credentials') return t('claim_bad_credentials')
    if (code === 'already_linked_other' || code === 'conflict_other_account') {
      return t('claim_other_account')
    }
    if (code === 'invalid_confirm_code' || code === 'confirm_code_invalid') {
      return t('account_unlink_bad_code')
    }
    if (code === 'email_mismatch') return t('account_unlink_email_mismatch')
    if (code === 'missing_confirm_code') return t('account_unlink_need_mail_first')
    if (code === 'unlink_mail_unavailable') return t('account_unlink_mail_unavailable')
    if (code === 'token_missing') return t('toast_token_missing')
    if (code === 'missing_credentials') return t('toast_need_creds')
    if (code === 'account' || code === 'account_unknown_action') return t('toast_account_failed')
    // Never surface raw API/error codes in the UI.
    return t('toast_account_failed')
  }, [])

  const claimAccount = useCallback(async (email: string, password: string, accountPin: string) => {
    setClaimBusy(true)
    setClaimError('')
    try {
      const result = await motorBridge.account('link', email, password, accountPin)
      if (isGuiLockedPayload(result)) {
        enterLockScreen()
        void refreshSession()
        return
      }
      if (!result.ok) {
        setClaimError(mapAccountError(result))
        return
      }
      showToast(t('toast_link_ok'))
      setClaimError('')
      await refreshSession()
    } catch (reason) {
      setClaimError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setClaimBusy(false)
    }
  }, [enterLockScreen, mapAccountError, refreshSession, showToast])

  const watchUnlinkCompletion = useCallback(async () => {
    for (let i = 0; i < 90; i++) {
      await new Promise((resolve) => window.setTimeout(resolve, 4000))
      try {
        const session = await refreshSession()
        if (!session.account_linked) {
          setUnlinkOpen(false)
          setUnlinkLinkSent(false)
          showToast(t('toast_unlink_ok'))
          return
        }
      } catch {
        // keep waiting — user may still click the email link
      }
    }
  }, [refreshSession, showToast])

  const requestUnlinkLink = useCallback(async (
    password: string,
    accountPin: string,
    emailConfirm: string,
  ) => {
    setAccountBusy(true)
    setAccountError('')
    try {
      if (emailConfirm.trim().toLowerCase() !== accountEmail.trim().toLowerCase()) {
        setAccountError(t('account_unlink_email_mismatch'))
        return
      }
      const result = await motorBridge.account('unlink_request', accountEmail, password, accountPin)
      if (isGuiLockedPayload(result)) {
        setUnlinkOpen(false)
        enterLockScreen()
        void refreshSession()
        return
      }
      if (!result.ok) {
        setAccountError(mapAccountError(result))
        return
      }
      setUnlinkLinkSent(true)
      showToast(t('toast_unlink_link_sent'))
      void watchUnlinkCompletion()
    } catch (reason) {
      setAccountError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setAccountBusy(false)
    }
  }, [accountEmail, enterLockScreen, mapAccountError, refreshSession, showToast, watchUnlinkCompletion])

  const refresh = useCallback(async (opts?: { silent?: boolean }) => {
    const silent = Boolean(opts?.silent && statusHydrated)
    if (!silent) setStatusLoading(true)
    try {
      const session = await refreshSession()
      if (session.locked) return

      const pong = await motorBridge.ping()
      setOnline(pong.ok)
      setUpdateStuck(Boolean(pong.update_stuck) && !pong.ok)
      if (!pong.ok) {
        // Keep last known status so toggles don't flash Off while motor restarts.
        if (!statusHydrated) {
          setStatus(null)
          setError(
            pong.update_stuck ? t('motor_unreachable_update_stuck') : t('motor_unreachable'),
          )
        } else if (!silent || pong.update_stuck) {
          setError(
            pong.update_stuck ? t('motor_unreachable_update_stuck') : t('status_refreshing'),
          )
        }
        void refreshBanner()
        return
      }
      setUpdateStuck(false)
      const snapshot = await motorBridge.status()
      if (isGuiLockedPayload(snapshot)) {
        enterLockScreen()
        void refreshSession()
        return
      }
      setStatus(snapshot)
      setStatusHydrated(true)
      setError(snapshot.ok === false ? String(snapshot.error ?? t('status_failed')) : '')
      setUpdatedAt(new Date().toLocaleTimeString(currentLang() === 'en' ? 'en-US' : 'tr-TR'))
      void refreshBanner()
    } catch (reason) {
      setOnline(false)
      if (!statusHydrated) {
        setError(reason instanceof Error ? reason.message : String(reason))
      } else if (!silent) {
        setError(t('status_refreshing'))
      }
    } finally {
      if (!silent) setStatusLoading(false)
    }
  }, [enterLockScreen, refreshBanner, refreshSession, statusHydrated])

  // When motor bumps status_generation (remote cmd applied), refresh ASAP.
  const statusGeneration = Number((status as { status_generation?: number } | null)?.status_generation || 0)

  useEffect(() => {
    const syncGate = () => {
      void refreshSession()
    }
    const ready = async () => {
      try {
        await loadI18n()
        setLang(currentLang())
        setI18nTick((n) => n + 1)
        const session = await refreshSession()
        if (!session.locked) void refresh()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : String(reason))
      }
    }
    window.addEventListener('pywebviewready', ready)
    window.addEventListener('asteria-session-gate', syncGate)
    window.addEventListener('focus', syncGate)
    document.addEventListener('visibilitychange', syncGate)
    void ready()
    // Quiet poll: remote cmds still surface within a few seconds without
    // hammering STATUS / threats/config (StatusPage extras) every 2s.
    const ms = locked === false ? (statusGeneration > 0 ? 3000 : 5000) : 8000
    const timer = window.setInterval(() => {
      if (locked === false) void refresh({ silent: true })
      else void refreshSession()
    }, ms)
    return () => {
      window.removeEventListener('pywebviewready', ready)
      window.removeEventListener('asteria-session-gate', syncGate)
      window.removeEventListener('focus', syncGate)
      document.removeEventListener('visibilitychange', syncGate)
      window.clearInterval(timer)
    }
  }, [locked, refresh, refreshSession, statusGeneration])

  const onMenuAction = useCallback(
    (action: MenuAction) => {
      if (action === 'refresh') {
        void refresh({ silent: false })
        return
      }
      if (action === 'link_account') {
        setPage('settings')
        setClaimError('')
        return
      }
      if (action === 'unlink_account') {
        setAccountError('')
        setUnlinkLinkSent(false)
        setUnlinkOpen(true)
        return
      }
      if (action === 'about') {
        void openAbout()
        return
      }
      if (action === 'check_updates') {
        void checkUpdates()
        return
      }
      const map: Record<
        Exclude<MenuAction, 'refresh' | 'link_account' | 'unlink_account' | 'about' | 'check_updates'>,
        [string, string]
      > = {
        open_dashboard: ['open_dashboard', t('toast_dashboard')],
        copy_token: ['copy_token', t('toast_token')],
        open_servers: ['open_servers', t('toast_servers')],
        open_logs: ['open_logs', t('toast_logs')],
        open_website: ['open_website', t('toast_website')],
        open_github: ['open_github', t('toast_github')],
      }
      const [shell, toast] = map[action]
      void runShell(shell, toast)
    },
    [checkUpdates, openAbout, refresh, runShell],
  )

  const submitPin = async (event: FormEvent) => {
    event.preventDefault()
    const result = await motorBridge.unlock(pin)
    if (result.ok) {
      setLocked(false)
      setPin('')
      setError('')
      void refresh()
      return
    }
    setError(
      result.reason === 'locked_out'
        ? t('lock_locked_out', { seconds: result.lockout_seconds ?? 0 })
        : t('lock_bad_pin'),
    )
  }

  const dismissBanner = async () => {
    await motorBridge.update_banner('dismiss')
    setBanner(null)
  }

  const recoverUpdate = useCallback(async () => {
    setRecoverBusy(true)
    try {
      const result = await motorBridge.update_banner('recover')
      if (isGuiLockedPayload(result)) {
        enterLockScreen()
        return
      }
      if (result.ok === false && result.error === 'helper_in_flight') {
        showToast(t('toast_update_recover_failed'), 'err')
        return
      }
      setBanner(result.status && typeof result.status === 'object' ? (result.status as UpdateBanner) : null)
      setUpdateStuck(false)
      showToast(
        result.motor_ok || result.aborted ? t('toast_update_recovered') : t('toast_update_recover_failed'),
        result.motor_ok || result.aborted ? 'ok' : 'err',
      )
      // Give Background a moment, then refresh motor state.
      window.setTimeout(() => {
        void refresh()
      }, 1500)
    } catch (reason) {
      showToast(reason instanceof Error ? reason.message : String(reason), 'err')
    } finally {
      setRecoverBusy(false)
    }
  }, [enterLockScreen, refresh, showToast])

  const switchLang = async (next: 'tr' | 'en') => {
    await loadI18n(next)
    setLang(currentLang())
    setI18nTick((n) => n + 1)
    if (locked === false) {
      showToast(next === 'en' ? t('toast_lang_en') : t('toast_lang_tr'))
    }
  }

  const nav = navItems()

  useEffect(() => {
    const ver = String(status?.version || '').trim()
    document.title = ver ? `Asteria v${ver}` : 'Asteria'
  }, [status?.version])

  // Fast banner poll while an update is in flight.
  useEffect(() => {
    if (locked !== false) return
    const active =
      banner &&
      ['accepted', 'downloading', 'staging', 'installing'].includes(String(banner.phase || ''))
    if (!active) return
    const timer = window.setInterval(() => {
      void refreshBanner()
    }, 800)
    return () => window.clearInterval(timer)
  }, [banner, locked, refreshBanner])

  // PIN gate: never render Control Center chrome while host session is locked.
  if (locked !== false) {
    return (
      <LockScreen
        ready={locked === true}
        pin={pin}
        onPinChange={setPin}
        onUnlock={(event) => void submitPin(event)}
        error={error}
        accountLinked={accountLinked}
        accountEmail={accountEmail}
        onOpenDashboard={() => void motorBridge.shell('open_dashboard')}
        lang={lang}
        onLang={(next) => void switchLang(next)}
      />
    )
  }

  // First-run / orphan: claim this agent before full Control Center (anti-brick).
  if (!accountLinked) {
    return (
      <ClaimAccountGate
        pinEnabled={pinEnabled}
        busy={claimBusy}
        error={claimError}
        onLink={(email, password, accountPin) => void claimAccount(email, password, accountPin)}
        onOpenDashboard={() => void motorBridge.shell('open_dashboard')}
        onOpenRegister={() => void motorBridge.shell('open_website')}
      />
    )
  }

  const bannerText = (() => {
    if (!banner) return ''
    const phase = String(banner.phase || '').toLowerCase()
    const pct = banner.progress != null ? Number(banner.progress) : null
    let title = t('update_banner_default')
    if (phase === 'accepted') title = t('update_banner_accepted')
    else if (phase === 'downloading' && pct != null && Number.isFinite(pct)) {
      title = t('update_banner_downloading_pct', { pct: Math.round(pct) })
    } else if (phase === 'downloading') title = t('update_banner_downloading')
    else if (phase === 'staging') title = t('update_banner_staging')
    else if (phase === 'installing') title = t('update_banner_installing')
    else if (phase === 'done') title = t('update_banner_done')
    else if (phase === 'failed') {
      title = banner.detail === 'update_stalled' ? t('update_banner_stalled') : t('update_banner_failed')
    }
    const fromV = String(banner.from_version || '')
    const toV = String(banner.to_version || '')
    const ver =
      fromV || toV
        ? t('update_banner_version_line', { from_v: fromV || '—', to_v: toV || '—' })
        : ''
    const err = phase === 'failed' ? String(banner.error || banner.detail || '') : ''
    return [title, ver, err].filter(Boolean).join(' · ')
  })()

  const bannerProgress =
    banner?.progress != null && Number.isFinite(Number(banner.progress))
      ? Math.max(0, Math.min(100, Number(banner.progress)))
      : banner?.phase === 'installing' || banner?.phase === 'staging'
        ? 100
        : banner?.phase === 'accepted'
          ? 5
          : null

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="side-brand">
          <BrandSidebar />
        </div>
        <nav>
          {nav.map((item) => (
            <button
              key={item.id}
              type="button"
              className={page === item.id ? 'nav on' : 'nav'}
              onClick={() => setPage(item.id)}
            >
              <span>{item.label}</span>
              <small>{item.blurb}</small>
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="lang-row" role="group" aria-label="Language">
            <button type="button" className={`lang-btn ${lang === 'tr' ? 'on' : ''}`} onClick={() => void switchLang('tr')}>
              TR
            </button>
            <span className="lang-sep" aria-hidden="true">|</span>
            <button type="button" className={`lang-btn ${lang === 'en' ? 'on' : ''}`} onClick={() => void switchLang('en')}>
              EN
            </button>
          </div>
          <div className={`side-status ${online ? 'online' : 'offline'}`}>
            <span className="side-status-motor">
              <i />
              {online ? t('motor_online') : t('motor_offline')}
            </span>
            <span className="side-status-sep" aria-hidden="true">|</span>
            <span className="side-status-ver" title={t('about_version')}>
              {status?.version ? `v${String(status.version)}` : '—'}
            </span>
          </div>
          <button
            type="button"
            className="btn ghost side-tray-btn"
            onClick={() => {
              void motorBridge.shell('minimize').then((result) => {
                if (result.ok !== false) enterLockScreen()
              })
            }}
          >
            {t('tray_hide')}
          </button>
        </div>
      </aside>

      <main className="content">
        {/* All operator alerts share one top stack (never split around the identity row). */}
        {(banner || error) && (
          <div className="top-alerts" role="region" aria-label="alerts">
            {banner && (
              <div className={`update-banner ${banner.phase === 'failed' ? 'fail' : banner.phase === 'done' ? 'ok' : ''}`}>
                <div className="update-banner-copy">
                  <span>{bannerText}</span>
                  {bannerProgress != null && (
                    <div className="update-banner-track" aria-hidden="true">
                      <div className="update-banner-fill" style={{ width: `${bannerProgress}%` }} />
                    </div>
                  )}
                </div>
                <div className="update-banner-actions">
                  {(banner.phase === 'failed' ||
                    banner.can_abort ||
                    ['accepted', 'downloading', 'staging', 'installing'].includes(String(banner.phase || ''))) && (
                    <button
                      type="button"
                      className="btn ghost sm"
                      disabled={recoverBusy}
                      onClick={() => void recoverUpdate()}
                    >
                      {t('update_recover')}
                    </button>
                  )}
                  <button type="button" className="btn ghost sm" onClick={() => void dismissBanner()}>
                    {t('btn_close')}
                  </button>
                </div>
              </div>
            )}
            {error && (
              <aside className={`error${error === t('status_refreshing') ? ' soft' : ''}`}>
                <span>{error}</span>
                {(updateStuck || (!online && statusHydrated === false)) &&
                  !(
                    banner &&
                    (banner.phase === 'failed' ||
                      banner.can_abort ||
                      ['accepted', 'downloading', 'staging', 'installing'].includes(
                        String(banner.phase || ''),
                      ))
                  ) && (
                  <button
                    type="button"
                    className="btn ghost sm"
                    disabled={recoverBusy}
                    onClick={() => void recoverUpdate()}
                  >
                    {t('update_recover')}
                  </button>
                )}
              </aside>
            )}
          </div>
        )}

        {/* Left: identity row + live meters; right: action buttons (single row). */}
        <header className="topbar topbar-actions">
          <div className="topbar-left">
            <IdentityStrip
              serverName={serverName}
              tokenPreview={tokenPreview}
              tokenPresent={tokenPresent}
              clientId={clientId}
              publicIp={String(status?.public_ip || '')}
              onCopyToken={() => void runShell('copy_token', t('toast_token'))}
            />
            <LiveMeters status={status} />
          </div>
          <div className="btn-row">
            {accountLinked && (
              <button
                type="button"
                className="account-chip"
                data-tooltip={t('account_chip_dashboard')}
                aria-label={t('account_chip_dashboard')}
                onClick={() => void runShell('open_dashboard', t('toast_dashboard'))}
              >
                <span className="account-chip-icon" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <circle cx="12" cy="8" r="3.5" />
                    <path d="M5 20c.6-4 3-6 7-6s6.4 2 7 6" />
                  </svg>
                </span>
                <span>{accountEmail || t('lock_linked_badge')}</span>
              </button>
            )}
            <HeaderMenu
              version={String(status?.version || '')}
              accountLinked={accountLinked}
              onAction={onMenuAction}
            />
          </div>
        </header>

        {page === 'status' && (
          <StatusPage
            status={status}
            online={online}
            statusLoading={statusLoading || !statusHydrated}
            updatedAt={updatedAt}
            onRefresh={() => void refresh({ silent: false })}
            onToast={showToast}
            onNavigate={(next) => setPage(next)}
          />
        )}
        {page === 'threat' && <ThreatPage onToast={showToast} />}
        {page === 'iplist' && <IpListPage onToast={showToast} />}
        {page === 'services' && <ServicesPage onToast={showToast} />}
        {page === 'layers' && (
          <LayersPage
            status={status}
            statusLoading={statusLoading || !statusHydrated}
            onRefresh={() => void refresh({ silent: false })}
            onToast={showToast}
          />
        )}
        {page === 'tools' && <ToolsPage onToast={showToast} />}
        {page === 'settings' && (
          <SettingsPage
            pinEnabled={pinEnabled}
            onToast={showToast}
            onSession={() => void refreshSession()}
          />
        )}
      </main>

      {toast && <div className={`toast ${toast.kind}`}>{toast.msg}</div>}
      {about && (
        <AboutModal
          info={about}
          onClose={() => setAbout(null)}
          onOpenWebsite={() => void runShell('open_website', t('toast_website'))}
          onOpenGithub={() => void runShell('open_github', t('toast_github'))}
          onOpenLogs={() => void runShell('open_logs', t('toast_logs'))}
        />
      )}
      {unlinkOpen && (
        <AccountActionModal
          email={accountEmail}
          busy={accountBusy}
          error={accountError}
          linkSent={unlinkLinkSent}
          onClose={() => {
            if (!accountBusy) {
              setUnlinkOpen(false)
              setUnlinkLinkSent(false)
            }
          }}
          onRequestLink={(password, accountPin, emailConfirm) =>
            void requestUnlinkLink(password, accountPin, emailConfirm)
          }
        />
      )}
    </div>
  )
}
