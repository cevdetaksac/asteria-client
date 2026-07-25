import { type FormEvent, useCallback, useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from './bridge'
import { AccountActionModal } from './components/AccountActionModal'
import { AboutModal, type AboutInfo } from './components/AboutModal'
import { BrandMark, BrandWordmark } from './components/Brand'
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

type UpdateBanner = {
  phase?: string
  to_version?: string
  from_version?: string
  progress?: number
  detail?: string
  error?: string
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
  const [error, setError] = useState('')
  const [updatedAt, setUpdatedAt] = useState('')
  const [page, setPage] = useState<PageId>('status')
  const [toast, setToast] = useState<{ msg: string; kind: 'ok' | 'err' } | null>(null)
  const [banner, setBanner] = useState<UpdateBanner | null>(null)
  const [lang, setLang] = useState(currentLang())
  const [, setI18nTick] = useState(0)
  const [about, setAbout] = useState<AboutInfo | null>(null)
  const [unlinkOpen, setUnlinkOpen] = useState(false)
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountError, setAccountError] = useState('')

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
        showToast(result.ok ? okMsg : String(result.error || action), result.ok ? 'ok' : 'err')
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
        return
      }
      if (result.update_available) {
        showToast(t('toast_update_available', { latest: String(result.latest || result.tag || '') }))
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
        showToast(String(result.error || 'about'), 'err')
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

  const unlinkAccount = useCallback(async (password: string, accountPin: string) => {
    setAccountBusy(true)
    setAccountError('')
    try {
      const result = await motorBridge.account(
        'unlink',
        accountEmail,
        password,
        accountPin,
      )
      if (isGuiLockedPayload(result)) {
        setUnlinkOpen(false)
        enterLockScreen()
        void refreshSession()
        return
      }
      if (!result.ok) {
        const message =
          result.error === 'pin_required'
            ? t('account_pin_required')
            : result.error === 'pin_verification_failed'
              ? t('account_pin_wrong')
              : String(result.error || result.reason || 'account')
        setAccountError(message)
        return
      }
      setUnlinkOpen(false)
      showToast(t('toast_unlink_ok'))
      await refreshSession()
    } catch (reason) {
      setAccountError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setAccountBusy(false)
    }
  }, [accountEmail, enterLockScreen, refreshSession, showToast])

  const onMenuAction = useCallback(
    (action: MenuAction) => {
      if (action === 'link_account') {
        setPage('settings')
        return
      }
      if (action === 'unlink_account') {
        setAccountError('')
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
        Exclude<MenuAction, 'link_account' | 'unlink_account' | 'about' | 'check_updates'>,
        [string, string]
      > = {
        copy_token: ['copy_token', t('toast_token')],
        open_servers: ['open_servers', t('toast_servers')],
        open_logs: ['open_logs', t('toast_logs')],
        open_website: ['open_website', t('toast_website')],
        open_github: ['open_github', t('toast_github')],
      }
      const [shell, toast] = map[action]
      void runShell(shell, toast)
    },
    [checkUpdates, openAbout, runShell],
  )

  const refresh = useCallback(async () => {
    try {
      const session = await refreshSession()
      if (session.locked) return

      const pong = await motorBridge.ping()
      setOnline(pong.ok)
      if (!pong.ok) {
        setStatus(null)
        setError(t('motor_unreachable'))
        return
      }
      const snapshot = await motorBridge.status()
      if (isGuiLockedPayload(snapshot)) {
        enterLockScreen()
        void refreshSession()
        return
      }
      setStatus(snapshot)
      setError(snapshot.ok === false ? String(snapshot.error ?? t('status_failed')) : '')
      setUpdatedAt(new Date().toLocaleTimeString(currentLang() === 'en' ? 'en-US' : 'tr-TR'))
      void refreshBanner()
    } catch (reason) {
      setOnline(false)
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }, [enterLockScreen, refreshBanner, refreshSession])

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
    const timer = window.setInterval(() => {
      if (locked === false) void refresh()
      else void refreshSession()
    }, 4000)
    return () => {
      window.removeEventListener('pywebviewready', ready)
      window.removeEventListener('asteria-session-gate', syncGate)
      window.removeEventListener('focus', syncGate)
      document.removeEventListener('visibilitychange', syncGate)
      window.clearInterval(timer)
    }
  }, [locked, refresh, refreshSession])

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

  const switchLang = async (next: 'tr' | 'en') => {
    await loadI18n(next)
    setLang(currentLang())
    setI18nTick((n) => n + 1)
    if (locked === false) {
      showToast(next === 'en' ? t('toast_lang_en') : t('toast_lang_tr'))
    }
  }

  const nav = navItems()

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

  const bannerText = banner
    ? [
        banner.phase ? String(banner.phase).toUpperCase() : t('update_banner_default'),
        banner.to_version ? `→ ${banner.to_version}` : '',
        banner.progress != null ? `${banner.progress}%` : '',
        banner.detail || banner.error || '',
      ]
        .filter(Boolean)
        .join(' · ')
    : ''

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="side-brand">
          <BrandMark size={44} />
          <BrandWordmark />
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
          <div className={`connection ${online ? 'online' : 'offline'}`}>
            <span /> {online ? t('motor_online') : t('motor_offline')}
          </div>
          <div className="lang-row">
            <button type="button" className={`btn ghost sm ${lang === 'tr' ? 'on' : ''}`} onClick={() => void switchLang('tr')}>
              TR
            </button>
            <button type="button" className={`btn ghost sm ${lang === 'en' ? 'on' : ''}`} onClick={() => void switchLang('en')}>
              EN
            </button>
          </div>
          <button
            type="button"
            className="btn ghost sm"
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
        {banner && (
          <div className={`update-banner ${banner.phase === 'failed' ? 'fail' : ''}`}>
            <span>{bannerText}</span>
            <button type="button" className="btn ghost sm" onClick={() => void dismissBanner()}>
              {t('btn_close')}
            </button>
          </div>
        )}

        {/* Identity (host/token) left — actions + Help right (old GUI top-bar parity). */}
        <header className="topbar topbar-actions">
          <IdentityStrip
            serverName={serverName}
            tokenPreview={tokenPreview}
            tokenPresent={tokenPresent}
            clientId={clientId}
            onCopyToken={() => void runShell('copy_token', t('toast_token'))}
          />
          <LiveMeters status={status} />
          <div className="btn-row">
            {accountLinked && (
              <button
                type="button"
                className="account-chip"
                title={accountEmail}
                onClick={() => setPage('settings')}
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
            <button type="button" className="btn ghost sm" onClick={() => void runShell('open_dashboard', t('toast_dashboard'))}>
              {t('btn_dashboard')}
            </button>
            <button type="button" className="btn sm" onClick={() => void refresh()}>
              {t('btn_refresh')}
            </button>
            <HeaderMenu
              version={String(status?.version || '')}
              accountLinked={accountLinked}
              onAction={onMenuAction}
            />
          </div>
        </header>

        {error && <aside className="error">{error}</aside>}
        {page === 'status' && (
          <StatusPage
            status={status}
            online={online}
            updatedAt={updatedAt}
            onRefresh={() => void refresh()}
            onToast={showToast}
            onNavigate={(next) => setPage(next)}
          />
        )}
        {page === 'threat' && <ThreatPage onToast={showToast} />}
        {page === 'iplist' && <IpListPage onToast={showToast} />}
        {page === 'services' && <ServicesPage onToast={showToast} />}
        {page === 'layers' && (
          <LayersPage status={status} onRefresh={() => void refresh()} onToast={showToast} />
        )}
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
          onClose={() => {
            if (!accountBusy) setUnlinkOpen(false)
          }}
          onConfirm={(password, accountPin) => void unlinkAccount(password, accountPin)}
        />
      )}
    </div>
  )
}
