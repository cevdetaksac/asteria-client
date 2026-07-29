import { useCallback, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { RdpSecureMoveModal, type RdpMoveInfo } from '../components/RdpSecureMoveModal'
import { t } from '../i18n'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type CatalogService = { port: string; service: string }

export function ServicesPage({ onToast }: Props) {
  const [catalog, setCatalog] = useState<CatalogService[]>([])
  const [running, setRunning] = useState<string[]>([])
  const [busy, setBusy] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [rdp, setRdp] = useState<RdpMoveInfo | null>(null)
  const [rdpModal, setRdpModal] = useState(false)
  const [rdpBusy, setRdpBusy] = useState(false)
  const [secondsLeft, setSecondsLeft] = useState(0)
  const [pageHelp, setPageHelp] = useState(false)

  const refreshRdp = useCallback(async () => {
    const result = await motorBridge.rdp('status')
    if (!result.ok) return null
    const info: RdpMoveInfo = {
      protected: Boolean(result.protected),
      current_port: Number(result.current_port || 3389),
      secure_port: Number(result.secure_port || 53389),
      standard_port: Number(result.standard_port || 3389),
      admin: result.admin !== false,
      pending: Boolean(result.pending),
      pending_mode: result.pending_mode ? String(result.pending_mode) : undefined,
      pending_from: result.pending_from != null ? Number(result.pending_from) : undefined,
      pending_to: result.pending_to != null ? Number(result.pending_to) : undefined,
      seconds_left: Number(result.seconds_left || 0),
      confirm_seconds: Number(result.confirm_seconds || 60),
    }
    setRdp(info)
    setSecondsLeft(info.seconds_left || 0)
    if (info.pending) setRdpModal(true)
    return info
  }, [])

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const [cat, list, status] = await Promise.all([
        motorBridge.catalog(),
        motorBridge.ipc('HONEYPOT_LIST'),
        motorBridge.status(),
      ])
      setCatalog(Array.isArray(cat.services) ? cat.services : [])
      const fromList = Array.isArray(list.services) ? list.services : []
      const names = fromList
        .map((row) => {
          if (typeof row === 'string') return row.toUpperCase()
          if (row && typeof row === 'object' && 'service' in row) {
            return String((row as { service: string }).service).toUpperCase()
          }
          return ''
        })
        .filter(Boolean)
      const fromStatus = Array.isArray(status.running_services)
        ? status.running_services.map((s) => String(s).toUpperCase())
        : []
      setRunning(Array.from(new Set([...names, ...fromStatus])))
      await refreshRdp()
    } catch (reason) {
      onToast(reason instanceof Error ? reason.message : String(reason), 'err')
    } finally {
      setLoading(false)
    }
  }, [onToast, refreshRdp])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 6000)
    return () => window.clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    if (!rdp?.pending) return
    const tick = window.setInterval(() => {
      setSecondsLeft((n) => Math.max(0, n - 1))
      void refreshRdp()
    }, 1000)
    return () => window.clearInterval(tick)
  }, [rdp?.pending, refreshRdp])

  const toggle = async (svc: CatalogService, start: boolean) => {
    setBusy(svc.service)
    try {
      const result = start
        ? await motorBridge.ipc('HONEYPOT_START', { service: svc.service, port: Number(svc.port) })
        : await motorBridge.ipc('HONEYPOT_STOP', { service: svc.service })
      onToast(
        result.ok
          ? start
            ? t('toast_svc_start', { service: svc.service })
            : t('toast_svc_stop', { service: svc.service })
          : String(result.error || 'HONEYPOT'),
        result.ok ? 'ok' : 'err',
      )
      await refresh()
    } finally {
      setBusy('')
    }
  }

  const beginRdp = async () => {
    setRdpBusy(true)
    try {
      const mode = rdp?.protected ? 'rollback' : 'secure'
      const result = await motorBridge.rdp('begin', mode)
      if (!result.ok) {
        onToast(String(result.error || result.detail || t('toast_rdp_fail')), 'err')
        return
      }
      onToast(t('toast_rdp_moved', { port: String(result.to_port || result.current_port || '') }), 'ok')
      await refreshRdp()
    } finally {
      setRdpBusy(false)
    }
  }

  const confirmRdp = async () => {
    setRdpBusy(true)
    try {
      const result = await motorBridge.rdp('confirm')
      if (!result.ok) {
        onToast(String(result.error || t('toast_rdp_fail')), 'err')
        return
      }
      onToast(t('toast_rdp_confirmed', { port: String(result.current_port || '') }), 'ok')
      setRdpModal(false)
      await refresh()
    } finally {
      setRdpBusy(false)
    }
  }

  const cancelRdp = async () => {
    setRdpBusy(true)
    try {
      const result = await motorBridge.rdp('cancel')
      onToast(
        result.ok
          ? t('toast_rdp_reverted', { port: String(result.current_port || '') })
          : String(result.error || t('toast_rdp_fail')),
        result.ok ? 'ok' : 'err',
      )
      setRdpModal(false)
      await refresh()
    } finally {
      setRdpBusy(false)
    }
  }

  const openRdpModal = async () => {
    const info = await refreshRdp()
    if (info) setRdpModal(true)
  }

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('services_eyebrow')}</p>
          <h2>{t('services_title')}</h2>
          <p className="muted">{t('services_blurb')}</p>
        </div>
        <div className="btn-row">
          <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
            {t('help_more')}
          </button>
          <button type="button" className="btn" onClick={() => void refresh()}>{t('btn_refresh')}</button>
        </div>
      </div>

      <div className="service-grid">
        {loading && catalog.length === 0 && <p className="muted">{t('status_section_loading')}</p>}
        {!loading && catalog.length === 0 && <p className="muted">{t('services_empty')}</p>}
        {catalog.map((svc) => {
          const active = running.includes(svc.service.toUpperCase())
          const isRdp = svc.service.toUpperCase() === 'RDP'
          const listenPort = isRdp ? Number(svc.port || 3389) : Number(svc.port)
          const rowBusy = loading || busy === svc.service
          return (
            <article
              key={`${svc.service}-${svc.port}`}
              className={`service-card ${active ? 'active' : ''}${loading ? ' loading' : ''}`}
            >
              <h3 className="service-card-title">
                {svc.service}
                <span className="port"> : {listenPort}</span>
              </h3>
              <div className="service-actions">
                <button
                  type="button"
                  className={`btn ${active && !loading ? 'danger' : ''}`}
                  disabled={rowBusy}
                  onClick={() => void toggle(svc, !active)}
                >
                  {loading
                    ? t('label_loading')
                    : active
                      ? t('layers_close')
                      : t('layers_open')}
                </button>
              </div>
            </article>
          )
        })}
      </div>

      <article className={`panel rdp-tool-card${loading && !rdp ? ' loading' : ''}`}>
        <div className="rdp-tool-head">
          <div>
            <p className="eyebrow">{t('services_rdp_tool_eyebrow')}</p>
            <h3>{t('services_rdp_tool_title')}</h3>
            <p className="muted">{t('services_rdp_tool_blurb')}</p>
          </div>
          {loading && !rdp ? (
            <span className="pill muted">{t('label_loading')}</span>
          ) : rdp ? (
            <span className={`pill ${rdp.protected ? 'ok' : 'off'}`}>
              {rdp.protected
                ? t('services_rdp_protected', { port: rdp.current_port })
                : t('services_rdp_standard', { port: rdp.current_port })}
            </span>
          ) : null}
        </div>
        <ol className="rdp-tool-steps">
          <li>{t('services_rdp_step_1')}</li>
          <li>{t('services_rdp_step_2')}</li>
          <li>{t('services_rdp_step_3')}</li>
        </ol>
        {rdp?.pending && (
          <p className="muted rdp-status">{t('services_rdp_pending', { sec: secondsLeft })}</p>
        )}
        <div className="btn-row">
          <button type="button" className="btn" disabled={rdpBusy} onClick={() => void openRdpModal()}>
            {t('services_rdp_secure_btn')}
          </button>
          <button type="button" className="btn ghost" disabled={rdpBusy} onClick={() => void refreshRdp()}>
            {t('btn_refresh')}
          </button>
        </div>
      </article>

      {rdpModal && rdp && (
        <RdpSecureMoveModal
          info={rdp}
          busy={rdpBusy}
          secondsLeft={secondsLeft}
          onClose={() => {
            if (!rdp.pending) setRdpModal(false)
          }}
          onBegin={beginRdp}
          onConfirm={confirmRdp}
          onCancel={cancelRdp}
        />
      )}
      {pageHelp && (
        <DetailModal
          title={t('services_title')}
          eyebrow={t('services_eyebrow')}
          blurb={t('services_blurb')}
          guide={<FeatureGuide prefix="help_hp" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
