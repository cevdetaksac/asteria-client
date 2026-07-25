import { useCallback, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { t } from '../i18n'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type CatalogService = { port: string; service: string }

export function ServicesPage({ onToast }: Props) {
  const [catalog, setCatalog] = useState<CatalogService[]>([])
  const [running, setRunning] = useState<string[]>([])
  const [busy, setBusy] = useState<string>('')

  const refresh = useCallback(async () => {
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
    } catch (reason) {
      onToast(reason instanceof Error ? reason.message : String(reason), 'err')
    }
  }, [onToast])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 6000)
    return () => window.clearInterval(timer)
  }, [refresh])

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

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('services_eyebrow')}</p>
          <h2>{t('services_title')}</h2>
          <p className="muted">{t('services_blurb')}</p>
        </div>
        <button type="button" className="btn" onClick={() => void refresh()}>{t('btn_refresh')}</button>
      </div>

      <div className="service-grid">
        {catalog.length === 0 && <p className="muted">{t('services_empty')}</p>}
        {catalog.map((svc) => {
          const active = running.includes(svc.service.toUpperCase())
          return (
            <article key={`${svc.service}-${svc.port}`} className={`service-card ${active ? 'on' : ''}`}>
              <div>
                <p className="eyebrow">{active ? t('label_active') : t('label_off')}</p>
                <h3>{svc.service}</h3>
                <p className="mono muted">:{svc.port}</p>
              </div>
              <button
                type="button"
                className={`btn ${active ? 'danger' : ''}`}
                disabled={busy === svc.service}
                onClick={() => void toggle(svc, !active)}
              >
                {active ? t('btn_stop') : t('btn_start')}
              </button>
            </article>
          )
        })}
      </div>
    </section>
  )
}
