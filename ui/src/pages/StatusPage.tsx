import { useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { IconBtn, icons } from '../components/IconBtn'
import { Switch } from '../components/Switch'
import { t } from '../i18n'
import { asRecord, boolLabel, formatBps, pick, triLabel } from '../lib'

type Props = {
  status: MotorStatus | null
  online: boolean
  statusLoading?: boolean
  updatedAt: string
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
  onNavigate: (page: 'services' | 'layers' | 'threat' | 'iplist') => void
}

type HardenCheck = {
  id?: string
  label?: string
  ok?: boolean | null
  detail?: string
  fixable?: boolean
}

type IpRow = {
  ip: string
  services?: string[]
  attempts?: number
  score?: number
  reason?: string
  last_seen?: number
  status?: string
}

const IP_PREVIEW = 8

export function StatusPage({ status, online, statusLoading = false, updatedAt, onRefresh, onToast, onNavigate }: Props) {
  const running = Array.isArray(status?.running_services) ? status.running_services : []
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const rs = asRecord(status?.rs_quarantine)
  const resources = asRecord(status?.resources)
  const pending = statusLoading || !status
  const [checks, setChecks] = useState<HardenCheck[]>([])
  const [busy, setBusy] = useState(false)
  const [extrasLoading, setExtrasLoading] = useState(true)
  const [extrasHydrated, setExtrasHydrated] = useState(false)
  const [watching, setWatching] = useState<IpRow[]>([])
  const [blocked, setBlocked] = useState<IpRow[]>([])
  const [whitelist, setWhitelist] = useState<IpRow[]>([])
  const [ipTotals, setIpTotals] = useState({ watching: 0, blocked: 0, whitelist: 0 })
  const [detail, setDetail] = useState<'motor' | 'mode' | 'honeypot' | 'resources' | 'ransomware' | 'netguard' | null>(null)

  const loadExtras = async () => {
    setExtrasLoading(true)
    try {
      const [h, table, cloud] = await Promise.all([
        motorBridge.harden('status'),
        motorBridge.ipc('IP_TABLE'),
        motorBridge.cloud('GET', 'threats/config'),
      ])
      if (h.ok && Array.isArray(h.checks)) setChecks(h.checks as HardenCheck[])

      const watchRows = Array.isArray(table.watching) ? (table.watching as IpRow[]) : []
      const blockRows = Array.isArray(table.blocked) ? (table.blocked as IpRow[]) : []
      let wlRows = Array.isArray(table.whitelist) ? (table.whitelist as IpRow[]) : []
      const totals = asRecord(table.totals)

      // Cloud whitelist is SoT when motor local set is thin (frontend-only edge).
      if (cloud.ok && cloud.data && typeof cloud.data === 'object') {
        const wl = (cloud.data as Record<string, unknown>).whitelist_ips
        if (Array.isArray(wl)) {
          const fromCloud = wl.map(String).filter(Boolean)
          const seen = new Set(wlRows.map((r) => r.ip))
          for (const ip of fromCloud) {
            if (!seen.has(ip)) {
              wlRows.push({ ip, reason: 'whitelist', status: 'whitelisted' })
              seen.add(ip)
            }
          }
          setIpTotals({
            watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
            blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
            whitelist: Math.max(Number(totals.whitelist ?? 0) || 0, fromCloud.length),
          })
        } else {
          setIpTotals({
            watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
            blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
            whitelist: Number(totals.whitelist ?? wlRows.length) || wlRows.length,
          })
        }
      } else {
        setIpTotals({
          watching: Number(totals.watching ?? watchRows.length) || watchRows.length,
          blocked: Number(totals.blocked ?? blockRows.length) || blockRows.length,
          whitelist: Number(totals.whitelist ?? wlRows.length) || wlRows.length,
        })
      }

      setWatching(watchRows)
      setBlocked(blockRows)
      setWhitelist(wlRows)
      setExtrasHydrated(true)
    } finally {
      setExtrasLoading(false)
    }
  }

  useEffect(() => {
    void loadExtras()
    const timer = window.setInterval(() => void loadExtras(), 20000)
    return () => window.clearInterval(timer)
    // Intentionally not tied to `status` — App silent poll was re-firing
    // harden/IP_TABLE/threats/config every ~2s and spamming logs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const unlockRs = async () => {
    const result = await motorBridge.ipc('RS_UNLOCK')
    onToast(result.ok ? t('toast_rs_cleared') : String(result.error || 'RS unlock'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngAccept = async () => {
    const result = await motorBridge.ipc('NG_ACCEPT_SURFACE')
    onToast(result.ok ? t('toast_ng_accept') : String(result.error || 'NG accept'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const ngMaint = async (start: boolean) => {
    const result = await motorBridge.ipc(start ? 'NG_MAINT_START' : 'NG_MAINT_END_SNAPSHOT')
    onToast(
      result.ok ? (start ? t('toast_ng_maint_on') : t('toast_ng_maint_off')) : String(result.error || 'NG'),
      result.ok ? 'ok' : 'err',
    )
    onRefresh()
  }

  const toggleLayer = async (key: 'ransomware' | 'network_guard', value: boolean) => {
    if (pending || busy) return
    setBusy(true)
    try {
      const patch: Record<string, unknown> =
        key === 'ransomware'
          ? { ransomware_protection_enabled: value }
          : { protection: { network_guard: { enabled: value } } }
      const result = await motorBridge.cloud('POST', 'threats/config', patch)
      onToast(result.ok ? t('toast_layer_ok') : String(result.error || 'layer'), result.ok ? 'ok' : 'err')
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  const fixHarden = async (target: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.harden('fix', target)
      onToast(
        result.ok ? t('toast_fix_ok', { target }) : String(result.error || t('toast_fix_fail')),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const mutateIp = async (cmd: 'BLOCK_IP' | 'UNBLOCK_IP', ip: string) => {
    setBusy(true)
    try {
      const result = await motorBridge.ipc(cmd, { ip, reason: 'status' })
      onToast(
        result.ok
          ? cmd === 'BLOCK_IP'
            ? t('toast_blocked', { ip })
            : t('toast_unblocked', { ip })
          : String(result.error || 'IPC'),
        result.ok ? 'ok' : 'err',
      )
      await loadExtras()
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  const addWhitelist = async (ip: string) => {
    setBusy(true)
    try {
      const cloud = await motorBridge.cloud('GET', 'threats/config')
      const data = cloud.ok && cloud.data && typeof cloud.data === 'object'
        ? (cloud.data as Record<string, unknown>)
        : {}
      const current = Array.isArray(data.whitelist_ips) ? data.whitelist_ips.map(String) : []
      const next = Array.from(new Set([...current, ip]))
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const removeWhitelist = async (ip: string) => {
    setBusy(true)
    try {
      const cloud = await motorBridge.cloud('GET', 'threats/config')
      const data = cloud.ok && cloud.data && typeof cloud.data === 'object'
        ? (cloud.data as Record<string, unknown>)
        : {}
      const current = Array.isArray(data.whitelist_ips) ? data.whitelist_ips.map(String) : []
      const next = current.filter((x) => x !== ip)
      const result = await motorBridge.cloud('POST', 'threats/config', { whitelist_ips: next })
      onToast(result.ok ? t('toast_wl_ok') : String(result.error || 'Whitelist'), result.ok ? 'ok' : 'err')
      await loadExtras()
    } finally {
      setBusy(false)
    }
  }

  const hostCpu = pick(resources, 'host_cpu_percent', 'cpu_percent', 'cpu')
  const hostRam = pick(resources, 'host_memory_percent', 'ram_percent', 'memory_percent')
  const procCpu = pick(resources, 'process_cpu_percent')
  const procRam = pick(resources, 'process_rss_mb')
  const netDown = formatBps(resources.net_recv_bps)
  const netUp = formatBps(resources.net_sent_bps)

  const switchLoading = pending || busy
  const onOff = (on: boolean) =>
    triLabel(on, {
      yes: t('label_on'),
      no: t('label_off'),
      loading: t('label_loading'),
      pending,
    })

  const renderIpCol = (
    title: string,
    rows: IpRow[],
    total: number,
    emptyKey: string,
    kind: 'watching' | 'blocked' | 'whitelist',
  ) => (
    <article className="panel ip-col">
      <div className="ip-col-head">
        <div>
          <p className="eyebrow">
            {title}
            {extrasLoading && extrasHydrated && <span className="inline-spinner" aria-label={t('label_loading')} />}
          </p>
          <h3>{total}</h3>
        </div>
        <button
          type="button"
          className="btn ghost sm tip"
          data-tooltip={t('status_ip_all')}
          aria-label={t('status_ip_all')}
          onClick={() => onNavigate('iplist')}
        >
          {t('status_ip_all')}
        </button>
      </div>
      <div className="ip-col-list">
        {!extrasHydrated && <p className="muted empty-ip">{t('status_section_loading')}</p>}
        {extrasHydrated && rows.length === 0 && <p className="muted empty-ip">{t(emptyKey)}</p>}
        {extrasHydrated && rows.slice(0, IP_PREVIEW).map((row) => (
          <div key={`${kind}-${row.ip}`} className="ip-row">
            <div className="ip-row-main">
              <strong className="mono">{row.ip}</strong>
              {kind === 'watching' && (
                <span className="ip-meta">
                  {t('status_ip_watch_meta', {
                    attempts: row.attempts ?? 0,
                    score: row.score ?? 0,
                  })}
                </span>
              )}
              <p className="ip-reason">{row.reason || '—'}</p>
            </div>
            <div className="ip-row-actions">
              {kind === 'watching' && (
                <>
                  <IconBtn
                    icon={icons.block}
                    title={t('btn_block')}
                    danger
                    disabled={busy}
                    onClick={() => void mutateIp('BLOCK_IP', row.ip)}
                  />
                  <IconBtn
                    icon={icons.whitelist}
                    title={t('btn_whitelist_add')}
                    disabled={busy}
                    onClick={() => void addWhitelist(row.ip)}
                  />
                </>
              )}
              {kind === 'blocked' && (
                <>
                  <IconBtn
                    icon={icons.unblock}
                    title={t('btn_unblock')}
                    disabled={busy}
                    onClick={() => void mutateIp('UNBLOCK_IP', row.ip)}
                  />
                  <IconBtn
                    icon={icons.whitelist}
                    title={t('btn_whitelist_add')}
                    disabled={busy}
                    onClick={() => void addWhitelist(row.ip)}
                  />
                </>
              )}
              {kind === 'whitelist' && (
                <IconBtn
                  icon={icons.removeWhitelist}
                  title={t('iplist_exclude')}
                  disabled={busy}
                  onClick={() => void removeWhitelist(row.ip)}
                />
              )}
            </div>
          </div>
        ))}
        {extrasHydrated && total > IP_PREVIEW && (
          <button type="button" className="btn ghost sm" onClick={() => onNavigate('iplist')}>
            {t('status_ip_more', { count: total - IP_PREVIEW })}
          </button>
        )}
      </div>
    </article>
  )

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('status_eyebrow')}</p>
          <h2>{online ? t('status_title_online') : t('status_title_offline')}</h2>
          <p className="muted">{t('status_blurb')}</p>
        </div>
        <button type="button" className="btn" onClick={onRefresh}>{t('btn_refresh')}</button>
      </div>

      <div className="chip-row">
        <button type="button" className={`chip ${online ? 'on' : ''}${pending ? ' loading' : ''}`} onClick={() => setDetail('motor')}>
          {t('status_card_motor')}{' '}
          {pending ? t('label_loading') : online ? t('label_ok') : t('status_motor_down')}
        </button>
        <button
          type="button"
          className={`chip ${!pending && status?.ransomware_running ? 'on' : ''}${pending ? ' loading' : ''}`}
          onClick={() => setDetail('ransomware')}
        >
          {t('layers_rs')} {onOff(Boolean(status?.ransomware_running))}
        </button>
        <button
          type="button"
          className={`chip ${!pending && ng.running ? 'on' : ''}${pending ? ' loading' : ''}`}
          onClick={() => setDetail('netguard')}
        >
          NetGuard {onOff(Boolean(ng.running))}
        </button>
        <button
          type="button"
          className={`chip ${!pending && running.length ? 'on' : ''}${pending ? ' loading' : ''}`}
          onClick={() => setDetail('honeypot')}
        >
          {pending ? `${t('status_card_honeypot')} ${t('label_loading')}` : t('status_chip_honeypot', { count: running.length })}
        </button>
        <button
          type="button"
          className={`chip ${!pending && rs.active ? 'warn' : ''}${pending ? ' loading' : ''}`}
          onClick={() => setDetail('ransomware')}
        >
          {pending
            ? t('label_loading')
            : t('status_quarantine', { count: pick(rs, 'entries') })}
        </button>
      </div>

      <div className="cards">
        <article className={`clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('motor')}>
          <p>{t('status_card_motor')}</p>
          <strong>{pending ? t('label_loading') : online ? t('label_active') : t('status_motor_down')}</strong>
          <small>IPC 127.0.0.1:58632 · {pending ? '…' : pick(status, 'version')}</small>
        </article>
        <article className={`clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('mode')}>
          <p>{t('status_card_mode')}</p>
          <strong>{pending ? t('label_loading') : pick(status, 'protection_mode')}</strong>
          <small>
            {pending ? t('status_section_loading') : t('status_policy', { policy: pick(defense, 'defense_policy') })}
          </small>
        </article>
        <article className={`clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('honeypot')}>
          <p>{t('status_card_honeypot')}</p>
          <strong>{pending ? '…' : running.length}</strong>
          <small>
            {pending
              ? t('status_section_loading')
              : running.length
                ? running.join(', ')
                : t('status_no_services')}
          </small>
        </article>
        <article className={`clickable${pending ? ' loading' : ''}`} onClick={() => setDetail('resources')}>
          <p>{t('status_card_resources')}</p>
          <strong>{pending ? t('label_loading') : `${hostCpu}%`}</strong>
          <small>
            {pending ? (
              t('status_section_loading')
            ) : (
              <>
                {t('status_ram', { ram: hostRam, updated: updatedAt || '—' })}
                {' · '}
                {t('status_proc_res', { cpu: procCpu, ram: procRam })}
                {' · '}
                ↓{netDown} ↑{netUp}
              </>
            )}
          </small>
        </article>
      </div>

      <div className="ip-cols" style={{ marginTop: 18 }}>
        {renderIpCol(t('status_ip_watching'), watching, ipTotals.watching, 'status_ip_empty_watch', 'watching')}
        {renderIpCol(t('status_ip_blocked'), blocked, ipTotals.blocked, 'status_ip_empty_blocked', 'blocked')}
        {renderIpCol(t('status_ip_whitelist'), whitelist, ipTotals.whitelist, 'status_ip_empty_wl', 'whitelist')}
      </div>

      <div className="split" style={{ marginTop: 18 }}>
        <article className="panel clickable" onClick={() => setDetail('netguard')}>
          <div className="panel-head-row">
            <p className="eyebrow">{t('status_ng_eyebrow')}</p>
            <IconBtn
              icon={icons.info}
              title={t('help_more')}
              onClick={(e) => {
                e.stopPropagation()
                setDetail('netguard')
              }}
            />
          </div>
          <h3>
            {pending
              ? t('label_loading')
              : ng.maintenance
                ? t('status_ng_maint')
                : ng.drift
                  ? t('status_ng_drift')
                  : t('status_ng_stable')}
          </h3>
          <p className="muted">
            {pending
              ? t('status_section_loading')
              : t('status_ng_baseline', {
                  version: pick(ng, 'baseline_version'),
                  inet: boolLabel(ng.internet_ok, t('label_ok'), t('layers_none')),
                })}
          </p>
          <p className="feature-card-help">{t('status_ng_card_help')}</p>
          <div className="btn-row status-panel-actions" onClick={(e) => e.stopPropagation()}>
            <label className="layer-switch-field">
              <span>{onOff(Boolean(ng.enabled ?? ng.running))}</span>
              <Switch
                checked={Boolean(ng.enabled ?? ng.running)}
                loading={switchLoading}
                label={t('layers_ng')}
                onChange={(next) => void toggleLayer('network_guard', next)}
              />
            </label>
            <label className="layer-switch-field">
              <span>{t('status_ng_maint_mode')}</span>
              <Switch
                checked={Boolean(ng.maintenance)}
                loading={switchLoading}
                label={t('status_ng_maint_mode')}
                onChange={(next) => void ngMaint(next)}
              />
            </label>
            <button type="button" className="btn" disabled={switchLoading} onClick={() => void ngAccept()}>
              {t('status_ng_accept')}
            </button>
          </div>
        </article>
        <article className="panel clickable" onClick={() => setDetail('ransomware')}>
          <div className="panel-head-row">
            <p className="eyebrow">{t('status_rs_eyebrow')}</p>
            <IconBtn
              icon={icons.info}
              title={t('help_more')}
              onClick={(e) => {
                e.stopPropagation()
                setDetail('ransomware')
              }}
            />
          </div>
          <h3>{pending ? t('label_loading') : rs.active ? t('status_rs_active') : t('status_rs_watch')}</h3>
          <p className="muted">
            {pending
              ? t('status_section_loading')
              : t('status_rs_meta', { canary: pick(rs, 'canary_files'), alerts: pick(rs, 'alerts_total') })}
          </p>
          <p className="feature-card-help">{t('status_rs_card_help')}</p>
          <div className="btn-row status-panel-actions" onClick={(e) => e.stopPropagation()}>
            <label className="layer-switch-field">
              <span>{onOff(Boolean(status?.ransomware_running))}</span>
              <Switch
                checked={Boolean(status?.ransomware_running)}
                loading={switchLoading}
                label={t('layers_rs')}
                onChange={(next) => void toggleLayer('ransomware', next)}
              />
            </label>
            <button
              type="button"
              className="btn danger"
              disabled={switchLoading || (!rs.active && Number(rs.entries || 0) === 0)}
              onClick={() => void unlockRs()}
            >
              {t('status_rs_unlock')}
            </button>
          </div>
        </article>
      </div>

      <div className="split" style={{ marginTop: 18 }}>
        <article className="panel" style={{ gridColumn: '1 / -1' }}>
          <p className="eyebrow">{t('status_harden_eyebrow')}</p>
          <h3>{t('status_harden_title')}</h3>
          <p className="feature-card-help" style={{ marginBottom: 10 }}>
            {t('status_harden_help')}
          </p>
          <p className="muted" style={{ marginBottom: 10 }}>
            {t('status_rdp_moved_hint')}
          </p>
          <div className="check-list">
            {checks.length === 0 && <p className="muted">{t('status_harden_loading')}</p>}
            {checks.map((c) => (
              <div key={String(c.id || c.label)} className="check-row">
                <div>
                  <strong className={c.ok === false ? 'bad' : c.ok ? 'good' : ''}>{c.label}</strong>
                  <p className="muted">{c.detail}</p>
                </div>
                {c.fixable && c.id && (
                  <button type="button" className="btn sm" disabled={busy} onClick={() => void fixHarden(String(c.id))}>
                    {t('btn_fix')}
                  </button>
                )}
              </div>
            ))}
          </div>
        </article>
      </div>

      {detail === 'motor' && (
        <DetailModal
          title={t('status_card_motor')}
          eyebrow={t('status_eyebrow')}
          blurb={online ? t('status_detail_motor_ok') : t('status_detail_motor_down')}
          rows={[
            { label: t('status_card_motor'), value: online ? t('label_active') : t('status_motor_down'), tone: online ? 'ok' : 'bad' },
            { label: t('about_version'), value: pick(status, 'version') },
            { label: 'IPC', value: '127.0.0.1:58632' },
          ]}
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'mode' && (
        <DetailModal
          title={t('status_card_mode')}
          eyebrow={t('status_eyebrow')}
          blurb={t('status_detail_mode_blurb')}
          rows={[
            { label: t('status_card_mode'), value: pick(status, 'protection_mode') },
            { label: t('layers_title'), value: pick(defense, 'defense_policy') },
            { label: t('layers_version', { version: pick(defense, 'defense_policy_version') }), value: pick(defense, 'defense_policy_version') },
          ]}
          actions={
            <button type="button" className="btn sm ghost" onClick={() => { setDetail(null); onNavigate('layers') }}>
              {t('nav_layers')}
            </button>
          }
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'honeypot' && (
        <DetailModal
          title={t('status_card_honeypot')}
          eyebrow={t('services_eyebrow')}
          blurb={running.length ? running.join(', ') : t('status_no_services')}
          rows={[
            { label: t('status_card_honeypot'), value: String(running.length), tone: running.length ? 'ok' : 'plain' },
          ]}
          actions={
            <button type="button" className="btn sm" onClick={() => { setDetail(null); onNavigate('services') }}>
              {t('nav_services')}
            </button>
          }
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'resources' && (
        <DetailModal
          title={t('status_card_resources')}
          eyebrow={t('status_eyebrow')}
          blurb={t('status_detail_resources_blurb')}
          rows={[
            { label: 'CPU', value: `${hostCpu}%` },
            { label: 'RAM', value: `${hostRam}%` },
            { label: t('status_proc_res', { cpu: procCpu, ram: procRam }), value: `${procCpu}% / ${procRam} MB` },
            { label: 'Network', value: `↓${netDown} ↑${netUp}` },
            { label: t('btn_refresh'), value: updatedAt || '—' },
          ]}
          actions={
            <button type="button" className="btn sm ghost" onClick={() => { setDetail(null); onNavigate('threat') }}>
              {t('nav_threat')}
            </button>
          }
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'ransomware' && (
        <DetailModal
          title={t('layers_rs')}
          eyebrow={t('status_rs_eyebrow')}
          blurb={rs.active ? t('status_rs_active') : t('status_rs_watch')}
          guide={<FeatureGuide prefix="help_rs" />}
          rows={[
            {
              label: t('layers_rs'),
              value: onOff(Boolean(status?.ransomware_running)),
              tone: pending ? 'plain' : status?.ransomware_running ? 'ok' : 'bad',
              toggle: {
                checked: Boolean(status?.ransomware_running),
                loading: switchLoading,
                label: t('layers_rs'),
                onChange: (next) => void toggleLayer('ransomware', next),
              },
            },
            { label: t('layers_detail_canary_files'), value: pending ? t('label_loading') : pick(rs, 'canary_files') },
            { label: t('layers_detail_total_alerts'), value: pending ? t('label_loading') : pick(rs, 'alerts_total') },
            {
              label: t('status_quarantine', { count: pick(rs, 'entries') }),
              value: pending ? t('label_loading') : rs.active ? t('status_rs_active') : t('label_ok'),
              tone: pending ? 'plain' : rs.active ? 'bad' : 'ok',
            },
          ]}
          actions={
            <>
              <button
                type="button"
                className="btn sm danger"
                disabled={switchLoading || (!rs.active && Number(rs.entries || 0) === 0)}
                onClick={() => void unlockRs()}
              >
                {t('status_rs_unlock')}
              </button>
              <button type="button" className="btn sm ghost" onClick={() => { setDetail(null); onNavigate('layers') }}>
                {t('nav_layers')}
              </button>
            </>
          }
          onClose={() => setDetail(null)}
        />
      )}
      {detail === 'netguard' && (
        <DetailModal
          title={t('layers_ng')}
          eyebrow={t('status_ng_eyebrow')}
          blurb={t('layers_ng_detail_blurb')}
          guide={<FeatureGuide prefix="help_ng" />}
          rows={[
            {
              label: t('layers_ng'),
              value: onOff(Boolean(ng.running || ng.enabled)),
              tone: pending ? 'plain' : ng.running || ng.enabled ? 'ok' : 'bad',
              toggle: {
                checked: Boolean(ng.running || ng.enabled),
                loading: switchLoading,
                label: t('layers_ng'),
                onChange: (next) => void toggleLayer('network_guard', next),
              },
            },
            {
              label: t('status_ng_surface'),
              value: pending
                ? t('label_loading')
                : ng.maintenance
                  ? t('status_ng_maint')
                  : ng.drift
                    ? t('status_ng_drift')
                    : t('status_ng_stable'),
            },
            {
              label: t('status_ng_maint_mode'),
              value: onOff(Boolean(ng.maintenance)),
              toggle: {
                checked: Boolean(ng.maintenance),
                loading: switchLoading,
                label: t('status_ng_maint_mode'),
                onChange: (next) => void ngMaint(next),
              },
            },
            { label: t('layers_detail_baseline'), value: pending ? t('label_loading') : pick(ng, 'baseline_version') },
            {
              label: t('layers_detail_internet'),
              value: pending ? t('label_loading') : ng.internet_ok ? t('label_ok') : t('layers_none'),
              tone: pending ? 'plain' : ng.internet_ok ? 'ok' : 'bad',
            },
          ]}
          actions={
            <button type="button" className="btn sm" disabled={switchLoading} onClick={() => void ngAccept()}>
              {t('status_ng_accept')}
            </button>
          }
          onClose={() => setDetail(null)}
        />
      )}
    </section>
  )
}
