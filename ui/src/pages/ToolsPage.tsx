import { useCallback, useEffect, useState } from 'react'
import { motorBridge } from '../bridge'
import { DetailModal } from '../components/DetailModal'
import { FeatureGuide } from '../components/FeatureGuide'
import { t } from '../i18n'

type Props = {
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

type OpenTool = { id: string; label: string; target: string }
type Finding = {
  id: string
  severity: string
  ok: boolean
  detail: string
  fix?: string
}
type ToolsTab = 'detect' | 'repair' | 'admin'

type RepairCard = { id: string; destructive?: boolean; group: string }

const REPAIR_CARDS: RepairCard[] = [
  { id: 'share_network_fix', group: 'daily' },
  { id: 'printer_fix', group: 'daily' },
  { id: 'audio_fix', group: 'daily' },
  { id: 'dns_flush', group: 'daily' },
  { id: 'time_sync', group: 'daily' },
  { id: 'auto_fix_findings', group: 'critical' },
  { id: 'fix_taskmgr', group: 'critical' },
  { id: 'restart_taskmgr', group: 'critical' },
  { id: 'restart_explorer', group: 'critical' },
  { id: 'fix_shell', group: 'critical' },
  { id: 'fix_regedit', group: 'critical' },
  { id: 'fix_cmd', group: 'critical' },
  { id: 'policy_restore', group: 'critical' },
  { id: 'restart_critical_services', group: 'services' },
  { id: 'webview2', group: 'runtime' },
  { id: 'icon_cache', group: 'shell' },
  { id: 'clear_temp', group: 'shell' },
  { id: 'sfc_scan', group: 'deep' },
  { id: 'dism_health', group: 'deep' },
  { id: 'full_safe', group: 'deep' },
  { id: 'winsock_reset', destructive: true, group: 'danger' },
  { id: 'firewall_reset', destructive: true, group: 'danger' },
  { id: 'wu_reset', destructive: true, group: 'danger' },
]

const GROUP_ORDER = ['daily', 'critical', 'services', 'runtime', 'shell', 'deep', 'danger'] as const

function severityClass(sev: string, ok: boolean): string {
  if (ok) return 'good'
  if (sev === 'critical') return 'bad'
  if (sev === 'high') return 'bad'
  if (sev === 'medium') return 'warn'
  return 'muted'
}

export function ToolsPage({ onToast }: Props) {
  const [tab, setTab] = useState<ToolsTab>('detect')
  const [tools, setTools] = useState<OpenTool[]>([])
  const [admin, setAdmin] = useState(false)
  const [wv2, setWv2] = useState<{ present?: boolean; detail?: string }>({})
  const [findings, setFindings] = useState<Finding[]>([])
  const [issueCount, setIssueCount] = useState(0)
  const [criticalCount, setCriticalCount] = useState(0)
  const [busy, setBusy] = useState('')
  const [lastResult, setLastResult] = useState('')
  const [pageHelp, setPageHelp] = useState(false)

  const refresh = useCallback(async () => {
    const cat = await motorBridge.tools('catalog')
    if (cat.ok === false) {
      onToast(String(cat.error || 'tools'), 'err')
      return
    }
    const open = Array.isArray(cat.open_tools) ? (cat.open_tools as OpenTool[]) : []
    setTools(open)
    const st = cat.status && typeof cat.status === 'object' ? (cat.status as Record<string, unknown>) : {}
    setAdmin(Boolean(st.admin))
    const w = st.webview2 && typeof st.webview2 === 'object' ? (st.webview2 as Record<string, unknown>) : {}
    setWv2({ present: Boolean(w.present), detail: String(w.detail || '') })
    const diag = cat.diagnose && typeof cat.diagnose === 'object' ? (cat.diagnose as Record<string, unknown>) : {}
    const list = Array.isArray(diag.findings) ? (diag.findings as Finding[]) : []
    setFindings(list)
    setIssueCount(Number(diag.issues || list.filter((f) => !f.ok).length))
    setCriticalCount(Number(diag.critical || 0))
  }, [onToast])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const openTool = async (id: string) => {
    setBusy(`open:${id}`)
    try {
      const r = await motorBridge.tools('open', id)
      onToast(r.ok ? t('tools_open_ok', { name: id }) : String(r.error || 'open'), r.ok ? 'ok' : 'err')
    } finally {
      setBusy('')
    }
  }

  const runRepair = async (id: string, destructive?: boolean) => {
    if (destructive) {
      const ok = window.confirm(t(`tools_confirm_${id}` as 'tools_confirm_firewall_reset'))
      if (!ok) return
    } else if (id === 'full_safe' || id === 'auto_fix_findings') {
      if (!window.confirm(t(`tools_confirm_${id}` as 'tools_confirm_full_safe'))) return
    }
    setBusy(`repair:${id}`)
    setLastResult('')
    try {
      const r = await motorBridge.tools('repair', id, Boolean(destructive))
      const detail = String(r.detail || r.error || (r.ok ? 'ok' : 'failed'))
      setLastResult(`${id}: ${detail}`)
      onToast(
        r.ok ? t('tools_repair_ok', { name: t(`tools_repair_${id}` as 'tools_repair_webview2') }) : String(r.error || detail),
        r.ok ? 'ok' : 'err',
      )
      await refresh()
    } finally {
      setBusy('')
    }
  }

  const runDiagnose = async () => {
    setBusy('diagnose')
    try {
      const r = await motorBridge.tools('diagnose')
      if (r.ok === false) {
        onToast(String(r.error || 'diagnose'), 'err')
        return
      }
      const list = Array.isArray(r.findings) ? (r.findings as Finding[]) : []
      setFindings(list)
      setIssueCount(Number(r.issues || list.filter((f) => !f.ok).length))
      setCriticalCount(Number(r.critical || 0))
      onToast(t('tools_diagnose_done', { n: String(Number(r.issues || 0)) }), 'ok')
    } finally {
      setBusy('')
    }
  }

  const broken = findings.filter((f) => !f.ok)

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('tools_eyebrow')}</p>
          <h2>{t('tools_title')}</h2>
          <p className="muted">{t('tools_blurb')}</p>
        </div>
        <div className="btn-row">
          <button type="button" className="btn ghost sm" onClick={() => setPageHelp(true)}>
            {t('help_more')}
          </button>
          <button type="button" className="btn" disabled={Boolean(busy)} onClick={() => void refresh()}>
            {t('btn_refresh')}
          </button>
        </div>
      </div>

      <div className="cards three" style={{ marginBottom: 18 }}>
        <article>
          <p>{t('tools_card_admin')}</p>
          <strong className={admin ? 'good' : 'bad'}>{admin ? t('label_ok') : t('tools_admin_needed')}</strong>
          <small>{t('tools_card_admin_meta')}</small>
        </article>
        <article>
          <p>{t('tools_card_health')}</p>
          <strong className={issueCount ? 'bad' : 'good'}>
            {issueCount ? t('tools_issues_n', { n: String(issueCount) }) : t('label_ok')}
          </strong>
          <small>
            {criticalCount
              ? t('tools_critical_n', { n: String(criticalCount) })
              : wv2.detail || t('tools_card_health_meta')}
          </small>
        </article>
        <article>
          <p>{t('tools_card_wv2')}</p>
          <strong className={wv2.present ? 'good' : 'bad'}>
            {wv2.present ? t('label_ok') : t('tools_wv2_missing')}
          </strong>
          <small>{wv2.detail || '—'}</small>
        </article>
      </div>

      <nav className="page-tabs" aria-label={t('tools_title')}>
        {(
          [
            ['detect', t('tools_tab_detect'), issueCount],
            ['repair', t('tools_tab_repair'), REPAIR_CARDS.length],
            ['admin', t('tools_tab_admin'), tools.length],
          ] as Array<[ToolsTab, string, number]>
        ).map(([id, label, count]) => (
          <button
            key={id}
            type="button"
            className={`page-tab${tab === id ? ' active' : ''}`}
            onClick={() => setTab(id)}
          >
            {label}
            <span className="tab-count">{count}</span>
          </button>
        ))}
      </nav>

      {tab === 'detect' && (
        <article className="panel panel-spaced">
          <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
            <div>
              <p className="eyebrow">{t('tools_detect_eyebrow')}</p>
              <h3>{t('tools_detect_title')}</h3>
              <p className="muted">{t('tools_detect_blurb')}</p>
            </div>
            <div className="btn-row">
              <button type="button" className="btn" disabled={Boolean(busy)} onClick={() => void runDiagnose()}>
                {busy === 'diagnose' ? t('label_loading') : t('tools_detect_run')}
              </button>
              <button
                type="button"
                className="btn"
                disabled={Boolean(busy) || !broken.length}
                onClick={() => void runRepair('auto_fix_findings')}
              >
                {t('tools_repair_auto_fix_findings')}
              </button>
            </div>
          </div>
          <div className="tools-findings">
            {(findings.length ? findings : []).map((f) => (
              <div key={f.id} className={`tools-finding${f.ok ? '' : ' issue'}`}>
                <div>
                  <strong className={severityClass(f.severity, f.ok)}>
                    {t(`tools_finding_${f.id}` as 'tools_finding_taskmgr_policy')}
                  </strong>
                  <p className="muted">{f.detail}</p>
                </div>
                {!f.ok && f.fix ? (
                  <button
                    type="button"
                    className="btn sm"
                    disabled={Boolean(busy)}
                    onClick={() => void runRepair(f.fix!)}
                  >
                    {t('btn_fix')}
                  </button>
                ) : (
                  <span className={f.ok ? 'good' : 'muted'}>{f.ok ? t('label_ok') : f.severity}</span>
                )}
              </div>
            ))}
            {!findings.length ? <p className="muted">{t('tools_detect_empty')}</p> : null}
          </div>
          {lastResult ? <p className="muted" style={{ marginTop: 12 }}>{lastResult}</p> : null}
        </article>
      )}

      {tab === 'repair' && (
        <article className="panel panel-spaced">
          <div className="page-head" style={{ marginBottom: 12, paddingBottom: 0, border: 'none' }}>
            <div>
              <p className="eyebrow">{t('tools_repair_eyebrow')}</p>
              <h3>{t('tools_repair_title')}</h3>
              <p className="muted">{t('tools_repair_blurb')}</p>
            </div>
            <button
              type="button"
              className="btn"
              disabled={Boolean(busy)}
              onClick={() => void runRepair('full_safe')}
            >
              {t('tools_repair_full_safe')}
            </button>
          </div>
          {GROUP_ORDER.map((group) => {
            const cards = REPAIR_CARDS.filter((c) => c.group === group)
            if (!cards.length) return null
            return (
              <div key={group} className="tools-repair-group">
                <p className="eyebrow">{t(`tools_group_${group}` as 'tools_group_critical')}</p>
                <div className="tools-repair-grid">
                  {cards.map((card) => (
                    <div key={card.id} className={`tools-repair-card${card.destructive ? ' danger' : ''}`}>
                      <div>
                        <strong>{t(`tools_repair_${card.id}` as 'tools_repair_webview2')}</strong>
                        <p className="muted">{t(`tools_repair_${card.id}_blurb` as 'tools_repair_webview2_blurb')}</p>
                      </div>
                      <button
                        type="button"
                        className={`btn sm${card.destructive ? ' danger' : ''}`}
                        disabled={Boolean(busy)}
                        onClick={() => void runRepair(card.id, card.destructive)}
                      >
                        {busy === `repair:${card.id}` ? t('label_loading') : t('tools_run')}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
          {lastResult ? <p className="muted" style={{ marginTop: 12 }}>{lastResult}</p> : null}
        </article>
      )}

      {tab === 'admin' && (
        <article className="panel">
          <p className="eyebrow">{t('tools_admin_eyebrow')}</p>
          <h3>{t('tools_admin_title')}</h3>
          <p className="muted" style={{ marginBottom: 12 }}>{t('tools_admin_blurb')}</p>
          <div className="tools-open-grid">
            {tools.map((tool) => (
              <button
                key={tool.id}
                type="button"
                className="tools-open-btn"
                disabled={Boolean(busy)}
                onClick={() => void openTool(tool.id)}
                title={tool.target}
              >
                <strong>{t(`tools_open_${tool.id}` as 'tools_open_taskmgr')}</strong>
                <span className="muted mono">{tool.target}</span>
              </button>
            ))}
          </div>
        </article>
      )}

      {pageHelp && (
        <DetailModal
          title={t('tools_title')}
          eyebrow={t('tools_eyebrow')}
          blurb={t('tools_blurb')}
          guide={<FeatureGuide prefix="help_tools" />}
          onClose={() => setPageHelp(false)}
        />
      )}
    </section>
  )
}
