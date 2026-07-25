import { useEffect, useState } from 'react'
import { motorBridge, type MotorStatus } from '../bridge'
import { t } from '../i18n'
import { asRecord, pick } from '../lib'

type Props = {
  status: MotorStatus | null
  onRefresh: () => void
  onToast: (msg: string, kind?: 'ok' | 'err') => void
}

export function LayersPage({ status, onRefresh, onToast }: Props) {
  const defense = asRecord(status?.defense_policy)
  const ng = asRecord(status?.network_guard)
  const current = pick(defense, 'defense_policy')
  const locked = Boolean(defense.defense_policy_locked)
  const [cfg, setCfg] = useState<Record<string, unknown>>({})

  const policies = [
    { id: 'observe', title: t('layers_policy_observe'), blurb: t('layers_policy_observe_blurb') },
    { id: 'balanced', title: t('layers_policy_balanced'), blurb: t('layers_policy_balanced_blurb') },
    { id: 'paranoid', title: t('layers_policy_paranoid'), blurb: t('layers_policy_paranoid_blurb') },
  ] as const

  useEffect(() => {
    void motorBridge.cloud('GET', 'threats/config').then((result) => {
      if (result.ok && result.data && typeof result.data === 'object') {
        setCfg(result.data as Record<string, unknown>)
      }
    })
  }, [status])

  const setPolicy = async (policy: string) => {
    const result = await motorBridge.cloud('POST', 'threats/config', {
      protection: { defense_policy: policy },
    })
    onToast(result.ok ? t('toast_policy', { policy }) : String(result.error || 'policy'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const lockObserve = async () => {
    const result = await motorBridge.cloud('POST', 'threats/config', {
      protection: { defense_policy: 'observe', defense_policy_locked: true },
    })
    onToast(result.ok ? t('toast_lock_ok') : String(result.error || 'lock'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const toggleLayer = async (key: string, value: boolean) => {
    const patch: Record<string, unknown> = {}
    if (key === 'ransomware') patch.ransomware_protection_enabled = value
    if (key === 'canaries') patch.canary_files_enabled = value
    if (key === 'network_guard') patch.protection = { network_guard: { enabled: value } }
    const result = await motorBridge.cloud('POST', 'threats/config', patch)
    onToast(result.ok ? t('toast_layer_ok') : String(result.error || 'layer'), result.ok ? 'ok' : 'err')
    onRefresh()
  }

  const rsOn = Boolean(status?.ransomware_running)
  const ngOn = Boolean(ng.enabled ?? ng.running)
  const canaries = Number(asRecord(status?.rs_quarantine).canary_files || 0) > 0

  return (
    <section className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">{t('layers_eyebrow')}</p>
          <h2>{t('layers_title')}</h2>
          <p className="muted">{t('layers_blurb')}</p>
        </div>
      </div>

      <div className="policy-grid">
        {policies.map((policy) => {
          const selected = current === policy.id
          return (
            <article key={policy.id} className={`policy-card ${selected ? 'selected' : ''}`}>
              <div>
                <p className="eyebrow">{selected ? t('label_active') : t('label_select')}</p>
                <h3>{policy.title}</h3>
                <p className="muted">{policy.blurb}</p>
              </div>
              <button
                type="button"
                className={`btn ${selected ? 'policy-selected' : ''}`}
                disabled={selected || (locked && policy.id !== 'observe')}
                onClick={() => void setPolicy(policy.id)}
              >
                {selected ? t('layers_policy_selected') : t('btn_apply')}
              </button>
            </article>
          )
        })}
      </div>

      <div className="btn-row" style={{ marginTop: 16 }}>
        <button type="button" className="btn ghost" disabled={locked} onClick={() => void lockObserve()}>
          {t('layers_lock_observe')}
        </button>
        <span className="muted">{t('layers_version', { version: pick(defense, 'defense_policy_version') })}</span>
      </div>

      <div className="cards three layer-toggles" style={{ marginTop: 28 }}>
        <article className="layer-card">
          <p>{t('layers_rs')}</p>
          <strong>{rsOn ? t('label_on') : t('label_off')}</strong>
          <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('ransomware', !rsOn)}>
            {rsOn ? t('layers_close') : t('layers_open')}
          </button>
        </article>
        <article className="layer-card">
          <p>{t('layers_canary')}</p>
          <strong>{canaries ? t('layers_has') : t('layers_none')}</strong>
          <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('canaries', !canaries)}>
            {t('layers_sync')}
          </button>
        </article>
        <article className="layer-card">
          <p>{t('layers_ng')}</p>
          <strong>{ngOn ? t('label_on') : t('label_off')}</strong>
          <button type="button" className="btn sm ghost" onClick={() => void toggleLayer('network_guard', !ngOn)}>
            {ngOn ? t('layers_close') : t('layers_open')}
          </button>
        </article>
      </div>

      {Object.keys(cfg).length > 0 && (
        <p className="muted" style={{ marginTop: 18 }}>
          {t('layers_cfg_loaded', { count: Object.keys(cfg).length })}
        </p>
      )}
    </section>
  )
}
