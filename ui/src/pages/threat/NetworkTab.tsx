import { t } from '../../i18n'
import { asRecord } from '../../lib'
import { DataTable } from '../../components/DataTable'
import { DashLink } from '../../components/DashLink'
import { RowActionMenu } from '../../components/RowActionMenu'

// Props are passed straight from ThreatPage state (see ThreatPage for types).
export function NetworkTab({ shares, thirdParty, extrasReady, shareCustom, svcUnknown, busy, removeShare, stopService }: Record<string, any>) {
  return (
    <div className="split split-stack u-mb18">
      <article className="panel">
        <p className="eyebrow">{t('threat_shares_eyebrow')}</p>
        <DashLink path="dash_servers" label={t('dash_link_inventory')} />
        <h3>{t('threat_shares_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
        <p className="muted">
          {shareCustom > 0
            ? t('threat_shares_custom', { count: shareCustom })
            : t('threat_shares_default_only')}
        </p>
        <DataTable
          rows={shares}
          rowKey={(row) => `share-${String(asRecord(row).name || '')}`}
          empty={extrasReady ? t('threat_shares_empty') : t('label_loading')}
          defaultPageSize={10}
          columns={[
            {
              id: 'name',
              header: t('threat_shares_col_name'),
              searchText: (row) => String(asRecord(row).name || ''),
              cell: (row) => {
                const r = asRecord(row)
                const name = String(r.name || '')
                const isDefault = Boolean(r.is_default)
                const usersN = Number(r.current_users || 0) || 0
                return (
                  <>
                    <strong className={`mono ${isDefault ? 'muted' : ''}`}>{name}</strong>
                    {usersN > 0 && (
                      <small className="muted"> · {t('threat_shares_users', { count: usersN })}</small>
                    )}
                  </>
                )
              },
            },
            {
              id: 'path',
              header: t('threat_shares_col_path'),
              className: 'muted',
              searchText: (row) => String(asRecord(row).path || asRecord(row).description || ''),
              cell: (row) => String(asRecord(row).path || asRecord(row).description || '—'),
            },
            {
              id: 'actions',
              header: t('threat_col_actions'),
              headerClassName: 'actions-head',
              className: 'actions-cell',
              cell: (row) => {
                const r = asRecord(row)
                const name = String(r.name || '')
                if (r.is_default) return <span className="muted u-fs11">—</span>
                return (
                  <RowActionMenu
                    primary={[{ id: 'rm', label: t('threat_shares_remove'), danger: true, disabled: busy, onClick: () => void removeShare(name) }]}
                  />
                )
              },
            },
          ]}
        />
      </article>

      <article className="panel">
        <p className="eyebrow">{t('threat_svc_eyebrow')}</p>
        <h3>{t('threat_svc_title')}{!extrasReady && <span className="inline-spinner" />}</h3>
        <p className="muted">
          {svcUnknown > 0
            ? t('threat_svc_unknown', { count: svcUnknown })
            : t('threat_svc_clean')}
        </p>
        <DataTable
          rows={thirdParty}
          rowKey={(row) => `svc-${String(asRecord(row).name || '')}`}
          empty={extrasReady ? t('threat_svc_empty') : t('label_loading')}
          defaultPageSize={10}
          columns={[
            {
              id: 'name',
              header: t('threat_svc_col_name'),
              searchText: (row) => `${asRecord(row).display || ''} ${asRecord(row).name || ''}`,
              cell: (row) => {
                const r = asRecord(row)
                const name = String(r.name || '')
                const display = String(r.display || name)
                return (
                  <>
                    <strong>{display}</strong>
                    <div className="mono muted u-fs11">{name}</div>
                    {Boolean(r.known) && <span className="pill muted">{t('threat_svc_known')}</span>}
                  </>
                )
              },
            },
            {
              id: 'path',
              header: t('threat_svc_col_path'),
              className: 'muted',
              searchText: (row) => String(asRecord(row).path || ''),
              cell: (row) => (
                <span className="u-fs11 u-break">{String(asRecord(row).path || '—')}</span>
              ),
            },
            {
              id: 'actions',
              header: t('threat_col_actions'),
              headerClassName: 'actions-head',
              className: 'actions-cell',
              cell: (row) => {
                const r = asRecord(row)
                const name = String(r.name || '')
                const display = String(r.display || name)
                if (r.known) return <span className="muted u-fs11">{t('threat_svc_known')}</span>
                return (
                  <RowActionMenu
                    primary={[{ id: 'stop', label: t('threat_svc_stop'), danger: true, disabled: busy, onClick: () => void stopService(name, display) }]}
                  />
                )
              },
            },
          ]}
        />
      </article>
    </div>
  )
}
