import { t } from '../../i18n'
import type { LocalUser } from './model'
import { DataTable } from '../../components/DataTable'

// Props are passed straight from ThreatPage state (see ThreatPage for types).
export function AccountsTab({ users, usersReady, userCounts, currentUser, userColumns }: { users: LocalUser[] } & Record<string, any>) {
  return (
    <div className="accordion open">
      <div className="accordion-trigger" aria-expanded={true}>
        <div>
          <p className="eyebrow">{t('threat_ir_eyebrow')}</p>
          <h3>{t('threat_users_title')}{!usersReady && <span className="inline-spinner" />}</h3>
          <p className="muted">
            {t('threat_card_accounts_meta', {
              active: userCounts.active,
              disabled: userCounts.disabled,
            })}
            {currentUser ? ` · ${t('threat_you_are', { user: currentUser })}` : ''}
          </p>
        </div>
      </div>
      <div className="accordion-body">
        <p className="muted u-mb12">{t('threat_users_blurb')}</p>
        <DataTable
          rows={users}
          rowKey={(u) => u.username}
          empty={usersReady ? t('threat_users_empty') : t('label_loading')}
          tableClassName="accounts-table"
          defaultPageSize={25}
          columns={userColumns}
        />
      </div>
    </div>
  )
}
