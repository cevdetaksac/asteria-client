import { t } from './i18n'
import type { PageId } from './lib'

export type { PageId }

export function navItems(): Array<{ id: PageId; label: string; blurb: string }> {
  return [
    { id: 'status', label: t('nav_status'), blurb: t('nav_status_blurb') },
    { id: 'threat', label: t('nav_threat'), blurb: t('nav_threat_blurb') },
    { id: 'iplist', label: t('nav_iplist'), blurb: t('nav_iplist_blurb') },
    { id: 'services', label: t('nav_services'), blurb: t('nav_services_blurb') },
    { id: 'layers', label: t('nav_layers'), blurb: t('nav_layers_blurb') },
    { id: 'tools', label: t('nav_tools'), blurb: t('nav_tools_blurb') },
    { id: 'settings', label: t('nav_settings'), blurb: t('nav_settings_blurb') },
  ]
}
