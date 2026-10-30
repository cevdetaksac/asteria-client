import { t } from './i18n'
import type { PageId } from './lib'

export type { PageId }

/** U1: 4 top-level groups; merged pages become sub-tabs. Old PageIds stay valid (deep links). */
export type GroupId = 'status' | 'threat' | 'protect' | 'settings'

export const GROUPS: Array<{ id: GroupId; pages: PageId[] }> = [
  { id: 'status', pages: ['status'] },
  { id: 'threat', pages: ['threat', 'iplist'] },
  { id: 'protect', pages: ['layers', 'services'] },
  { id: 'settings', pages: ['settings', 'tools'] },
]

export function groupOf(page: PageId): GroupId {
  return (GROUPS.find((g) => g.pages.includes(page)) ?? GROUPS[0]).id
}

export function subTabs(page: PageId): Array<{ id: PageId; label: string }> {
  const group = GROUPS.find((g) => g.pages.includes(page))
  if (!group || group.pages.length < 2) return []
  const label: Record<PageId, string> = {
    status: t('nav_status'),
    threat: t('nav_threat'),
    iplist: t('nav_iplist'),
    layers: t('nav_layers'),
    services: t('nav_services'),
    settings: t('nav_settings'),
    tools: t('nav_advanced'),
  }
  return group.pages.map((id) => ({ id, label: label[id] }))
}

export function navItems(): Array<{ id: GroupId; first: PageId; label: string; blurb: string }> {
  return [
    { id: 'status', first: 'status', label: t('nav_status'), blurb: t('nav_status_blurb') },
    { id: 'threat', first: 'threat', label: t('nav_threat'), blurb: t('nav_threat_group_blurb') },
    { id: 'protect', first: 'layers', label: t('nav_protect'), blurb: t('nav_protect_blurb') },
    { id: 'settings', first: 'settings', label: t('nav_settings'), blurb: t('nav_settings_group_blurb') },
  ]
}
