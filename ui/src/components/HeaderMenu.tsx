import { useEffect, useId, useRef, useState } from 'react'
import { t } from '../i18n'

export type MenuAction =
  | 'open_dashboard'
  | 'refresh'
  | 'copy_token'
  | 'link_account'
  | 'unlink_account'
  | 'open_servers'
  | 'open_logs'
  | 'check_updates'
  | 'open_website'
  | 'open_github'
  | 'about'

type Props = {
  version?: string
  accountLinked: boolean
  onAction: (action: MenuAction) => void
}

type Item =
  | { type: 'item'; id: MenuAction; label: string }
  | { type: 'sep'; id: string }

export function HeaderMenu({ version, accountLinked, onAction }: Props) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const menuId = useId()

  useEffect(() => {
    if (!open) return
    const onDoc = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const items: Item[] = [
    { type: 'item', id: 'open_dashboard', label: t('btn_dashboard') },
    { type: 'item', id: 'refresh', label: t('btn_refresh') },
    { type: 'sep', id: 'sep-actions' },
    { type: 'item', id: 'copy_token', label: t('btn_copy_token') },
    {
      type: 'item',
      id: accountLinked ? 'unlink_account' : 'link_account',
      label: accountLinked ? t('btn_unlink_account') : t('btn_link_account'),
    },
    { type: 'item', id: 'open_servers', label: t('btn_servers_web') },
    { type: 'sep', id: 'sep-help' },
    { type: 'item', id: 'open_logs', label: t('menu_logs') },
    { type: 'item', id: 'check_updates', label: t('menu_check_updates') },
    { type: 'item', id: 'open_website', label: t('menu_website') },
    { type: 'item', id: 'open_github', label: t('menu_github') },
    { type: 'item', id: 'about', label: t('menu_about') },
  ]

  return (
    <div className={`header-menu ${open ? 'open' : ''}`} ref={rootRef}>
      <button
        type="button"
        className="btn ghost sm header-menu-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((prev) => !prev)}
      >
        <span className="header-menu-label">{t('menu_help')}</span>
        <span className="header-menu-caret" aria-hidden="true" />
      </button>
      {open && (
        <div className="header-menu-panel" role="menu" id={menuId}>
          {version && (
            <div className="header-menu-version" role="presentation">
              v{version}
            </div>
          )}
          {items.map((item) =>
            item.type === 'sep' ? (
              <div key={item.id} className="header-menu-sep" role="separator" />
            ) : (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                className="header-menu-item"
                onClick={() => {
                  setOpen(false)
                  onAction(item.id)
                }}
              >
                {item.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  )
}
