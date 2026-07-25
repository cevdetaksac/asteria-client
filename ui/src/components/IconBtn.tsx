import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core'
import {
  faBan,
  faCheck,
  faCircleInfo,
  faLockOpen,
  faRotateRight,
  faUserCheck,
  faUserMinus,
  faKey,
  faPowerOff,
  faUserSlash,
  faArrowUpRightFromSquare,
} from '@fortawesome/free-solid-svg-icons'

export const icons = {
  block: faBan,
  unblock: faLockOpen,
  whitelist: faUserCheck,
  removeWhitelist: faUserMinus,
  ok: faCheck,
  refresh: faRotateRight,
  password: faKey,
  logoff: faPowerOff,
  disable: faUserSlash,
  open: faArrowUpRightFromSquare,
  info: faCircleInfo,
} as const

type Props = {
  icon: IconDefinition
  title: string
  onClick?: () => void
  disabled?: boolean
  danger?: boolean
  className?: string
}

/** Compact icon action with CSS tooltip centered above (no native title delay). */
export function IconBtn({ icon, title, onClick, disabled, danger, className = '' }: Props) {
  return (
    <button
      type="button"
      className={`icon-btn ${danger ? 'danger' : ''} ${className}`.trim()}
      aria-label={title}
      data-tooltip={title}
      disabled={disabled}
      onClick={onClick}
    >
      <FontAwesomeIcon icon={icon} fixedWidth />
    </button>
  )
}
