import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core'
import {
  faBan,
  faCheck,
  faLockOpen,
  faUserCheck,
  faUserMinus,
} from '@fortawesome/free-solid-svg-icons'

export const icons = {
  block: faBan,
  unblock: faLockOpen,
  whitelist: faUserCheck,
  removeWhitelist: faUserMinus,
  ok: faCheck,
} as const

type Props = {
  icon: IconDefinition
  title: string
  onClick?: () => void
  disabled?: boolean
  danger?: boolean
  className?: string
}

/** Compact icon action with native title + CSS tooltip on hover. */
export function IconBtn({ icon, title, onClick, disabled, danger, className = '' }: Props) {
  return (
    <button
      type="button"
      className={`icon-btn ${danger ? 'danger' : ''} ${className}`.trim()}
      title={title}
      aria-label={title}
      data-tooltip={title}
      disabled={disabled}
      onClick={onClick}
    >
      <FontAwesomeIcon icon={icon} />
    </button>
  )
}
