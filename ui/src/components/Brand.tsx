import logoMark from '../assets/brand/favicon_light.png'
import logoWide from '../assets/brand/logo_light.png'
import logoSquare from '../assets/brand/logo_square_light.png'

type MarkProps = {
  size?: number
  className?: string
}

/** Tower + sparkles mark — *_light ink for dark UI (logo_set README). */
export function BrandMark({ size = 42, className = '' }: MarkProps) {
  return (
    <img
      className={`brand-mark-img ${className}`.trim()}
      src={logoMark}
      alt=""
      width={size}
      height={size}
      draggable={false}
    />
  )
}

type WordProps = {
  tagline?: boolean
  compact?: boolean
}

/** ASTERIA wordmark in Bruno Ace + optional RUN line. */
export function BrandWordmark({ tagline = true, compact = false }: WordProps) {
  return (
    <div className={`brand-wordmark ${compact ? 'compact' : ''}`.trim()}>
      <span className="brand-asteria" aria-label="Asteria">
        ASTERIA
      </span>
      {tagline && (
        <span className="brand-run" aria-hidden="true">
          <i />
          RUN
          <i />
        </span>
      )}
    </div>
  )
}

/** Lock / hero lockup: square stacked art, wide horizontal, or mark+wordmark. */
export function BrandLockup({ mode = 'split' }: { mode?: 'split' | 'wide' | 'square' }) {
  if (mode === 'wide') {
    return (
      <img
        className="brand-logo-wide"
        src={logoWide}
        alt="Asteria Run"
        draggable={false}
      />
    )
  }
  if (mode === 'square') {
    return (
      <img
        className="brand-logo-square"
        src={logoSquare}
        alt="Asteria Run"
        draggable={false}
      />
    )
  }
  return (
    <div className="brand-lockup">
      <BrandMark size={48} />
      <BrandWordmark />
    </div>
  )
}
