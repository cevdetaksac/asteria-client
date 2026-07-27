import type { ReactNode } from 'react'
import { t } from '../i18n'

type Section = {
  heading: string
  body: string
}

type Props = {
  /** i18n key prefix, e.g. ``help_ng`` → ``help_ng_what_h`` / ``help_ng_what`` … */
  prefix: string
  /** Extra keys beyond the standard what/how/do/tip quartet. */
  extra?: Array<{ headingKey: string; bodyKey: string }>
  children?: ReactNode
}

const STANDARD: Array<{ h: string; b: string }> = [
  { h: 'what_h', b: 'what' },
  { h: 'how_h', b: 'how' },
  { h: 'do_h', b: 'do' },
  { h: 'tip_h', b: 'tip' },
]

/** Structured, i18n-driven feature explainer for detail modals and cards. */
export function FeatureGuide({ prefix, extra, children }: Props) {
  const sections: Section[] = []
  for (const part of STANDARD) {
    const heading = t(`${prefix}_${part.h}`)
    const body = t(`${prefix}_${part.b}`)
    if (!body || body === `${prefix}_${part.b}`) continue
    sections.push({
      heading: heading === `${prefix}_${part.h}` ? '' : heading,
      body,
    })
  }
  for (const item of extra || []) {
    const body = t(item.bodyKey)
    if (!body || body === item.bodyKey) continue
    const heading = t(item.headingKey)
    sections.push({
      heading: heading === item.headingKey ? '' : heading,
      body,
    })
  }
  if (sections.length === 0 && !children) return null

  return (
    <div className="feature-guide">
      {sections.map((sec) => (
        <section key={`${sec.heading}-${sec.body.slice(0, 24)}`} className="feature-guide-sec">
          {sec.heading ? <h4>{sec.heading}</h4> : null}
          {sec.body.split('\n').map((line) => (
            <p key={line}>{line}</p>
          ))}
        </section>
      ))}
      {children}
    </div>
  )
}
