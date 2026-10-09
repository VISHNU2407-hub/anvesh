import {
  BadgeCheck,
  Flag,
  Globe,
  KeyRound,
  ShieldQuestion,
  Smartphone,
} from 'lucide-react'

function pickIcon(text) {
  const t = text.toLowerCase()
  if (t.includes('password') || t.includes('credential') || t.includes('otp')) {
    return KeyRound
  }
  if (t.includes('report')) return Flag
  if (t.includes('official') || t.includes('directly') || t.includes('address')) {
    return Globe
  }
  if (t.includes('app') || t.includes('device') || t.includes('browser')) {
    return Smartphone
  }
  if (t.includes('cautious') || t.includes('unknown') || t.includes('demo')) {
    return ShieldQuestion
  }
  return BadgeCheck
}

/**
 * Reusable safety-recommendations card. Renders practical, plain-English
 * advice returned by the assessment (or a cautious default when none was
 * supplied).
 */
export default function Recommendations({ items = [], accent = 'brand' }) {
  const list = items.filter(Boolean)
  const accentText =
    accent === 'high'
      ? 'text-risk-high'
      : accent === 'medium'
        ? 'text-risk-medium'
        : accent === 'low'
          ? 'text-risk-low'
          : 'text-brand'

  if (list.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-line bg-canvas p-5 text-sm text-muted">
        No specific advice was returned for this scan. Treat unknown results
        cautiously and verify the destination before sharing any information.
      </div>
    )
  }

  return (
    <ul className="space-y-3">
      {list.map((item, i) => {
        const Icon = pickIcon(item)
        return (
          <li key={i} className="flex items-start gap-3">
            <span
              className={`mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full bg-canvas ring-1 ring-line ${accentText}`}
              aria-hidden="true"
            >
              <Icon size={15} />
            </span>
            <span className="text-sm leading-relaxed text-slate-700">{item}</span>
          </li>
        )
      })}
    </ul>
  )
}
