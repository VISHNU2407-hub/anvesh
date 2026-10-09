import { riskStyle } from './riskStyles'

const LABELS = {
  low: 'Low Risk',
  medium: 'Medium Risk',
  high: 'High Risk',
  unknown: 'Unknown',
}

/**
 * Pill-shaped risk category badge. Accepts a risk level
 * ("Low" | "Medium" | "High" | "Unknown").
 */
export default function RiskBadge({ level = 'Unknown', size = 'md' }) {
  const style = riskStyle(level)
  const text = LABELS[style.key]
  const sizing =
    size === 'sm'
      ? 'px-2.5 py-0.5 text-xs gap-1.5'
      : 'px-3 py-1 text-sm gap-2'

  return (
    <span
      className={`inline-flex items-center rounded-full border font-semibold transition-colors duration-300 ${style.badge} ${sizing}`}
    >
      <span
        aria-hidden="true"
        className={`size-2 rounded-full ${style.key === 'low' ? 'bg-risk-low' : style.key === 'medium' ? 'bg-risk-medium' : style.key === 'high' ? 'bg-risk-high' : 'bg-risk-unknown'}`}
      />
      {text}
    </span>
  )
}
