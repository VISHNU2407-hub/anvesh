/** Shared risk-level helpers: colors, labels, and score thresholds. */

export const RISK_STYLES = {
  Low: {
    key: 'low',
    text: 'Low Risk',
    badge: 'bg-risk-low-soft text-risk-low border-green-200',
    solid: 'text-risk-low',
    ring: 'ring-green-200',
    hex: '#16a34a',
    soft: '#ecfdf5',
    border: 'border-green-200',
  },
  Medium: {
    key: 'medium',
    text: 'Medium Risk',
    badge: 'bg-risk-medium-soft text-risk-medium border-amber-200',
    solid: 'text-risk-medium',
    ring: 'ring-amber-200',
    hex: '#d97706',
    soft: '#fffbeb',
    border: 'border-amber-200',
  },
  High: {
    key: 'high',
    text: 'High Risk',
    badge: 'bg-risk-high-soft text-risk-high border-red-200',
    solid: 'text-risk-high',
    ring: 'ring-red-200',
    hex: '#dc2626',
    soft: '#fef2f2',
    border: 'border-red-200',
  },
  Unknown: {
    key: 'unknown',
    text: 'Unknown',
    badge: 'bg-risk-unknown-soft text-risk-unknown border-slate-300',
    solid: 'text-risk-unknown',
    ring: 'ring-slate-300',
    hex: '#64748b',
    soft: '#f1f5f9',
    border: 'border-slate-300',
  },
}

export function riskStyle(level) {
  return RISK_STYLES[level] ?? RISK_STYLES.Unknown
}

export function formatTimestamp(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}
