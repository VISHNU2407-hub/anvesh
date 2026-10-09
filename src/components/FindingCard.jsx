import { CircleAlert, CircleHelp, Info, TriangleAlert } from 'lucide-react'

const SEVERITY = {
  high: {
    label: 'High',
    wrap: 'border-red-200 bg-risk-high-soft',
    chip: 'bg-red-600 text-white',
    icon: CircleAlert,
    iconClass: 'text-red-600',
  },
  medium: {
    label: 'Medium',
    wrap: 'border-amber-200 bg-risk-medium-soft',
    chip: 'bg-amber-500 text-white',
    icon: TriangleAlert,
    iconClass: 'text-amber-600',
  },
  low: {
    label: 'Low',
    wrap: 'border-blue-200 bg-brand-soft',
    chip: 'bg-brand text-white',
    icon: Info,
    iconClass: 'text-brand',
  },
  informational: {
    label: 'Info',
    wrap: 'border-slate-200 bg-slate-50',
    chip: 'bg-slate-500 text-white',
    icon: CircleHelp,
    iconClass: 'text-slate-500',
  },
}

function severityStyle(severity) {
  return SEVERITY[String(severity ?? '').toLowerCase()] ?? SEVERITY.informational
}

/**
 * A single security finding: title, severity badge, plain-English
 * explanation, and an optional evidence classification from the response.
 */
export default function FindingCard({ finding }) {
  if (!finding) return null
  const style = severityStyle(finding.severity)
  const Icon = style.icon

  return (
    <li
      className={`flex gap-3 rounded-xl border p-4 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md ${style.wrap}`}
    >
      <span className="mt-0.5 shrink-0" aria-hidden="true">
        <Icon size={18} className={style.iconClass} />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <h4 className="text-sm font-semibold text-ink">{finding.name}</h4>
          <span
            className={`rounded-full px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${style.chip}`}
          >
            {style.label}
          </span>
        </div>
        {finding.explanation ? (
          <p className="mt-1 text-sm leading-relaxed text-slate-600">
            {finding.explanation}
          </p>
        ) : null}
        {finding.evidence ? (
          <p className="mt-2 text-xs font-medium uppercase tracking-wide text-muted">
            Evidence: {String(finding.evidence).replace(/-/g, ' ')}
          </p>
        ) : null}
      </div>
    </li>
  )
}
