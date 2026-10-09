import {
  CircleAlert,
  RefreshCw,
  ShieldQuestion,
  TriangleAlert,
  WifiOff,
} from 'lucide-react'

const PRESENTATION = {
  empty: {
    title: 'URL required',
    icon: CircleAlert,
    wrap: 'border-slate-300 bg-slate-50',
    iconClass: 'text-slate-500',
  },
  missing_scheme: {
    title: 'Invalid URL',
    icon: CircleAlert,
    wrap: 'border-slate-300 bg-slate-50',
    iconClass: 'text-slate-500',
  },
  unsupported_scheme: {
    title: 'Unsupported link type',
    icon: TriangleAlert,
    wrap: 'border-amber-200 bg-risk-medium-soft',
    iconClass: 'text-risk-medium',
  },
  missing_hostname: {
    title: 'Hostname missing',
    icon: CircleAlert,
    wrap: 'border-slate-300 bg-slate-50',
    iconClass: 'text-slate-500',
  },
  malformed: {
    title: 'Invalid URL',
    icon: CircleAlert,
    wrap: 'border-slate-300 bg-slate-50',
    iconClass: 'text-slate-500',
  },
  network: {
    title: 'Analysis service unavailable',
    icon: WifiOff,
    wrap: 'border-red-200 bg-risk-high-soft',
    iconClass: 'text-risk-high',
  },
  timeout: {
    title: 'Request timed out',
    icon: TriangleAlert,
    wrap: 'border-amber-200 bg-risk-medium-soft',
    iconClass: 'text-risk-medium',
  },
  http: {
    title: 'Analysis service error',
    icon: TriangleAlert,
    wrap: 'border-amber-200 bg-risk-medium-soft',
    iconClass: 'text-risk-medium',
  },
  invalid_response: {
    title: 'Unexpected service response',
    icon: ShieldQuestion,
    wrap: 'border-amber-200 bg-risk-medium-soft',
    iconClass: 'text-risk-medium',
  },
}

const DEFAULT = PRESENTATION.malformed

/**
 * Accessible error message card.
 *
 * - `variant="inline"`: compact validation message under the input.
 * - default: full error panel with a Try Again button (for service errors).
 *
 * Never renders stack traces or raw technical details to the user.
 */
export default function ErrorMessage({
  code = 'malformed',
  message,
  onRetry,
  variant = 'panel',
}) {
  const style = PRESENTATION[code] ?? DEFAULT
  const Icon = style.icon
  const inline = variant === 'inline'

  if (inline) {
    return (
      <p
        role="alert"
        className="mt-2 flex items-start gap-2 text-sm font-medium text-risk-high"
      >
        <Icon size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        {message}
      </p>
    )
  }

  return (
    <div
      role="alert"
      className={`animate-fade-up rounded-2xl border p-5 ${style.wrap}`}
    >
      <div className="flex items-start gap-3">
        <span
          className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-white/70 ring-1 ring-black/5"
          aria-hidden="true"
        >
          <Icon size={18} className={style.iconClass} />
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-bold text-ink">{style.title}</h3>
          <p className="mt-1 text-sm leading-relaxed text-slate-700">{message}</p>
          {onRetry ? (
            <button type="button" onClick={onRetry} className="btn-primary mt-4 text-sm">
              <RefreshCw size={15} aria-hidden="true" />
              Try Again
            </button>
          ) : null}
        </div>
      </div>
    </div>
  )
}
