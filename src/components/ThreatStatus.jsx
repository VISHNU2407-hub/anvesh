import { CircleHelp, EyeOff, ShieldAlert, ShieldCheck } from 'lucide-react'

const STATES = {
  malicious: {
    title: 'Known malicious match',
    text: 'text-red-700',
    iconBg: 'bg-red-100',
    icon: ShieldAlert,
    iconClass: 'text-red-600',
    border: 'border-red-200',
    fallback:
      'This address matched a known threat entry in the supplied intelligence data.',
  },
  clean: {
    title: 'No known threat match',
    text: 'text-emerald-700',
    iconBg: 'bg-emerald-100',
    icon: ShieldCheck,
    iconClass: 'text-emerald-600',
    border: 'border-emerald-200',
    fallback:
      'No match was found in the consulted sources. This does not guarantee the URL is safe.',
  },
  unavailable: {
    title: 'Unable to verify',
    text: 'text-slate-700',
    iconBg: 'bg-slate-100',
    icon: CircleHelp,
    iconClass: 'text-slate-500',
    border: 'border-slate-300',
    fallback:
      'Threat-intelligence data could not be retrieved for this scan.',
  },
  not_checked: {
    title: 'Not checked in demo mode',
    text: 'text-blue-800',
    iconBg: 'bg-blue-100',
    icon: EyeOff,
    iconClass: 'text-brand',
    border: 'border-blue-200',
    fallback:
      'No threat feed, reputation database, or domain-age lookup was queried — this scan runs on local demo data.',
  },
}

function resolveState(status) {
  const key = String(status ?? '').toLowerCase()
  // Backend reputation_status values (new contract)
  if (key === 'threat_detected' || key === 'malicious' || key === 'known_malicious') return STATES.malicious
  if (key === 'no_known_threat' || key === 'clean' || key === 'no_match' || key === 'safe') return STATES.clean
  if (key === 'not_checked' || key === 'not-checked') return STATES.not_checked
  // Anything else (including 'unavailable', error reasons) -> unable to verify
  return STATES.unavailable
}

/**
 * Threat-intelligence status card.
 * Renders one of four distinct states and only ever displays details that
 * were actually supplied by the response — nothing is fabricated.
 */
export default function ThreatStatus({ status, message }) {
  const state = resolveState(status)
  const Icon = state.icon
  const text = message || state.fallback

  return (
    <div className={`rounded-xl border bg-white p-4 ${state.border}`}>
      <div className="flex items-start gap-3">
        <span
          className={`flex size-9 shrink-0 items-center justify-center rounded-lg ${state.iconBg}`}
          aria-hidden="true"
        >
          <Icon size={18} className={state.iconClass} />
        </span>
        <div className="min-w-0">
          <p className={`text-sm font-semibold ${state.text}`}>{state.title}</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{text}</p>
        </div>
      </div>
    </div>
  )
}
