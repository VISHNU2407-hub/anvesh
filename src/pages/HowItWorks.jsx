import {
  ArrowRight,
  FileSearch,
  Radar,
  Search,
  ShieldCheck,
} from 'lucide-react'

const STEPS = [
  {
    icon: FileSearch,
    title: 'URL Parsing and Validation',
    text: 'The URL is split into its parts and checked for format errors; only http:// and https:// links are accepted.',
  },
  {
    icon: Search,
    title: 'Suspicious Pattern Analysis',
    text: 'Structural red flags are collected, such as deep subdomains, look-alike domains, and credential wording like "login" or "verify".',
  },
  {
    icon: Radar,
    title: 'Threat Intelligence',
    text: 'The domain is checked against reputation and threat feeds for known-malicious matches.',
  },
  {
    icon: ShieldCheck,
    title: 'Risk Assessment and Safety Advice',
    text: 'Indicators combine into a 0–100 score with a risk category, plus clear steps to stay safe.',
  },
]

/** Four-step pipeline: icon, title, one sentence each. */
export default function HowItWorks() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="animate-rise max-w-2xl">
        <h1 className="section-title">How it works</h1>
        <p className="mt-3 text-sm leading-relaxed text-muted sm:text-base">
          URLens analyzes a URL in four steps.
        </p>
      </div>

      <ol className="stagger-children mt-8 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {STEPS.map((step, index) => (
          <li key={step.title} className="card relative flex flex-col p-5">
            <div className="flex items-center justify-between">
              <span
                className="flex size-10 items-center justify-center rounded-xl bg-gradient-to-br from-brand to-brand-dark text-white shadow-md shadow-blue-500/25"
                aria-hidden="true"
              >
                <step.icon size={19} />
              </span>
              <span className="tabular text-3xl font-extrabold text-line">
                {String(index + 1).padStart(2, '0')}
              </span>
            </div>
            <h2 className="mt-4 text-base font-bold leading-snug text-ink">
              {step.title}
            </h2>
            <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">
              {step.text}
            </p>
            {index < STEPS.length - 1 ? (
              <ArrowRight
                size={16}
                className="absolute -right-3 top-1/2 hidden -translate-y-1/2 text-slate-300 max-xl:hidden md:block"
                aria-hidden="true"
              />
            ) : null}
            {index < STEPS.length - 1 ? (
              <ArrowRight
                size={16}
                className="absolute -bottom-3 left-1/2 -translate-x-1/2 text-slate-300 md:hidden"
                aria-hidden="true"
              />
            ) : null}
          </li>
        ))}
      </ol>

      <p className="animate-rise anim-delay-4 mt-6 text-sm text-muted">
        In this demo, analysis runs on local mock data — no live threat feeds
        are contacted, and no automated result guarantees safety.
      </p>
    </div>
  )
}
