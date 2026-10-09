import {
  ArrowLeft,
  FileSearch,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import FindingCard from './FindingCard'
import Recommendations from './Recommendations'
import RiskBadge from './RiskBadge'
import RiskMeter from './RiskMeter'
import ThreatStatus from './ThreatStatus'
import UrlDetails from './UrlDetails'
import { formatTimestamp, riskStyle } from './riskStyles'

function SectionCard({ icon: Icon, title, children, className = '' }) {
  return (
    <section className={`card p-5 sm:p-6 ${className}`}>
      <h3 className="mb-4 flex items-center gap-2 text-sm font-bold uppercase tracking-wide text-muted">
        <Icon size={15} aria-hidden="true" />
        {title}
      </h3>
      {children}
    </section>
  )
}

/**
 * Analysis report dashboard. One component renders every demonstration
 * scenario (low / medium / high / unknown) with risk-consistent accents,
 * clearly labeled demo notices, findings, threat-intelligence status, and
 * safety recommendations.
 */
export default function ResultDashboard({ result, onNewScan }) {
  if (!result) return null

  const style = riskStyle(result.risk_level)
  const isHigh = style.key === 'high'
  const isDemo = Boolean(result.demo)

  return (
    <div className="animate-fade-up">
      {/* Header row */}
      <div className="animate-rise mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="section-title text-2xl sm:text-3xl">Analysis report</h1>
          <RiskBadge level={result.risk_level} />
        </div>
        <button type="button" onClick={onNewScan} className="btn-primary self-start text-sm sm:self-auto">
          <ArrowLeft size={16} aria-hidden="true" />
          New Scan
        </button>
      </div>

      {/* One status banner: high-risk warning or demo notice — not both */}
      {isHigh ? (
        <div
          role="alert"
          className="mb-4 flex items-start gap-3 rounded-2xl border border-red-300 bg-gradient-to-r from-red-50 to-rose-50 p-4"
        >
          <ShieldAlert size={20} className="mt-0.5 shrink-0 text-risk-high" aria-hidden="true" />
          <p className="text-sm leading-relaxed text-red-700">
            <strong className="font-bold text-red-800">
              Simulated high-risk demonstration.
            </strong>{' '}
            Not a confirmed malicious verdict. Do not enter passwords, OTPs, or
            payment information.
          </p>
        </div>
      ) : isDemo ? (
        <div className="mb-4 flex items-start gap-3 rounded-2xl border border-blue-200 bg-brand-soft p-4">
          <Sparkles size={18} className="mt-0.5 shrink-0 text-brand" aria-hidden="true" />
          <p className="text-sm leading-relaxed text-blue-900">
            <strong className="font-bold text-brand-dark">
              {result.demo.label}
              {/simulated/i.test(result.demo.label) ? '' : ' · SIMULATED RESULT'}
            </strong>{' '}
            — {result.demo.note}
          </p>
        </div>
      ) : null}

      {result.risk_level === 'Unknown' && !isDemo ? (
        <div className="mb-4 rounded-2xl border border-slate-300 bg-slate-50 p-4 text-sm text-slate-700">
          The service could not determine a risk level for this URL. Treat the
          result cautiously.
        </div>
      ) : null}

      {/* Result cards, in decision order: risk → URL → findings → threat → advice */}
      <div className="flex flex-col gap-4">
        <section
          className="card animate-rise anim-delay-1 border-t-4 p-6"
          style={{ borderTopColor: style.hex }}
          aria-label="Risk score summary"
        >
          <div className="mb-4 flex items-center justify-between gap-2">
            <h3 className="text-sm font-bold uppercase tracking-wide text-muted">
              Risk score
            </h3>
            <RiskBadge level={result.risk_level} size="sm" />
          </div>

          <RiskMeter score={result.risk_score} level={result.risk_level} />

          <p className="mt-4 text-center text-xs font-medium text-muted">
            {isDemo ? 'Illustrative demo score · ' : 'Score · '}
            <span className="font-semibold">
              {typeof result.risk_score === 'number'
                ? `${result.risk_score}/100`
                : 'no score available'}
            </span>
          </p>
        </section>

        <div className="animate-rise anim-delay-2">
          <UrlDetails result={result} />
        </div>

        <SectionCard
          icon={FileSearch}
          title="Security findings"
          className="animate-rise anim-delay-3"
        >
          {result.findings.length > 0 ? (
              <ul className="stagger-children space-y-3">
                {result.findings.map((finding, i) => (
                  <FindingCard key={`${finding.name}-${i}`} finding={finding} />
                ))}
              </ul>
            ) : (
              <div className="rounded-xl border border-dashed border-line bg-canvas p-5 text-sm text-muted">
                No findings were returned for this scan. An absence of findings
                is not proof that the URL is safe.
              </div>
            )}
          </SectionCard>

          <SectionCard
            icon={Radar}
            title="Threat intelligence status"
            className="animate-rise anim-delay-4"
          >
            <ThreatStatus
              status={result.reputation?.status}
              message={result.reputation?.message}
            />
          </SectionCard>

          <SectionCard
            icon={ShieldCheck}
            title="Safety recommendations"
            className="animate-rise anim-delay-5"
          >
            <Recommendations
              items={result.advice}
              accent={style.key === 'unknown' ? 'brand' : style.key}
            />
          </SectionCard>
      </div>

      {/* Scan time */}
      <p className="animate-rise anim-delay-6 mt-5 text-xs text-muted">
        Scan completed · {formatTimestamp(result.scanned_at)}
        {isDemo ? ' · Simulated report — demo mode' : ''}
      </p>
    </div>
  )
}
