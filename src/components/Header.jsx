import { useEffect, useState } from 'react'
import { Link as LinkIcon, Menu, Shield, X } from 'lucide-react'
import { Link, NavLink } from 'react-router-dom'
import { USE_MOCK } from '../services/analysisApi'

const NAV_ITEMS = [
  { to: '/', label: 'Home', end: true },
  { to: '/how-it-works', label: 'How It Works' },
  { to: '/history', label: 'History' },
]

function navClass({ isActive }) {
  return [
    'rounded-full px-3.5 py-2 text-sm font-medium transition-colors',
    isActive
      ? 'bg-brand-soft text-brand-dark font-semibold'
      : 'text-slate-600 hover:bg-canvas hover:text-ink',
    'duration-200',
  ].join(' ')
}

function DemoBadge({ compact = false }) {
  if (!USE_MOCK) {
    return (
      <span
        className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide text-emerald-700"
        title="The frontend is configured to call the FastAPI backend (VITE_USE_MOCK=false)."
      >
        <span className="size-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
        API mode
      </span>
    )
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide text-amber-700 ${
        compact ? '' : ''
      }`}
      title="Mock data is in use: results are simulated locally and no backend is connected."
    >
      <span className="size-1.5 rounded-full bg-amber-500" aria-hidden="true" />
      Demo mode
    </span>
  )
}

/**
 * Application header: branding, functional navigation, DEMO MODE indicator,
 * and a responsive mobile menu.
 */
export default function Header() {
  const [open, setOpen] = useState(false)

  // Close the mobile menu whenever the route changes.
  useEffect(() => {
    const close = () => setOpen(false)
    window.addEventListener('hashchange', close)
    return () => window.removeEventListener('hashchange', close)
  }, [])

  return (
    <header className="animate-header-in sticky top-0 z-40 border-b border-line bg-white/90 backdrop-blur-md">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-brand focus:px-3 focus:py-2 focus:text-sm focus:text-white"
      >
        Skip to content
      </a>

      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
        {/* Brand */}
        <Link
          to="/"
          className="group flex items-center gap-2.5"
          aria-label="URLens home"
        >
          <span className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-brand to-brand-dark text-white shadow-md shadow-blue-500/25 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:shadow-lg group-hover:shadow-blue-500/30">
            <Shield size={19} aria-hidden="true" />
          </span>
          <span className="text-lg font-extrabold tracking-tight text-ink transition-colors duration-200 group-hover:text-brand-dark">
            URL<span className="text-brand">ens</span>
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden items-center gap-1 md:flex" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className={navClass}>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <DemoBadge />
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-controls="mobile-nav"
            aria-label={open ? 'Close navigation menu' : 'Open navigation menu'}
            className="flex size-9 items-center justify-center rounded-lg border border-line text-ink transition hover:bg-canvas md:hidden"
          >
            {open ? <X size={18} aria-hidden="true" /> : <Menu size={18} aria-hidden="true" />}
          </button>
        </div>
      </div>

      {/* Mobile nav */}
      {open ? (
        <nav
          id="mobile-nav"
          aria-label="Mobile navigation"
          className="border-t border-line bg-white px-4 pb-4 pt-2 md:hidden"
        >
          <ul className="flex flex-col gap-1">
            {NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.end}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    [
                      'flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-brand-soft text-brand-dark'
                        : 'text-slate-600 hover:bg-canvas',
                    ].join(' ')
                  }
                >
                  <LinkIcon size={14} aria-hidden="true" />
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      ) : null}
    </header>
  )
}
