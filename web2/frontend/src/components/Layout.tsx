import { NavLink, Outlet } from 'react-router-dom'
import ErrorBoundary from './ErrorBoundary'
import logoBlanc from '../assets/cortechs-embleme-blanc.png'
import logoBleu from '../assets/cortechs-embleme-bleu.png'
import { DomainContext, useStoredDomain, useTheme } from '../hooks'

const SECTIONS = [
  {
    titre: 'Diagnostic',
    liens: [
      { to: '/', ico: '🏠', label: "Vue d'ensemble" },
      { to: '/dns', ico: '🔍', label: 'Enregistrements DNS' },
      { to: '/propagation', ico: '🌍', label: 'Propagation' },
    ],
  },
  {
    titre: 'Messagerie',
    liens: [
      { to: '/email', ico: '📧', label: 'Sécurité email' },
      { to: '/blacklists', ico: '🚫', label: 'Blacklists' },
    ],
  },
  {
    titre: 'Reconnaissance',
    liens: [
      { to: '/whois', ico: '📋', label: 'WHOIS' },
      { to: '/geo', ico: '📍', label: 'Géo IP' },
      { to: '/sous-domaines', ico: '🔎', label: 'Sous-domaines' },
    ],
  },
  {
    titre: 'Sécurité & rapport',
    liens: [
      { to: '/securite', ico: '🛡', label: 'Audit sécurité' },
      { to: '/rapport', ico: '📄', label: 'Rapport PDF' },
    ],
  },
]

export default function Layout() {
  const { domain, setDomain } = useStoredDomain()
  const { theme, toggle } = useTheme()

  return (
    <DomainContext.Provider value={{ domain, setDomain }}>
      <div className="app">
        <aside className="sidebar">
          <div className="brand">
            <span className="logo-cortechs" style={{ height: 34 }}>
              <img src={logoBlanc} alt="Cortechs" className="logo-sur-sombre" />
              <img src={logoBleu} alt="Cortechs" className="logo-sur-clair" />
            </span>{' '}
            <b>DNS</b> Checker
          </div>
          <nav className="menu">
            {SECTIONS.map(section => (
              <div className="sec" key={section.titre}>
                <div className="sec-title">{section.titre}</div>
                {section.liens.map(lien => (
                  <NavLink key={lien.to} to={lien.to} end={lien.to === '/'}
                           className={({ isActive }) => 'navi' + (isActive ? ' on' : '')}>
                    <span className="navi-ico">{lien.ico}</span>
                    <span className="navi-label">{lien.label}</span>
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
        </aside>

        <div className="main">
          <header className="topbar">
            <div className="topbar-title">
              DNS Checker <span className="muted" style={{ fontSize: 13, fontWeight: 500 }}>· {domain}</span>
            </div>
            <div className="topbar-user">
              <button className="theme-toggle" onClick={toggle} title="Changer de thème">
                {theme === 'dark' ? '☀️' : '🌙'}
              </button>
              <span className="pill gray">LAN · 192.168.17.35:8507</span>
            </div>
          </header>
          <main className="content">
            <div className="page wide">
              <ErrorBoundary>
                <Outlet />
              </ErrorBoundary>
            </div>
          </main>
        </div>
      </div>
    </DomainContext.Provider>
  )
}
