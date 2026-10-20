import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import JobPanel from '../components/JobPanel'
import { Section } from '../components/ui'
import { useDomain, useJob } from '../hooks'

type Resultat = { domain: string; count: number; subdomains: Record<string, string[]> }

export default function Subdomains() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const [bruteforce, setBruteforce] = useState(true)
  const [crtsh, setCrtsh] = useState(true)
  const { job, running, error, start } = useJob<Resultat>()
  const res = job?.status === 'done' ? job.result : null

  const lancer = () => start(() => api.subdomains(saisie, bruteforce, crtsh))

  // La liste sert à l'écran Audit sécurité (certificats TLS par sous-domaine)
  if (res) {
    try { localStorage.setItem('dns-subdomains', JSON.stringify(Object.keys(res.subdomains))) } catch { /* ignore */ }
  }

  return (
    <>
      <h2>Sous-domaines</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Deux sources croisées : les journaux de certificats (crt.sh) et un dictionnaire de noms courants.
      </p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine racine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') lancer() }} /></div>
        <label className="chk-inline"><input type="checkbox" checked={bruteforce}
                 onChange={e => setBruteforce(e.target.checked)} /> Brute-force DNS</label>
        <label className="chk-inline"><input type="checkbox" checked={crtsh}
                 onChange={e => setCrtsh(e.target.checked)} /> Certificate Transparency</label>
        <button className="btn primary" disabled={running} onClick={lancer}>
          {running ? 'Découverte…' : '🔎 Découvrir'}
        </button>
      </div>

      {(!bruteforce && !crtsh) && <div className="note">Choisissez au moins une méthode de découverte.</div>}
      <JobPanel job={job} running={running} error={error} />

      {res && (
        <Section titre="Sous-domaines découverts" compte={`${res.count} · ${res.domain}`}>
          <div className="tablewrap" style={{ maxHeight: 'none' }}>
            <table className="tbl">
              <thead><tr><th>Sous-domaine</th><th>Adresses IP</th></tr></thead>
              <tbody>
                {Object.entries(res.subdomains).map(([nom, adresses]) => (
                  <tr key={nom}>
                    <td className="mono">{nom}</td>
                    <td className="mono">{adresses.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
            Passez à l'<Link to="/securite">audit de sécurité</Link> : les certificats TLS de ces sous-domaines y sont contrôlés.
          </p>
        </Section>
      )}
    </>
  )
}
