import { useState } from 'react'
import { api } from '../api'
import { Section } from '../components/ui'
import { useAsync, useDomain } from '../hooks'

export default function GeoIp() {
  const { domain } = useDomain()
  const [cible, setCible] = useState(domain)
  const { data, loading, error, run } = useAsync<any>()

  return (
    <>
      <h2>Géolocalisation</h2>
      <p className="muted" style={{ marginTop: 0 }}>Où sont physiquement les serveurs d'un domaine ? Une entrée par adresse IP.</p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>IP ou domaine</span>
          <input className="search" value={cible} onChange={e => setCible(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') run(() => api.geo(cible)) }} /></div>
        <button className="btn primary" disabled={loading} onClick={() => run(() => api.geo(cible))}>
          {loading ? 'Localisation…' : '📍 Localiser'}
        </button>
      </div>

      {error && <div className="erreur">{error}</div>}

      {data && (
        <Section titre={`${data.ips.length} adresse(s) localisée(s)`} compte={data.target}>
          <div className="tablewrap" style={{ maxHeight: 'none' }}>
            <table className="tbl">
              <thead><tr><th>IP</th><th>Ville</th><th>Pays</th><th>Hébergeur</th><th>Sous-domaines</th></tr></thead>
              <tbody>
                {data.ips.map((entree: any) => (
                  <tr key={entree.ip}>
                    <td className="mono">{entree.ip}</td>
                    <td>{entree.geo?.city || '—'}</td>
                    <td>{entree.geo?.country || '—'}</td>
                    <td className="detail">{entree.geo?.isp || entree.geo?.org || '—'}</td>
                    <td className="detail">{(entree.subdomains || []).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}
    </>
  )
}
