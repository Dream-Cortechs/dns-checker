import { useEffect, useState } from 'react'
import { api, Meta } from '../api'
import { Pill, Section } from '../components/ui'
import { useAsync, useDomain } from '../hooks'

export default function DnsLookup() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const [type, setType] = useState('A')
  const [resolver, setResolver] = useState('')
  const [meta, setMeta] = useState<Meta | null>(null)
  const { data, loading, error, run } = useAsync<any>()

  useEffect(() => { api.meta().then(setMeta).catch(() => setMeta(null)) }, [])

  const rechercher = () => run(() => api.lookup(saisie, type, resolver))

  return (
    <>
      <h2>Enregistrements DNS</h2>
      <p className="muted" style={{ marginTop: 0 }}>Recherche directe d'un enregistrement, sur le résolveur système ou un résolveur public.</p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') rechercher() }} />
        </div>
        <div className="fld"><span>Type</span>
          <select value={type} onChange={e => setType(e.target.value)}>
            {(meta?.record_types || ['A']).map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="fld"><span>Résolveur</span>
          <select value={resolver} onChange={e => setResolver(e.target.value)}>
            <option value="">Système</option>
            {Object.entries(meta?.resolvers || {}).map(([nom, ip]) => (
              <option key={ip} value={ip}>{nom} — {ip}</option>
            ))}
          </select>
        </div>
        <button className="btn primary" onClick={rechercher} disabled={loading}>
          {loading ? 'Recherche…' : '🔍 Rechercher'}
        </button>
      </div>

      {error && <div className="erreur">{error}</div>}

      {data && (
        <Section titre={`${data.count} enregistrement(s) ${data.type} pour ${data.domain}`}
                 compte={`résolveur ${data.resolver || 'système'}`}>
          {data.error && <div className="erreur">Le moteur signale : {data.error}</div>}
          <div className="tablewrap" style={{ maxHeight: 'none' }}>
            <table className="tbl">
              <thead><tr><th>#</th><th>Valeur</th></tr></thead>
              <tbody>
                {data.records.map((valeur: string, index: number) => (
                  <tr key={index}><td>{index + 1}</td><td className="mono">{valeur}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.count === 0 && !data.error && <p className="muted" style={{ fontSize: 13 }}>Aucun enregistrement de ce type.</p>}
        </Section>
      )}

      <p className="muted" style={{ fontSize: 12.5, marginTop: 18 }}>
        <Pill tone="blue">Astuce</Pill> Le type ANY est souvent refusé par les résolveurs publics : préférez un type précis.
      </p>
    </>
  )
}
