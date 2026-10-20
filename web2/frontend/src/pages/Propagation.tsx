import { useState } from 'react'
import { api } from '../api'
import JobPanel from '../components/JobPanel'
import { Pill, Section } from '../components/ui'
import { useDomain, useJob } from '../hooks'

type Resultat = {
  domain: string
  type: string
  total: number
  success: number
  consensus: string
  consensus_pct: number
  details: { name: string; ip: string; result: string; ok: boolean; error: string | null }[]
}

export default function Propagation() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const [type, setType] = useState('A')
  const { job, running, error, start } = useJob<Resultat>()
  const res = job?.status === 'done' ? job.result : null

  return (
    <>
      <h2>Propagation DNS</h2>
      <p className="muted" style={{ marginTop: 0 }}>Le même enregistrement, demandé à 24 résolveurs publics dans le monde.</p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)} /></div>
        <div className="fld"><span>Type</span>
          <select value={type} onChange={e => setType(e.target.value)}>
            {['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'].map(t => <option key={t} value={t}>{t}</option>)}
          </select></div>
        <button className="btn primary" disabled={running}
                onClick={() => start(() => api.propagation(saisie, type))}>
          {running ? 'Interrogation…' : '🌍 Vérifier'}
        </button>
      </div>

      <JobPanel job={job} running={running} error={error} />

      {res && (
        <>
          <div className="cards" style={{ marginTop: 14 }}>
            <div className="card"><div className="kpi-ico">✅</div><div className="kpi-num">{res.success}/{res.total}</div>
              <div className="kpi-lbl">Réponses reçues</div></div>
            <div className="card"><div className="kpi-ico">🎯</div><div className="kpi-num">{res.consensus || '—'}</div>
              <div className="kpi-lbl">IP majoritaire</div><div className="kpi-period">{res.consensus_pct}% des résolveurs</div></div>
            <div className="card"><div className="kpi-ico">⚠️</div><div className="kpi-num">{res.total - res.success}</div>
              <div className="kpi-lbl">Sans réponse</div><div className="kpi-period">filtrage ou timeout</div></div>
          </div>

          {res.success < res.total && (
            <div className="note" style={{ marginTop: 14 }}>
              Les résolveurs sans réponse ({res.details.filter(d => !d.ok).map(d => d.name).join(', ')}) filtrent souvent
              les requêtes depuis la France : ce n'est pas nécessairement un défaut de la zone.
            </div>
          )}

          <Section titre="Détail par résolveur" compte={`${res.total} résolveurs`}>
            <div className="tablewrap">
              <table className="tbl">
                <thead><tr><th>Résolveur</th><th>Adresse</th><th>Réponse</th><th>État</th></tr></thead>
                <tbody>
                  {res.details.map(d => (
                    <tr key={d.ip}>
                      <td>{d.name}</td>
                      <td className="mono">{d.ip}</td>
                      <td className="mono">{d.result}</td>
                      <td>{d.ok ? <Pill tone="green">Répondu</Pill> : <Pill tone="amber">{d.error || 'Sans réponse'}</Pill>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        </>
      )}
    </>
  )
}
