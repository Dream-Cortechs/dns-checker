import { useState } from 'react'
import { api } from '../api'
import JobPanel from '../components/JobPanel'
import { Pill, Section } from '../components/ui'
import { useAsync, useDomain, useJob } from '../hooks'

type Reponse = {
  ip: string
  total: number
  listed: number
  warnings: number
  errors: number
  unknown: number
  clean: number
  details: { name: string; zone: string; status: string; code: string | null; detail: string }[]
}

const ETIQUETTES: Record<string, { ton: 'green' | 'amber' | 'red' | 'gray'; texte: string }> = {
  propre: { ton: 'green', texte: 'Propre' },
  listee: { ton: 'red', texte: 'IP listée' },
  listee_reseau: { ton: 'amber', texte: 'Réseau listé' },
  erreur: { ton: 'gray', texte: 'Requête refusée' },
  inconnu: { ton: 'gray', texte: 'Sans réponse' },
}

export default function Blacklist() {
  const { domain } = useDomain()
  const [cible, setCible] = useState(domain)
  const { job, running, error, start } = useJob<Reponse>()
  const geo = useAsync<any>()
  const res = job?.status === 'done' ? job.result : null

  return (
    <>
      <h2>Blacklists</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        12 listes anti-spam interrogées en direct. Un domaine est d'abord résolu en adresse IP.
      </p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Adresse IP ou domaine</span>
          <input className="search" value={cible} onChange={e => setCible(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') start(() => api.blacklist(cible)) }} /></div>
        <button className="btn primary" disabled={running}
                onClick={() => start(() => api.blacklist(cible))}>
          {running ? 'Vérification…' : '🚫 Vérifier'}
        </button>
        <button className="btn ghost" disabled={running}
                onClick={() => { geo.run(() => api.geo(cible)); }}>📍 Localiser</button>
      </div>

      <JobPanel job={job} running={running} error={error} />

      {geo.data && geo.data.ips?.[0]?.geo && (
        <div className="note" style={{ marginTop: 12 }}>
          {geo.data.target} → {geo.data.ips[0].ip} · {geo.data.ips[0].geo.isp} · {geo.data.ips[0].geo.city}, {geo.data.ips[0].geo.country}
        </div>
      )}

      {res && (
        <>
          <div className="cards" style={{ marginTop: 14 }}>
            <div className="card"><div className="kpi-ico">📣</div><div className="kpi-num">{res.ip}</div><div className="kpi-lbl">Adresse testée</div></div>
            <div className="card"><div className="kpi-ico">✅</div><div className="kpi-num">{res.clean}</div><div className="kpi-lbl">Listes propres</div></div>
            <div className="card"><div className="kpi-ico">❌</div><div className="kpi-num">{res.listed}</div><div className="kpi-lbl">Listages confirmés</div></div>
            <div className="card"><div className="kpi-ico">⚠️</div><div className="kpi-num">{res.warnings}</div><div className="kpi-lbl">À qualifier</div></div>
          </div>

          {res.listed === 0 && (
            <div className="charge confortable" style={{ marginTop: 12 }}>
              Aucun listage confirmé de cette adresse. {res.warnings > 0 && 'Les signaux « à qualifier » portent sur tout un réseau, pas sur cette IP.'}
            </div>
          )}

          <Section titre="Détail des listes" compte={`${res.total} listes`}>
            <div className="tablewrap">
              <table className="tbl">
                <thead><tr><th>Liste</th><th>Zone DNS</th><th>Code reçu</th><th>Lecture</th><th>État</th></tr></thead>
                <tbody>
                  {res.details.map(d => {
                    const etiquette = ETIQUETTES[d.status] || ETIQUETTES.inconnu
                    return (
                      <tr key={d.zone}>
                        <td><b>{d.name}</b></td>
                        <td className="mono">{d.zone}</td>
                        <td className="mono">{d.code || '—'}</td>
                        <td className="detail">{d.detail}</td>
                        <td><Pill tone={etiquette.ton}>{etiquette.texte}</Pill></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Section>
        </>
      )}
    </>
  )
}
