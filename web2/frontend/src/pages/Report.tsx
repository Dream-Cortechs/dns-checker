import { useState } from 'react'
import { api } from '../api'
import JobPanel from '../components/JobPanel'
import { Section } from '../components/ui'
import { useDomain, useJob } from '../hooks'

type Resultat = { domain: string; ip: string | null; name: string; size: number; url: string; generated_at: string }

export default function Report() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const [ip, setIp] = useState('')
  const { job, running, error, start } = useJob<Resultat>()
  const res = job?.status === 'done' ? job.result : null

  return (
    <>
      <h2>Rapport PDF</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Diagnostic complet mis en page, prêt à envoyer à un client. La génération prend une vingtaine de secondes.
      </p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)} /></div>
        <div className="fld"><span>IP pour les blacklists (facultatif)</span>
          <input className="search" value={ip} placeholder="déduite du domaine" onChange={e => setIp(e.target.value)} /></div>
        <button className="btn primary" disabled={running}
                onClick={() => start(() => api.report(saisie, ip))}>
          {running ? 'Génération…' : '📄 Générer le rapport'}
        </button>
      </div>

      <JobPanel job={job} running={running} error={error} />

      {res && (
        <Section titre="Rapport prêt" compte={res.generated_at}>
          <div className="card">
            <div className="ck-row"><span>Fichier</span><span className="v">{res.name}</span></div>
            <div className="ck-row"><span>Taille</span><span className="v">{Math.round(res.size / 1024)} ko</span></div>
            <div className="ck-row"><span>Domaine</span><span className="v">{res.domain}</span></div>
            <div className="ck-row"><span>IP analysée</span><span className="v">{res.ip || '—'}</span></div>
            <div className="form-actions" style={{ marginTop: 14 }}>
              <a className="btn primary" href={res.url} target="_blank" rel="noreferrer">📥 Télécharger le PDF</a>
            </div>
          </div>
        </Section>
      )}
    </>
  )
}
