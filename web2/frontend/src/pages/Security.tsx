import { useState } from 'react'
import { api } from '../api'
import JobPanel from '../components/JobPanel'
import { Pill, Section, texte } from '../components/ui'
import { useDomain, useJob } from '../hooks'

type Resultat = {
  domain: string
  score: number
  max_score: number
  criteria: Record<string, { ok: boolean; detail: string }>
  dnssec: { signed: boolean; details?: string[] }
  caa: { has_caa: boolean; records: string[]; issuers?: string[]; analysis?: string[] }
  http_headers: { score: number; max_score: number; checks?: Record<string, { ok: boolean; value?: string }> }
  tls: { total?: number; certificates?: Record<string, any>; expiring_soon?: string[]; summary?: string }
}

export default function Security() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const { job, running, error, start } = useJob<Resultat>()
  const res = job?.status === 'done' ? job.result : null

  const sousDomaines = (() => {
    try { return JSON.parse(localStorage.getItem('dns-subdomains') || '[]') as string[] } catch { return [] }
  })()

  return (
    <>
      <h2>Audit de sécurité</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        DNSSEC, CAA, en-têtes HTTP et certificats TLS des sous-domaines déjà découverts.
      </p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') start(() => api.security(saisie, sousDomaines)) }} /></div>
        <div className="fld"><span>Sous-domaines à contrôler</span>
          <input className="search" value={sousDomaines.length ? `${sousDomaines.length} sous-domaines mémorisés` : 'aucun (lancez d\'abord Sous-domaines)'} readOnly /></div>
        <button className="btn primary" disabled={running}
                onClick={() => start(() => api.security(saisie, sousDomaines))}>
          {running ? 'Audit en cours…' : '🛡 Lancer l\'audit'}
        </button>
      </div>

      <JobPanel job={job} running={running} error={error} />

      {res && (
        <>
          <div className={`charge ${res.score === res.max_score ? 'confortable' : res.score >= 2 ? 'modere' : 'eleve'}`}>
            Score {res.score}/{res.max_score} — {res.score === res.max_score ? 'zone correctement protégée'
              : 'plusieurs protections manquent'}
          </div>

          <div className="cards" style={{ marginTop: 4 }}>
            {Object.entries(res.criteria).map(([cle, critere]) => (
              <div className="card" key={cle}>
                <div className="kpi-ico">{critere.ok ? '✅' : '⚠️'}</div>
                <div className="kpi-num" style={{ fontSize: 16 }}>{cle === 'http_headers' ? 'En-têtes HTTP' : cle.toUpperCase()}</div>
                <div className="kpi-lbl">{texte(critere.detail)}</div>
              </div>
            ))}
          </div>

          <Section titre="Certificats TLS" compte={`${res.tls?.total ?? 0} hôte(s)`}>
            <div className="tablewrap">
              <table className="tbl">
                <thead><tr><th>Hôte</th><th>Émetteur</th><th>Expire le</th><th>Jours restants</th><th>État</th></tr></thead>
                <tbody>
                  {Object.values(res.tls?.certificates || {}).map((cert: any) => (
                    <tr key={cert.hostname}>
                      <td className="mono">{cert.hostname}</td>
                      <td className="detail">{cert.issuer_org || cert.issuer || '—'}</td>
                      <td>{cert.not_after || '—'}</td>
                      <td className="num">{cert.days_left ?? '—'}</td>
                      <td>{cert.error ? <Pill tone="red">{cert.error}</Pill>
                        : (cert.days_left ?? 999) < 21 ? <Pill tone="amber">Expire bientôt</Pill>
                        : <Pill tone="green">Valide</Pill>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          <div className="twocol">
            <div className="card">
              <h4 className="h4c">🔐 DNSSEC</h4>
              <p style={{ fontSize: 13 }}>{res.dnssec.signed ? 'Zone signée : les réponses sont protégées contre la falsification.'
                : 'Zone non signée : une réponse DNS peut être falsifiée (cache poisoning).'}</p>
              {(res.dnssec.details || []).map((d, i) => <div className="ck-row" key={i}><span className="muted">{d}</span></div>)}
            </div>
            <div className="card">
              <h4 className="h4c">🔐 CAA</h4>
              <p style={{ fontSize: 13 }}>{res.caa.has_caa ? `Autorités autorisées : ${(res.caa.issuers || []).join(', ')}`
                : 'CAA absent : n\'importe quelle autorité de certification peut émettre un certificat pour ce domaine.'}</p>
              {(res.caa.records || []).map((r, i) => <div className="ck-row" key={i}><span className="mono">{r}</span></div>)}
            </div>
          </div>

          <Section titre="En-têtes HTTP" compte={`${res.http_headers.score}/${res.http_headers.max_score}`}>
            <div className="card" style={{ padding: '6px 18px' }}>
              {Object.entries(res.http_headers.checks || {}).map(([nom, controle]: any) => (
                <div className="ck-row" key={nom}>
                  <span className={controle.ok ? 'ico-ok' : 'ico-err'}>{controle.ok ? '✓' : '✗'}</span>
                  <span>{nom}</span>
                  <span className="v">{texte(controle.value || (controle.ok ? 'présent' : 'absent'))}</span>
                </div>
              ))}
            </div>
          </Section>
        </>
      )}
    </>
  )
}
