import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, Summary } from '../api'
import JobPanel from '../components/JobPanel'
import { Kpi, Pill, Section } from '../components/ui'
import { useDomain, useJob } from '../hooks'

const TONS: Record<string, 'red' | 'amber' | 'blue'> = { critique: 'red', moyen: 'amber', info: 'blue' }

export default function Dashboard() {
  const { domain, setDomain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const { job, running, error, start } = useJob<Summary>()
  const resultat = job?.status === 'done' ? job.result : null

  const lancer = () => {
    const propre = saisie.trim()
    if (!propre) return
    setDomain(propre)
    start(() => api.summary(propre))
  }

  return (
    <>
      <div className="card dombar">
        <span style={{ fontSize: 22 }}>🔍</span>
        <input className="search domaine" value={saisie} aria-label="Nom de domaine"
               placeholder="ex: cortechs.fr" onChange={e => setSaisie(e.target.value)}
               onKeyDown={e => { if (e.key === 'Enter') lancer() }} />
        <span className="sep" />
        <button className="btn primary" onClick={lancer} disabled={running}>
          {running ? 'Scan en cours…' : '⚡ Scanner'}
        </button>
        <Link className="btn ghost" to="/rapport">📄 Rapport PDF</Link>
      </div>

      <JobPanel job={job} running={running} error={error} />

      {!resultat && !running && (
        <div className="card" style={{ marginTop: 16 }}>
          <h4 className="h4c">🧭 Que fait un scan complet ?</h4>
          <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
            Enregistrements DNS, propagation mondiale (24 résolveurs), MX/SPF/DKIM/DMARC,
            réputation IP, WHOIS, sous-domaines, géolocalisation et audit de sécurité.
            Saisissez un domaine puis cliquez sur Scanner.
          </p>
        </div>
      )}

      {resultat && (
        <>
          <div className="lrow" style={{ marginTop: 12 }}>
            <span className="lrow-t">Scan de {resultat.domain}</span>
            <span className="muted" style={{ fontSize: 12.5 }}>
              {resultat.scanned_at} · {resultat.ip || 'IP non résolue'}
            </span>
          </div>

          <div className="cards kpi6">
            <Kpi ico="🌍" valeur={`${resultat.propagation.success}/${resultat.propagation.total}`}
                 libelle="Propagation" periode="résolveurs qui répondent" />
            <Kpi ico="📧" valeur={`${resultat.email.score}/${resultat.email.max_score}`}
                 libelle="Sécurité email" periode="MX · SPF · DKIM · DMARC" />
            <Kpi ico="🛡" valeur={resultat.security ? `${resultat.security.score}/${resultat.security.max_score}` : '—'}
                 libelle="Protections zone" periode="DNSSEC · CAA · en-têtes · TLS" />
            <Kpi ico="🚫" valeur={resultat.blacklist ? resultat.blacklist.listed : '—'}
                 libelle="Blacklists" periode={resultat.blacklist ? `${resultat.blacklist.warnings} à qualifier` : 'IP non résolue'} />
            <Kpi ico="🔎" valeur={resultat.subdomains.count} libelle="Sous-domaines"
                 periode="crt.sh + brute-force" />
            <Kpi ico="📋" valeur={Object.keys(resultat.lookup).length} libelle="Types d'enregistrements"
                 periode="A · AAAA · MX · TXT · NS · SOA" />
          </div>

          {resultat.findings.length > 0 ? (
            <div className={'charge ' + (resultat.findings.some(f => f.severity === 'critique') ? 'eleve' : 'modere')}>
              ⚠️ {resultat.findings.length} point(s) relevé(s) sur {resultat.domain}
              {resultat.findings.filter(f => f.severity === 'critique').length > 0 && (
                <> — dont {resultat.findings.filter(f => f.severity === 'critique').length} critique(s)</>
              )}
            </div>
          ) : (
            <div className="charge confortable">✅ Aucun point bloquant détecté sur {resultat.domain}</div>
          )}

          <div className="twocol">
            <div>
              <Section titre="À corriger" compte={`${resultat.findings.length} point(s)`}>
                <div className="card" style={{ padding: '8px 18px' }}>
                  {resultat.findings.length === 0 && <p className="muted" style={{ fontSize: 13 }}>Rien à signaler.</p>}
                  {resultat.findings.map((point, index) => (
                    <div className="finding" key={index}>
                      <Pill tone={TONS[point.severity] || 'gray'}>{point.severity}</Pill>
                      <div className="d"><b>{point.title}</b><span>{point.detail}</span></div>
                    </div>
                  ))}
                </div>
              </Section>
            </div>

            <div>
              <Section titre="Propagation" compte={`${resultat.propagation.total} résolveurs`}>
                <div className="card">
                  <div className="tracks">
                    <div className="t">
                      <span>Réponses reçues</span>
                      <span className="tr"><i style={{ width: `${Math.round(resultat.propagation.success / resultat.propagation.total * 100)}%`, background: 'linear-gradient(90deg, var(--blue), var(--blue-2))' }} /></span>
                      <span className="mono">{Math.round(resultat.propagation.success / resultat.propagation.total * 100)}%</span>
                    </div>
                    <div className="t">
                      <span>Consensus</span>
                      <span className="tr"><i style={{ width: `${resultat.propagation.consensus_pct}%`, background: 'linear-gradient(90deg, #10b981, #06b6d4)' }} /></span>
                      <span className="mono">{resultat.propagation.consensus_pct}%</span>
                    </div>
                  </div>
                  <div className="lrow" style={{ marginTop: 10 }}>
                    <span className="lrow-t">IP majoritaire</span>
                    <span className="mono">{resultat.propagation.consensus || '—'}</span>
                  </div>
                  <div className="lrow">
                    <span className="lrow-t">Sans réponse</span>
                    <span className="muted" style={{ fontSize: 12.5 }}>
                      {resultat.propagation.details.filter(d => !d.ok).map(d => d.name).join(' · ') || 'aucun'}
                    </span>
                  </div>
                </div>
              </Section>
            </div>
          </div>

          <Section titre="Enregistrements DNS" compte={`zone ${resultat.domain}`}>
            <div className="tablewrap" style={{ maxHeight: 'none' }}>
              <table className="tbl">
                <thead><tr><th>Type</th><th>Valeur</th></tr></thead>
                <tbody>
                  {Object.entries(resultat.lookup).map(([type, valeurs]) =>
                    valeurs.map((valeur, index) => (
                      <tr key={type + index}>
                        <td><b>{type.toUpperCase()}</b></td>
                        <td className="mono">{valeur}</td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            </div>
          </Section>

          <Section titre="Messagerie" compte={`score ${resultat.email.score}/${resultat.email.max_score}`}>
            <div className="card" style={{ padding: '6px 18px' }}>
              {Object.entries(resultat.email.criteria).map(([cle, critere]) => (
                <div className="ck-row" key={cle}>
                  <span className={critere.ok ? 'ico-ok' : 'ico-err'}>{critere.ok ? '✓' : '✗'}</span>
                  <span>{cle.toUpperCase()}</span>
                  <span className="v">{critere.detail}</span>
                </div>
              ))}
            </div>
          </Section>

          {resultat.blacklist && (
            <Section titre="Réputation de l'IP" compte={resultat.blacklist.ip}>
              <div className="card" style={{ padding: '6px 18px' }}>
                <div className="ck-row"><span className="ico-ok">✓</span><span>{resultat.blacklist.clean} liste(s) propre(s)</span></div>
                <div className="ck-row">
                  <span className={resultat.blacklist.listed ? 'ico-err' : 'ico-ok'}>{resultat.blacklist.listed ? '✗' : '✓'}</span>
                  <span>{resultat.blacklist.listed} listage(s) confirmé(s) de l'IP</span>
                </div>
                <div className="ck-row"><span className="ico-warn">!</span><span>{resultat.blacklist.warnings} signal(aux) au niveau réseau (/24 ou AS)</span></div>
                <div className="ck-row"><span className="ico-warn">!</span><span className="v">{resultat.blacklist.errors + resultat.blacklist.unknown} liste(s) injoignable(s)</span></div>
                <p className="muted" style={{ fontSize: 12, margin: '10px 0' }}>
                  Détail complet dans l'écran <Link to="/blacklists">Blacklists</Link>.
                </p>
              </div>
            </Section>
          )}

          <Section titre="Sous-domaines" compte={`${resultat.subdomains.count} trouvés`}>
            <p className="muted" style={{ fontSize: 13 }}>
              <Link to="/sous-domaines">Ouvrir l'écran Sous-domaines</Link> pour la liste complète avec IP et hébergeur.
            </p>
          </Section>
        </>
      )}
    </>
  )
}
