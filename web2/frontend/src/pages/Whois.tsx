import { useState } from 'react'
import { api } from '../api'
import { Pill, Section, dateFr } from '../components/ui'
import { useAsync, useDomain } from '../hooks'

export default function Whois() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const { data, loading, error, run } = useAsync<any>()

  return (
    <>
      <h2>WHOIS</h2>
      <p className="muted" style={{ marginTop: 0 }}>Titulaire, registraire, dates et serveurs de noms — lus directement chez le registre.</p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') run(() => api.whois(saisie)) }} /></div>
        <button className="btn primary" disabled={loading} onClick={() => run(() => api.whois(saisie))}>
          {loading ? 'Interrogation…' : '📋 WHOIS'}
        </button>
      </div>

      {error && <div className="erreur">{error}</div>}
      {data?.error && <div className="erreur">{data.error}</div>}

      {data && !data.error && (
        <>
          <Section titre={data.domain} compte={`via ${data.server}`}>
            <div className="card" style={{ padding: '6px 18px' }}>
              <div className="ck-row"><span>Registraire</span><span className="v">{data.registrar || '—'}</span></div>
              <div className="ck-row"><span>Titulaire</span><span className="v">{data.holder || '—'}</span></div>
              <div className="ck-row"><span>Créé le</span><span className="v">{dateFr(data.creation_date)}</span></div>
              <div className="ck-row"><span>Dernière modification</span><span className="v">{dateFr(data.last_update)}</span></div>
              <div className="ck-row"><span>Prochaine échéance</span><span className="v">{dateFr(data.expiration_date)}</span></div>
              <div className="ck-row"><span>Statut</span><span className="v">{(data.status || []).join(' · ') || '—'}</span></div>
            </div>
          </Section>

          <Section titre="Serveurs de noms" compte={`${(data.name_servers || []).length}`}>
            <div className="card" style={{ padding: '6px 18px' }}>
              {(data.name_servers || []).map((ns: string) => (
                <div className="ck-row" key={ns}><span className="mono">{ns}</span></div>
              ))}
            </div>
          </Section>

          <Section titre="Réponse brute du registre">
            <pre className="raw">{data.raw}</pre>
          </Section>
          <Pill tone="blue">Les .fr n'exposent pas le titulaire complet (RGPD) : c'est normal.</Pill>
        </>
      )}
    </>
  )
}
