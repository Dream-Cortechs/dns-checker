import { useState } from 'react'
import { api } from '../api'
import { Pill, Section, texte } from '../components/ui'
import { useAsync, useDomain } from '../hooks'

export default function Email() {
  const { domain } = useDomain()
  const [saisie, setSaisie] = useState(domain)
  const [selector, setSelector] = useState('default')
  const { data, loading, error, run } = useAsync<any>()

  return (
    <>
      <h2>Sécurité email</h2>
      <p className="muted" style={{ marginTop: 0 }}>MX, SPF, DKIM et DMARC : les quatre briques qui décident si vos mails sont acceptés.</p>

      <div className="card filters" style={{ marginTop: 14 }}>
        <div className="fld"><span>Domaine</span>
          <input className="search" value={saisie} onChange={e => setSaisie(e.target.value)}
                 onKeyDown={e => { if (e.key === 'Enter') run(() => api.email(saisie, selector)) }} /></div>
        <div className="fld"><span>Sélecteur DKIM</span>
          <input className="search" value={selector} onChange={e => setSelector(e.target.value)} /></div>
        <button className="btn primary" disabled={loading}
                onClick={() => run(() => api.email(saisie, selector))}>
          {loading ? 'Analyse…' : '🔒 Analyser'}
        </button>
      </div>

      {error && <div className="erreur">{error}</div>}

      {data && (
        <>
          <div className={`charge ${data.score === data.max_score ? 'confortable' : data.score >= 2 ? 'modere' : 'eleve'}`}>
            Score {data.score}/{data.max_score} — {data.score === data.max_score
              ? 'messagerie correctement protégée'
              : 'des mécanismes de protection manquent'}
          </div>

          <div className="cards" style={{ marginTop: 4 }}>
            {Object.entries(data.criteria).map(([cle, critere]: any) => (
              <div className="card" key={cle}>
                <div className="kpi-ico">{critere.ok ? '✅' : '❌'}</div>
                <div className="kpi-num" style={{ fontSize: 16 }}>{cle.toUpperCase()}</div>
                <div className="kpi-lbl">{texte(critere.detail)}</div>
              </div>
            ))}
          </div>

          <Section titre="Enregistrements" compte={data.domain}>
            <div className="card" style={{ padding: '6px 18px' }}>
              <div className="ck-row"><span>MX</span><span className="v">{data.mx.servers.join(' · ') || '—'}</span></div>
              <div className="ck-row"><span>SPF</span><span className="v">{data.spf.records.join(' · ') || 'absent'}</span></div>
              <div className="ck-row"><span>SPF politique</span><span className="v">{data.spf.mechanism}</span></div>
              <div className="ck-row"><span>DKIM ({data.selector})</span>
                <span className="v">{data.dkim.present ? 'signature publiée' : 'absente'}</span></div>
              <div className="ck-row"><span>DMARC</span>
                <span className="v">{data.dmarc.present ? data.dmarc.policy : 'absent'}</span></div>
            </div>
          </Section>

          {!data.dkim.present && (
            <div className="note" style={{ marginTop: 14 }}>
              <b>DKIM absent.</b> Combiné à un DMARC strict, cela peut faire rejeter vos propres mails :
              la messagerie doit publier la clé publique du sélecteur utilisé (souvent{' '}
              <span className="mono">selector1</span> ou <span className="mono">selector2</span> avec Microsoft 365).
            </div>
          )}
          {data.dmarc.present && <Pill tone="green">DMARC : {data.dmarc.policy}</Pill>}
        </>
      )}
    </>
  )
}
