import { ReactNode } from 'react'

export function Pill({ tone, children }: { tone: 'green' | 'amber' | 'red' | 'blue' | 'gray'; children: ReactNode }) {
  return <span className={'pill ' + tone}>{children}</span>
}

export function Section({ titre, compte, children }: { titre: string; compte?: ReactNode; children: ReactNode }) {
  return (
    <>
      <h3 className="sect">{titre}{compte ? <span className="sect-count">{compte}</span> : null}</h3>
      {children}
    </>
  )
}

export function Kpi({ ico, valeur, libelle, periode }: { ico: string; valeur: ReactNode; libelle: string; periode?: string }) {
  return (
    <div className="card">
      <div className="kpi-ico">{ico}</div>
      <div className="kpi-num">{valeur}</div>
      <div className="kpi-lbl">{libelle}</div>
      {periode && <div className="kpi-period">{periode}</div>}
    </div>
  )
}

export function Ligne({ titre, valeur, ton }: { titre: string; valeur: ReactNode; ton?: 'green' | 'amber' | 'red' | 'blue' | 'gray' }) {
  return (
    <div className="lrow">
      <span className="lrow-t">{titre}</span>
      <span className="mono">{valeur}</span>
      {ton ? <Pill tone={ton}>{ton === 'green' ? 'OK' : ton === 'amber' ? 'à vérifier' : ton === 'red' ? 'critique' : ''}</Pill> : null}
    </div>
  )
}

export function Vide({ children }: { children: ReactNode }) {
  return <p className="muted" style={{ fontSize: 13, marginTop: 12 }}>{children}</p>
}

// Un « detail » venu du moteur peut être un objet (résumé TLS) : le rendre tel
// quel fait planter React (erreur #31, objet affiché comme enfant).
export function texte(valeur: unknown): string {
  if (valeur === null || valeur === undefined) return '—'
  if (typeof valeur === 'string') return valeur
  if (typeof valeur === 'number' || typeof valeur === 'boolean') return String(valeur)
  return JSON.stringify(valeur)
}

export function dateFr(valeur: string | null | undefined): string {
  if (!valeur) return '—'
  const date = new Date(valeur)
  if (Number.isNaN(date.getTime())) return valeur
  return date.toLocaleDateString('fr-FR')
}
