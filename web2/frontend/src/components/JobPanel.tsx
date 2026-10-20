import { Job } from '../api'

const ICONES: Record<string, string> = { ok: '✓', running: '⋯', warn: '!', error: '✕' }

export default function JobPanel({ job, running, error }: { job: Job | null; running: boolean; error: string | null }) {
  if (!job && !running && !error) return null
  return (
    <div className="card" style={{ padding: '4px 20px', marginTop: 14 }}>
      {job && (
        <div className="lrow">
          <span className="lrow-t">{job.label || job.kind}</span>
          <span className="pill gray">{job.elapsed.toFixed(1)} s</span>
          <span className={'pill ' + (job.status === 'done' ? 'green' : job.status === 'error' ? 'red' : 'blue')}>
            {job.status === 'done' ? 'Terminé' : job.status === 'error' ? 'Erreur' : 'En cours'}
          </span>
        </div>
      )}
      <div className="steps">
        {(job?.steps || []).map((step, index) => (
          <div className="step" key={index}>
            <span className={'dot ' + (step.status === 'ok' ? 'ok' : step.status === 'running' ? 'run' : step.status === 'warn' ? 'warn' : 'error')}>
              {ICONES[step.status] || '·'}
            </span>
            <div className="lbl"><b>{step.label}</b><span>{step.detail}</span></div>
            <span className="dur">{step.ts.toFixed(1)} s</span>
          </div>
        ))}
        {running && !(job?.steps || []).length && (
          <div className="step"><span className="dot run">⋯</span>
            <div className="lbl"><b>Démarrage…</b><span>Envoi de la demande au moteur</span></div>
            <span className="dur" /></div>
        )}
      </div>
      {error && <div className="erreur">{error}</div>}
      {job?.status === 'error' && <div className="erreur">{job.error}</div>}
    </div>
  )
}
