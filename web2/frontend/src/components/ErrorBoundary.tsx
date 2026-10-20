import { Component, ErrorInfo, ReactNode } from 'react'

type Props = { children: ReactNode }
type State = { erreur: Error | null }

// Sans garde-fou, une erreur de rendu vide TOUTE la page (écran noir, aucune
// explication). Ici l'utilisateur voit le message et peut recharger l'écran.
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { erreur: null }

  static getDerivedStateFromError(erreur: Error): State {
    return { erreur }
  }

  componentDidCatch(erreur: Error, infos: ErrorInfo) {
    console.error('Erreur de rendu :', erreur, infos.componentStack)
  }

  render() {
    if (this.state.erreur) {
      return (
        <div className="erreur" style={{ marginTop: 20 }}>
          <b>Cet écran n'a pas pu s'afficher.</b>
          <div style={{ marginTop: 6 }}>{this.state.erreur.message}</div>
          <div style={{ marginTop: 10 }}>
            <button className="btn ghost" onClick={() => { this.setState({ erreur: null }); location.reload() }}>
              Recharger
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
