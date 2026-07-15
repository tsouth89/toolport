import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** When this value changes, a shown error clears itself - so navigating to a
   *  different view recovers instead of leaving the crashed fallback stranded. */
  resetKey?: unknown;
  /** Rendered in place of the children after a caught error. */
  fallback: (error: Error, reset: () => void) => ReactNode;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Catches render/lifecycle throws (and failed `lazy()` imports) in the subtree so one
 * bad component shows a recoverable fallback instead of unmounting the whole app to a
 * blank window - which a desktop user can't just reload away. React error boundaries
 * must be class components; there is no hook equivalent.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("View crashed:", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  private reset = () => this.setState({ error: null });

  render() {
    if (this.state.error) {
      return this.props.fallback(this.state.error, this.reset);
    }
    return this.props.children;
  }
}
