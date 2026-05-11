// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 deskOTP contributors

import { Component, ErrorInfo, ReactNode } from "react";

interface FallbackProps {
  error: Error;
  resetErrorBoundary: () => void;
}

interface Props {
  fallbackRender: (props: FallbackProps) => ReactNode;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught:", error, info.componentStack);
  }

  resetErrorBoundary = () => {
    this.setState({ error: null });
  };

  render() {
    const { error } = this.state;
    if (error !== null) {
      return this.props.fallbackRender({
        error,
        resetErrorBoundary: this.resetErrorBoundary,
      });
    }
    return this.props.children;
  }
}
