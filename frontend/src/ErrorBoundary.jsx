import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('AgentShield Frontend Error:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#0b1728',
          color: '#f8fafc',
          fontFamily: 'Inter, system-ui, sans-serif',
          padding: '24px',
        }}>
          <div style={{
            maxWidth: '560px',
            width: '100%',
            backgroundColor: '#0f233d',
            border: '1px solid #1e3a5f',
            borderRadius: '12px',
            padding: '28px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px', color: '#f87171' }}>
              <AlertTriangle size={28} />
              <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
                AgentShield UI Encountered an Error
              </h2>
            </div>
            <p style={{ fontSize: '13px', color: '#94a3b8', lineHeight: 1.6, margin: '0 0 16px' }}>
              A client-side error occurred while rendering the dashboard. Please ensure the AgentShield backend is running on port 8000 and click below to reload.
            </p>
            {this.state.error?.message && (
              <pre style={{
                backgroundColor: '#071526',
                border: '1px solid #162c46',
                borderRadius: '8px',
                padding: '12px',
                fontSize: '12px',
                color: '#e2e8f0',
                overflowX: 'auto',
                marginBottom: '20px',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}>
                {this.state.error.message}
              </pre>
            )}
            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={this.handleReset}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '10px 18px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <RefreshCw size={15} /> Reload Application
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
