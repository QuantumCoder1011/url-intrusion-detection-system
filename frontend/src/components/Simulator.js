import React, { useState } from 'react';
import { simulateAttack } from '../services/api';

function Simulator({ onSimulationComplete }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleSimulate = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await simulateAttack(url);
      setResult(response);
      if (onSimulationComplete) {
        onSimulationComplete();
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Simulation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cyber-card terminal-window" style={{ marginTop: '20px' }}>
      <div className="terminal-header">
        <div className="terminal-btn red"></div>
        <div className="terminal-btn yellow"></div>
        <div className="terminal-btn green"></div>
        <span style={{ marginLeft: '10px', fontSize: '12px', color: '#666' }}>root@ids-gateway:~</span>
      </div>
      
      <div style={{ marginTop: '20px' }}>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '15px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--neon-cyan)' }}>{'>'}</span> INITIATE MANUAL PAYLOAD INJECTION SEQUENCE (BYPASS WAF)
        </p>
        
        <form onSubmit={handleSimulate} style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ color: 'var(--neon-green)', fontFamily: 'var(--font-mono)' }}>$</span>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="enter payload string (e.g. /search?q=' OR 1=1--)"
            style={{
              flex: 1,
              padding: '10px',
              backgroundColor: 'transparent',
              border: 'none',
              borderBottom: '1px solid var(--neon-cyan)',
              color: 'var(--neon-green)',
              outline: 'none',
              boxShadow: 'none',
              borderRadius: '0'
            }}
            disabled={loading}
          />
          <button type="submit" className="btn btn-danger" disabled={loading || !url.trim()} style={{ width: '150px' }}>
            {loading ? 'EXECUTING...' : 'EXECUTE'}
          </button>
        </form>

        {error && <div className="typing-text" style={{ marginTop: '15px', color: 'var(--neon-red)' }}>[!] ERROR: {error}</div>}

        {result && (
          <div style={{
            marginTop: '20px',
            padding: '15px',
            backgroundColor: 'rgba(0,0,0,0.5)',
            border: `1px solid ${result.detection ? 'var(--neon-red)' : 'var(--neon-green)'}`,
            fontFamily: 'var(--font-mono)'
          }}>
            <div className="typing-text" style={{ color: result.detection ? 'var(--neon-red)' : 'var(--neon-green)' }}>
              {'>'} {result.message.toUpperCase()}
            </div>
            
            {result.detection && (
              <ul style={{ marginTop: '10px', marginLeft: '20px', listStyleType: 'square', color: 'var(--text-primary)' }}>
                <li><span style={{ color: 'var(--neon-cyan)' }}>ATTACK_VECTOR:</span> {result.detection.attack_type}</li>
                <li><span style={{ color: 'var(--neon-cyan)' }}>SEVERITY_LEVEL:</span> <span className={`badge badge-${result.detection.severity.toLowerCase()}`}>{result.detection.severity}</span></li>
                <li><span style={{ color: 'var(--neon-cyan)' }}>CONFIDENCE_METRIC:</span> {result.detection.confidence_score}%</li>
                <li><span style={{ color: 'var(--neon-cyan)' }}>DETECTION_ENGINE:</span> {result.detection.detection_source}</li>
                <li><span style={{ color: 'var(--neon-cyan)' }}>PATTERN_MATCH:</span> <span style={{ color: 'var(--neon-red)' }}>{result.detection.pattern_matched}</span></li>
              </ul>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default Simulator;
