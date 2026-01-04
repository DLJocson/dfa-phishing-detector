/**
 * ============================================
 * RESULTS CARD COMPONENT
 * ============================================
 * Displays analysis results, risk assessment, and layer details
 */

import React from 'react';
import './ResultsCard.css';


// ============================================
// RESULTS CARD COMPONENT
// ============================================

const ResultsCard = ({ analysis }) => {
  if (!analysis) {
    return null;
  }

  const { risk_analysis, layers, tokens, hostname_components, summary } = analysis;
  const riskLevel = summary?.risk_level || 'Unknown';
  const riskScore = summary?.risk_score || 0;
  const riskColor = risk_analysis?.risk_color || '#6b7280';

  // ----------------------------------------
  // Helper Functions
  // ----------------------------------------
  
  const getCheckIcon = (triggered) => {
    return triggered ? (
      <span className="check-icon triggered">⚠️</span>
    ) : (
      <span className="check-icon safe">✓</span>
    );
  };

  // ----------------------------------------
  // Render
  // ----------------------------------------
  
  return (
    <div className="results-container">
      {/* Risk Summary Card */}
      <div className="risk-summary-card" style={{ borderLeftColor: riskColor }}>
        <div className="risk-header">
          <h2 className="risk-title">Risk Assessment</h2>
          <div 
            className="risk-badge" 
            style={{ 
              backgroundColor: riskColor,
              color: riskLevel === 'Critical' || riskLevel === 'High' ? 'white' : 'white'
            }}
          >
            {riskLevel}
          </div>
        </div>
        <div className="risk-score">
          <span className="score-label">Risk Score:</span>
          <span className="score-value">{riskScore.toFixed(2)}</span>
        </div>
        <div className="risk-stats">
          <div className="stat-item">
            <span className="stat-label">Checks Triggered:</span>
            <span className="stat-value">{summary?.total_triggered || 0} / {summary?.total_checks || 0}</span>
          </div>
        </div>
      </div>

      {/* URL Tokens */}
      <div className="tokens-card">
        <h3 className="card-title">URL Components</h3>
        <div className="tokens-grid">
          <div className="token-item">
            <span className="token-label">Schema:</span>
            <span className="token-value">{tokens?.schema || 'N/A'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">Hostname:</span>
            <span className="token-value">{tokens?.hostname || 'N/A'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">Domain:</span>
            <span className="token-value">{hostname_components?.domain || 'N/A'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">TLD:</span>
            <span className="token-value">{hostname_components?.tld ? `.${hostname_components.tld}` : 'N/A'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">Subdomain:</span>
            <span className="token-value">{hostname_components?.subdomain || 'None'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">Path:</span>
            <span className="token-value">{tokens?.path || '/'}</span>
          </div>
          <div className="token-item">
            <span className="token-label">Query:</span>
            <span className="token-value">{tokens?.query || 'None'}</span>
          </div>
        </div>
      </div>

      {/* Layer Results */}
      <div className="layers-container">
        <h3 className="card-title">DFA Layer Analysis</h3>
        {layers?.map((layer, layerIndex) => (
          <div key={layerIndex} className="layer-card">
            <div className="layer-header">
              <h4 className="layer-name">{layer.layer}</h4>
              <span className="layer-triggers">
                {layer.triggered_count} / {layer.total_checks} triggered
              </span>
            </div>
            <div className="checks-list">
              {Object.entries(layer.checks || {}).map(([checkName, checkResult]) => (
                <div 
                  key={checkName} 
                  className={`check-item ${checkResult.triggered ? 'triggered' : 'safe'}`}
                >
                  <div className="check-header">
                    {getCheckIcon(checkResult.triggered)}
                    <span className="check-name">{checkName.charAt(0).toUpperCase() + checkName.slice(1)}</span>
                  </div>
                  {checkResult.triggered && checkResult.reason && (
                    <div className="check-reason">{checkResult.reason}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Detailed Breakdown */}
      {risk_analysis?.breakdown?.check_details?.length > 0 && (
        <div className="breakdown-card">
          <h3 className="card-title">Detailed Score Breakdown</h3>
          <div className="breakdown-list">
            {risk_analysis.breakdown.check_details.map((detail, idx) => (
              <div key={idx} className="breakdown-item">
                <div className="breakdown-header">
                  <span className="breakdown-check">{detail.layer} - {detail.check}</span>
                  <span className="breakdown-score">+{detail.score.toFixed(2)}</span>
                </div>
                <div className="breakdown-reason">{detail.reason}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ResultsCard;

