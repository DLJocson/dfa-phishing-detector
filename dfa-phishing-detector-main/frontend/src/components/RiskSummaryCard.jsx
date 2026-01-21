import React from 'react';
import './RiskSummaryCard.css';

const RiskSummaryCard = ({ analysis }) => {
  if (!analysis) return null;

  const { summary, risk_analysis } = analysis;
  const riskScore = summary?.risk_score ?? 0;
  const totalTriggered = summary?.total_triggered ?? 0;
  const totalChecks = summary?.total_checks ?? 10;
  
  // Layer scores
  const layerScores = risk_analysis?.breakdown?.layer_scores || {};
  const layer1Score = layerScores['Layer 1 (Basic)'] ?? 0;
  const layer2Score = layerScores['Layer 2 (Advanced)'] ?? 0;
  const layer3Score = layerScores['Layer 3 (Threat)'] ?? 0;

  // Constants
  const maxScore = 18.40;
  
  // UPDATED LOGIC: Circle turns Red (#EF4444) if any risk is detected (> 0), otherwise Green (#10B981)
  const riskColor = riskScore > 0 ? '#EF4444' : '#10B981';

  // Calculate Percentage for the Gradient (0 to 100)
  const percentage = Math.min(100, Math.max(0, (riskScore / maxScore) * 100));
  
  // The magic CSS style for the Conic Gradient
  const gaugeStyle = {
    background: `conic-gradient(${riskColor} ${percentage}%, #e2e8f0 0deg)`
  };

  return (
    <div className="risk-summary-card-refactored fade-in">
      
      {/* Left Col: Dynamic Conic Gauge */}
      <div className="conic-gauge" style={gaugeStyle}>
        <div className="gauge-inner-circle">
          {/* Numbers also turn Red if risk detected */}
          <span 
            className="gauge-score-text" 
            style={{ color: riskColor }}
          >
            {Number(riskScore).toFixed(2)}
          </span>
          <span className="gauge-label">Risk Level</span>
        </div>
      </div>

      {/* Right Col: Clean Data Table */}
      <div className="score-breakdown">
        <div className="score-breakdown-title">Score Breakdown</div>
        
        <div className="breakdown-table">
          <div className="breakdown-row">
            <span>Layer 1 (Basic)</span>
            <span className="breakdown-score">{layer1Score}</span>
          </div>
          <div className="breakdown-row">
            <span>Layer 2 (Advanced)</span>
            <span className="breakdown-score">{layer2Score}</span>
          </div>
          <div className="breakdown-row">
            <span>Layer 3 (Threat)</span>
            <span className="breakdown-score">{layer3Score}</span>
          </div>
        </div>

        <div className="risk-stats-footer">
          <div className="stat-row">
            <i className="fas fa-chart-line"></i>
            <span>Score Capacity: {Number(riskScore).toFixed(2)} / {maxScore.toFixed(2)}</span>
          </div>
          <div className="stat-row">
            <i className="fas fa-tasks"></i>
            <span>Checks Triggered: {totalTriggered} / {totalChecks}</span>
          </div>
        </div>
      </div>
      
    </div>
  );
};

export default RiskSummaryCard;