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
  
  // Risk Level Classification
  const getRiskLevel = (score) => {
    if (score >= 0.00 && score <= 2.00) return { level: 'Low', color: '#06B6D4' };
    if (score >= 2.01 && score <= 6.00) return { level: 'Medium', color: '#EAB308' };
    if (score >= 6.01 && score <= 12.00) return { level: 'High', color: '#F97316' };
    if (score >= 12.01 && score <= 18.40) return { level: 'Critical', color: '#991B1B' };
    return { level: 'Unknown', color: '#6B7280' };
  };

  // Classification Labels
  const getClassification = (score) => {
    if (score >= 0.00 && score <= 1.00) return { label: 'Benign', color: '#22C55E' };
    if (score >= 1.01 && score <= 5.00) return { label: 'Suspicious', color: '#FACC15' };
    if (score >= 5.01) return { label: 'Malicious', color: '#EF4444' };
    return { label: 'Unknown', color: '#6B7280' };
  };

  const riskLevelInfo = getRiskLevel(riskScore);
  const classificationInfo = getClassification(riskScore);
  
  // Use classification color for the gauge (more prominent)
  const gaugeColor = classificationInfo.color;

  // Calculate Percentage for the Gradient (0 to 100)
  const percentage = Math.min(100, Math.max(0, (riskScore / maxScore) * 100));
  
  // The magic CSS style for the Conic Gradient
  const gaugeStyle = {
    background: `conic-gradient(${gaugeColor} ${percentage}%, #e2e8f0 0deg)`
  };

  return (
    <div className="risk-summary-card-refactored fade-in">
      
      {/* Left Col: Dynamic Conic Gauge */}
      <div className="conic-gauge" style={gaugeStyle}>
        <div className="gauge-inner-circle">
          {/* Numbers also use classification color */}
          <span 
            className="gauge-score-text" 
            style={{ color: gaugeColor }}
          >
            {Number(riskScore).toFixed(2)}
          </span>
          <span className="gauge-label">Risk Level</span>
        </div>
      </div>

      {/* Right Col: Clean Data Table */}
      <div className="score-breakdown">
        <div className="score-breakdown-title">Score Breakdown</div>
        
        {/* Risk Level and Classification Labels */}
        <div className="risk-labels">
          <div className="risk-label-item">
            <span className="risk-label-text">Risk Level:</span>
            <span 
              className="risk-label-value" 
              style={{ color: riskLevelInfo.color }}
            >
              {riskLevelInfo.level}
            </span>
          </div>
          <div className="risk-label-item">
            <span className="risk-label-text">Classification:</span>
            <span 
              className="risk-label-value" 
              style={{ color: classificationInfo.color }}
            >
              {classificationInfo.label}
            </span>
          </div>
        </div>
        
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