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

  // Constants - use backend's max_score if available, fallback to calculated value
  const maxScore = risk_analysis?.max_score ?? 18.40;
  
  // Unified Risk Classification - use backend's risk_level directly
  const getRiskClassification = (score, backendRiskLevel) => {
    // Use backend's risk_level if available, fallback to score-based classification
    if (backendRiskLevel) {
      const riskMap = {
        'Benign': { level: 'Benign', color: '#22C55E', description: 'Safe URL' },
        'Low': { level: 'Low', color: '#3B82F6', description: 'Minimal risk' },
        'Medium': { level: 'Medium', color: '#F59E0B', description: 'Moderate risk' },
        'High': { level: 'High', color: '#EF4444', description: 'High risk' },
        'Critical': { level: 'Critical', color: '#991B1B', description: 'Severe threat' }
      };
      return riskMap[backendRiskLevel] || { level: 'Unknown', color: '#6B7280', description: 'Unable to classify' };
    }
    
    // Fallback to score-based classification
    if (score <= 0.0) return { level: 'Benign', color: '#22C55E', description: 'Safe URL' };
    if (score <= 2.0) return { level: 'Low', color: '#3B82F6', description: 'Minimal risk' };
    if (score <= 6.0) return { level: 'Medium', color: '#F59E0B', description: 'Moderate risk' };
    if (score <= 12.0) return { level: 'High', color: '#EF4444', description: 'High risk' };
    return { level: 'Critical', color: '#991B1B', description: 'Severe threat' };
  };

  const riskClassificationInfo = getRiskClassification(riskScore, risk_analysis?.risk_level);
  
  // Use classification color for the gauge
  const gaugeColor = riskClassificationInfo.color;

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
            {percentage.toFixed(0)}%
          </span>
          <span className="gauge-label">Risk Level</span>
        </div>
      </div>

      {/* Right Col: Clean Data Table */}
      <div className="score-breakdown">
        <div className="score-breakdown-title">Score Breakdown</div>
        
        {/* Unified Risk Classification Display */}
        <div className="risk-labels">
          <div className="risk-label-item">
            <span className="risk-label-text">Risk Level:</span>
            <span 
              className="risk-label-value" 
              style={{ color: riskClassificationInfo.color }}
            >
              {riskClassificationInfo.level}
            </span>
          </div>
          <div className="risk-label-item">
            <span className="risk-label-text">Description:</span>
            <span 
              className="risk-label-value" 
              style={{ color: riskClassificationInfo.color }}
            >
              {riskClassificationInfo.description}
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