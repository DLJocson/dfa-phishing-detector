import React from 'react';
import './DiagnosticDetailsCard.css';

const DiagnosticDetailsCard = ({ analysis }) => {
  if (!analysis) return null;
  const checkDetails = analysis?.risk_analysis?.breakdown?.check_details || [];
  
  // Use backend's max_score if available, fallback to calculated value
  const maxScore = analysis?.risk_analysis?.max_score ?? 18.40;

  if (!Array.isArray(checkDetails) || checkDetails.length === 0) return null;

  const totalThreatScore = checkDetails.reduce((sum, d) => sum + (d.contribution || 0), 0);

  return (
    <div className="diagnostic-details-card">
      <div className="card-header">
        <h3 className="card-title">Diagnostic Details</h3>
      </div>
      
      <div className="diagnostic-table-container">
        <table className="diagnostic-table">
          <thead>
            <tr>
              <th>DFA Layer</th>
              <th>Pattern Detected</th>
              <th>Base</th>
              <th>×</th>
              <th>Contribution</th>
            </tr>
          </thead>
          <tbody>
            {checkDetails.map((d, index) => (
              <tr key={`${d.layer}-${d.check}-${index}`}>
                <td className="layer-cell">{d.layer}</td>
                <td className="pattern-cell">{d.reason || d.check}</td>
                <td className="weight-cell">{Number(d.raw_score || 0).toFixed(2)}</td>
                <td className="weight-cell">{Number(d.multiplier || 1).toFixed(2)}</td>
                <td className="weight-cell">{Number(d.contribution || 0).toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      <div className="total-score">
        <div className="total-score-label">Total Threat Score</div>
        <div className="total-score-value">{totalThreatScore.toFixed(2)} / {maxScore.toFixed(2)}</div>
      </div>
    </div>
  );
};

export default DiagnosticDetailsCard;
