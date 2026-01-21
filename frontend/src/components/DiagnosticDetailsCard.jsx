import React from 'react';
import './DiagnosticDetailsCard.css';

const DiagnosticDetailsCard = ({ analysis }) => {
  if (!analysis) return null;
  const { layers } = analysis;

  // Generate diagnostic details based on triggered checks
  const generateDiagnosticDetails = () => {
    if (!layers || !Array.isArray(layers)) return [];

    const diagnostics = [];
    
    layers.forEach(layer => {
      if (!layer.checks) return;
      
      Object.entries(layer.checks).forEach(([checkName, checkResult]) => {
        if (checkResult.triggered && checkResult.reason) {
          // Map check names to user-friendly descriptions
          const checkDescriptions = {
            'length': 'URL length anomaly detected',
            'schema': 'Suspicious protocol/schema identified',
            'tld': 'High-risk TLD detected',
            'homograph': 'Homograph attack detected (punycode characters)',
            'depth': 'Excessive subdomain depth',
            'keyword': 'Suspicious keywords found',
            'punycode': 'Punycode encoding detected',
            'chained': 'Chained URL redirection detected',
            'dynamic': 'Dynamic DNS patterns identified',
            'redirect': 'Suspicious redirect parameters'
          };

          const description = checkDescriptions[checkName] || checkName;
          
          diagnostics.push({
            layer: layer.layer,
            pattern: description,
            weight: checkResult.risk_score || 0,
            checkName
          });
        }
      });
    });

    // Sort by weight (highest first)
    diagnostics.sort((a, b) => b.weight - a.weight);

    return diagnostics;
  };

  const diagnostics = generateDiagnosticDetails();
  const totalThreatScore = diagnostics.reduce((sum, diag) => sum + diag.weight, 0);

  if (diagnostics.length === 0) return null;

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
              <th>Weight</th>
            </tr>
          </thead>
          <tbody>
            {diagnostics.map((diagnostic, index) => (
              <tr key={`${diagnostic.checkName}-${index}`}>
                <td className="layer-cell">{diagnostic.layer}</td>
                <td className="pattern-cell">{diagnostic.pattern}</td>
                <td className="weight-cell">{diagnostic.weight.toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      <div className="total-score">
        <div className="total-score-label">Total Threat Score</div>
        <div className="total-score-value">{totalThreatScore.toFixed(2)} / 18.40</div>
      </div>
    </div>
  );
};

export default DiagnosticDetailsCard;
