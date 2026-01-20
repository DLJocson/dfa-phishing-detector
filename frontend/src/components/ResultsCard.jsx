/**
 * Results Card Component: Displays analysis results, risk assessment, and layer details
 * - Layer "What": which checks triggered per DFA layer
 */

import React, { useState } from 'react';
import './ResultsCard.css';


const ResultsCard = ({ analysis }) => {
  const [expandedLayers, setExpandedLayers] = useState({});

  if (!analysis) {
    return null;
  }

  const { layers } = analysis;

  const toggleLayer = (index) => {
    setExpandedLayers((prev) => ({
      ...prev,
      [index]: !(prev[index] ?? true),
    }));
  };

  // Icon map for check types
  const checkIcons = {
    length: '📏',
    schema: '🌐',
    tld: '🗺️',
    homograph: '🔀',
    subdomain: '🏷️',
    punycode: '🔡',
    chained: '⛓️',
    dynamic: '⚡',
    redirect: '➡️',
    default: '✔️',
  };

  const getCheckIcon = (checkName, triggered) => {
    const icon = checkIcons[checkName] || checkIcons.default;
    return (
      <span className={`check-icon ${triggered ? 'triggered' : 'safe'}`}>{icon}</span>
    );
  };

  return (
    <div className="results-container fade-in">
      {/* Layer Analysis (collapsible cards) */}
      <div className="layers-container">
        <h3 className="card-title">DFA Layer Analysis</h3>
        {layers?.map((layer, layerIndex) => {
          const isExpanded = expandedLayers[layerIndex] ?? true;
          // Accent color by layer
          const layerColors = [
            '#2563eb', // Layer 1: blue
            '#a21caf', // Layer 2: purple
            '#ea580c', // Layer 3: orange
          ];
          const borderColor = layerColors[layerIndex] || '#64748b';
          const headerColor = borderColor;

          return (
            <div
              key={layerIndex}
              className={`layer-card layer-depth-${layerIndex + 1} ${!isExpanded ? 'collapsed' : ''}`}
              style={{ borderLeft: `6px solid ${borderColor}` }}
              tabIndex={0}
            >
              <div className="layer-header">
                <div className="layer-header-main">
                  <h4 className="layer-name" style={{ color: headerColor }}>{layer.layer}</h4>
                  <span className="layer-triggers">
                    {layer.triggered_count} / {layer.total_checks} triggered
                  </span>
                </div>
                <button
                  type="button"
                  className="layer-toggle"
                  onClick={() => toggleLayer(layerIndex)}
                  aria-label={isExpanded ? 'Collapse layer details' : 'Expand layer details'}
                >
                  {isExpanded ? '−' : '+'}
                </button>
              </div>
              {isExpanded && (
                <div className="checks-list">
                  {Object.entries(layer.checks || {}).map(([checkName, checkResult]) => (
                    <div
                      key={checkName}
                      className={`check-item ${checkResult.triggered ? 'triggered' : 'safe'}`}
                      style={{ boxShadow: '0 1.5px 6px 0 rgba(16,30,54,0.07)' }}
                    >
                      <div className="check-header">
                        {getCheckIcon(checkName, checkResult.triggered)}
                        <span className="check-name">
                          {checkName.charAt(0).toUpperCase() + checkName.slice(1)}
                        </span>
                      </div>
                      {checkResult.triggered && checkResult.reason && (
                        <div className="check-reason">{checkResult.reason}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ResultsCard;
