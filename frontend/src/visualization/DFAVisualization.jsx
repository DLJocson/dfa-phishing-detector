/**
 * DFA Visualization Component: Visual representation of DFA state transitions
 */

import React from 'react';
import './DFAVisualization.css';

const DFAVisualization = ({ analysis }) => {
  // Layer name mapping to ensure consistent labeling
  const getLayerDisplayName = (layerName) => {
    const layerMappings = {
      'Layer 1': 'Layer 1 (Basic)',
      'Layer 2': 'Layer 2 (Advanced)',
      'Layer 3': 'Layer 3 (Threat)',
    };
    return layerMappings[layerName] || layerName;
  };

  if (!analysis || !analysis.layers || !Array.isArray(analysis.layers)) {
    return (
      <div className="dfa-visualization-container">
        <h3 className="viz-title">DFA State Transitions</h3>
        <div className="no-data">
          <p>No analysis data available. Please analyze a URL to see DFA state transitions.</p>
        </div>
      </div>
    );
  }

  const { layers } = analysis;

  const renderLayerStates = (layer, layerIndex) => {
    const checks = Object.entries(layer.checks || {});
    const triggeredChecks = checks.filter(([_, check]) => check.triggered);
    const firstTriggeredIndex = checks.findIndex(([_, check]) => check?.triggered);
    
    return (
      <div
        key={layerIndex}
        className="dfa-layer-viz"
        style={{ "--layer-index": layerIndex }}
      >
        <div className="dfa-layer-header">
          <h4>{getLayerDisplayName(layer.layer)}</h4>
          <div className="layer-status">
            <span className={`status-indicator ${triggeredChecks.length > 0 ? 'active' : 'inactive'}`}>
              {triggeredChecks.length > 0 ? '●' : '○'}
            </span>
            <span>{triggeredChecks.length} of {checks.length} checks triggered</span>
          </div>
        </div>
        
        <div className="dfa-states">
          <div className="dfa-state initial">
            <div className="state-label">Start</div>
          </div>
          
          {checks.map(([checkName, checkResult], checkIndex) => {
            // Layout Logic: subsequent checks appear "skipped" if a threat is detected
            const isSkipped = firstTriggeredIndex >= 0 && checkIndex > firstTriggeredIndex;
            const stateClass = isSkipped
              ? 'skipped'
              : checkResult.triggered
                ? 'accept-triggered'
                : 'accept-safe';

            return (
              <React.Fragment key={checkIndex}>
                <div className="dfa-transition">
                  <div className="transition-line"></div>
                  <div className="transition-label">{checkName}</div>
                </div>
                <div className={`dfa-state ${stateClass}`}>
                  <div className="state-label">{checkName}</div>
                  {!isSkipped && checkResult.triggered && (
                    <div className="state-indicator triggered">⚠</div>
                  )}
                  {!isSkipped && !checkResult.triggered && (
                    <div className="state-indicator safe">✓</div>
                  )}
                  {isSkipped && (
                    <div className="state-indicator skipped">↷</div>
                  )}
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div className="dfa-visualization-container">
      <h3 className="viz-title">DFA State Transitions</h3>
      <div className="dfa-layers-viz">
        {layers.map((layer, index) => renderLayerStates(layer, index))}
      </div>
      
      <div className="legend">
        <div className="legend-item">
          <span className="legend-icon start">●</span>
          <span>Start</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon safe">✓</span>
          <span>Safe Check Passed</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon triggered">⚠</span>
          <span>Threat Detected</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon skipped">↷</span>
          <span>Skipped</span>
        </div>
      </div>
    </div>
  );
};

export default DFAVisualization;
