/**
 * DFA Visualization Component: Visual representation of DFA state transitions
 */

import React from 'react';
import './DFAVisualization.css';


const DFAVisualization = ({ analysis }) => {
  if (!analysis || !analysis.layers) {
    return null;
  }

  const { layers } = analysis;

  const renderLayerStates = (layer, layerIndex) => {
    const checks = Object.entries(layer.checks || {});
    const triggeredChecks = checks.filter(([_, check]) => check.triggered);
    
    return (
      <div
  key={layerIndex}
  className="dfa-layer-viz"
  style={{ "--layer-index": layerIndex }}
>

        <div className="dfa-layer-header">
          <h4>{layer.layer}</h4>
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
          
          {checks.map(([checkName, checkResult], checkIndex) => (
            <React.Fragment key={checkIndex}>
              <div className="dfa-transition">
                <div className="transition-line"></div>
                <div className="transition-label">{checkName}</div>
              </div>
              <div className={`dfa-state ${checkResult.triggered ? 'accept-triggered' : 'accept-safe'}`}>
                <div className="state-label">{checkName}</div>
                {checkResult.triggered && (
                  <div className="state-indicator triggered">⚠</div>
                )}
                {!checkResult.triggered && (
                  <div className="state-indicator safe">✓</div>
                )}
              </div>
            </React.Fragment>
          ))}
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
          <span className="legend-icon safe">✓</span>
          <span>Safe Check Passed</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon triggered">⚠</span>
          <span>Threat Detected</span>
        </div>
      </div>
    </div>
  );
};

export default DFAVisualization;
