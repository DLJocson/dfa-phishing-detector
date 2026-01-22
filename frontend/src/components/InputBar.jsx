/**
 * Input Bar Component: URL input form with Quick Action Chips
 */
import React, { useState } from 'react';
import './InputBar.css';

const InputBar = ({ onAnalyze, isLoading }) => {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handleChipClick = (value) => {
    setUrl(value);
    // Optional: Auto-analyze on click
    // onAnalyze(value); 
  };

  const exampleUrls = {
    suspicious: [
      'http://sub1.sub2.sub3.suspicious-domain-name-with-excessive-hyphens.xyz/login/verify/account/details/update/secure/ref/123456789',
      'https://xn--login.secure.update.paypаl.com',
      'https://server12345.com/click?id=1&u=2&s=3&t=4&m=5&redirect=http://evil.com',
      'http://xn--secure-login.update12345.ru/verify?dest=http://phish.com',
      'ftp://a.b.c.paypаl.tk/limit?q=http://bad.com'
    ],
    benign: [
      'https://www.google.com'
    ],
  };

  return (
    <div className="input-bar-container">
      {/* WRAPPER CARD */}
      <div className="input-card">
        <h3 className="card-title">URL Insertion</h3>
        
        <form onSubmit={handleSubmit} className="input-form">
          <div className="input-wrapper">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to analyze..."
              className="url-input"
              disabled={isLoading}
            />
            <button
              type="submit"
              className={`analyze-button${isLoading ? ' loading' : ''}`}
              disabled={isLoading || !url.trim()}
              aria-busy={isLoading}
            >
              {isLoading ? (
                <>
                  <span className="spinner" aria-hidden="true"></span>
                  Analyzing...
                </>
              ) : 'Analyze'}
            </button>
          </div>
        </form>

        {/* NEW: Action Chips Section */}
        <div className="quick-action-section">
          <span className="action-label">Quick Load:</span>
          
          <div className="chips-container">
            {/* Suspicious Chips */}
            {exampleUrls.suspicious.map((exUrl, idx) => (
              <button 
                key={`sus-${idx}`}
                onClick={() => handleChipClick(exUrl)}
                className="action-chip chip-suspicious"
                type="button"
                disabled={isLoading}
              >
                Phish Ex {idx + 1}
              </button>
            ))}

            {/* Separator */}
            <div className="chip-separator"></div>

            {/* Benign Chips */}
            {exampleUrls.benign.map((exUrl, idx) => (
              <button 
                key={`ben-${idx}`}
                onClick={() => handleChipClick(exUrl)}
                className="action-chip chip-benign"
                type="button"
                disabled={isLoading}
              >
                Safe Ex {idx + 1}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default InputBar;