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
      'http://account-verification@192.168.100.50/portal/login-recovery-system-authentication-gateway-2024.zip',
      'https://раypаl.login.update.admin.payment.auth.verify.top/secure?password=reset',
      'https://myaccount-53829.no-ip.org/oauth/callback?continue=https://accounts.google.com',
      'https://secure-login.update.сompany.ru',
      'https://gmail-security.verification.settings.com/signin?continue=https://mail.google.com',
      'http://сhase.online.banking.secure.account.xn--verify.login-673849.xyz/auth?redirect=https://chase.com&sessionid=a8k3m9'
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
                Phish {idx + 1}
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
                Safe Ex
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default InputBar;