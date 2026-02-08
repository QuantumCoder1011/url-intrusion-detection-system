import React from 'react';

function Header({ onClearDatabase }) {
  return (
    <header className="header">
      <div className="header-content">
        <h1>🛡️ URL Intrusion Detection System</h1>
        <div className="header-actions">
          <button className="btn btn-danger" onClick={onClearDatabase}>
            Clear Database
          </button>
        </div>
      </div>
    </header>
  );
}

export default Header;
