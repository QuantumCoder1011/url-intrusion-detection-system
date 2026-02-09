import React from 'react';

/**
 * Header with icon-only theme toggle. Theme persists in sessionStorage for analyst session continuity.
 * Single title line to avoid duplication; professional academic/industry styling.
 */
function Header({ theme, onThemeToggle }) {
  const isDark = theme === 'dark';
  return (
    <header className="header">
      <div className="header-content">
        <h1 className="header-title">URL-based Intrusion Detection System</h1>
        <button
          type="button"
          className="theme-toggle theme-toggle-icon"
          onClick={onThemeToggle}
          title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
          aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {isDark ? '☀' : '☽'}
        </button>
      </div>
    </header>
  );
}

export default Header;
