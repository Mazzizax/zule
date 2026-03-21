import React from 'react';

const DEV_ACCESS_ENABLED = false;

export default function Developer() {
  if (!DEV_ACCESS_ENABLED) {
    return (
      <div className="page-container">
        <div className="page-header">
          <h1>Developer Access</h1>
        </div>
        <div className="card">
          <p style={{ marginBottom: '16px' }}>
            Developer access requires approval. To request access, reach out to us.
          </p>
          <a
            href="https://mazzizax.org/contact"
            className="btn-primary"
            style={{ display: 'inline-block', textDecoration: 'none' }}
          >
            Request Developer Access
          </a>
        </div>
      </div>
    );
  }

  return null;
}
