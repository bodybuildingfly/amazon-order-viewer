// frontend/src/pages/OrdersPage.js

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import OrdersTable from '../components/OrdersTable';

function OrdersPage() {
  const {
    api,
    token,
    orders,
    isLoading,
    error,
    statusMessage,
    subStatusMessage,
    progress,
    fetchOrders,
  } = useAuth();

  // Local state for form inputs
  const [days, setDays] = useState(7);
  const [summarize, setSummarize] = useState(true);
  
  // Local state for the session tools section
  const [logoutMessage, setLogoutMessage] = useState('');

  const handleForceLogout = async () => {
    setLogoutMessage('Executing command...');
    try {
      const data = await api.post('/api/amazon-logout', {}, token);
      const fullMessage = `${data.message}\n\nOutput:\n${data.output || 'No output.'}`;
      setLogoutMessage(fullMessage);
    } catch (err) {
      setLogoutMessage(`Error: ${err.message}`);
    }
  };

  const handleFetchClick = () => {
    fetchOrders(days, summarize);
  };

  return (
    <div>
      <h2>Your Amazon Orders & Transactions</h2>
      <div className="controls-container">
        <span>Fetch orders from the last:</span>
        <input
          type="number"
          value={days}
          onChange={(e) => setDays(parseInt(e.target.value, 10))}
          className="form-input"
          style={{ width: '80px', textAlign: 'center' }}
          disabled={isLoading}
        />
        <span>days</span>

        <div className="summarize-toggle" style={{ display: 'flex', alignItems: 'center', marginLeft: '20px' }}>
          <input
            type="checkbox"
            id="summarize-toggle"
            checked={summarize}
            onChange={(e) => setSummarize(e.target.checked)}
            style={{ margin: '0 5px 0 0', transform: 'scale(1.2)' }}
            disabled={isLoading}
          />
          <label htmlFor="summarize-toggle" style={{ cursor: 'pointer' }}>Summarize Titles</label>
        </div>

        <button 
          onClick={handleFetchClick} 
          disabled={isLoading} 
          className="btn btn-primary"
          style={{ width: 'auto', marginLeft: 'auto' }}
        >
          {isLoading ? 'Loading...' : 'Load Orders'} 
        </button>
      </div>

      {isLoading && (
        <div className="status-container">
          <p className="status-message">Status: {statusMessage}</p>
          <progress value={progress.value} max={progress.max} className="progress-bar"></progress>
          {subStatusMessage && <p className="sub-status-message" style={{textAlign: 'center', fontStyle: 'italic', marginTop: '5px'}}>{subStatusMessage}</p>}
        </div>
      )}
      
      {error && <p className="form-message error">Error: {error}</p>}
      
      {!isLoading && orders.length === 0 && !error && (
        <p style={{ textAlign: 'center', marginTop: '20px' }}>
          No orders loaded. Use the controls above to fetch your orders.
        </p>
      )}

      {orders.length > 0 && <OrdersTable data={orders} />}

      <hr style={{ margin: '40px 0', border: 'none', borderTop: '1px solid var(--border-color)' }}/>
      
      <div className="session-tools-container">
        <h3>Session Tools</h3>
        <p>
          If you are having trouble loading orders, you can force a logout of the Amazon session on the server. 
          This will clear any saved cookies and require a fresh login on the next attempt.
        </p>
        <button onClick={handleForceLogout} className="btn btn-secondary">
          Force Amazon Session Logout
        </button>
        {logoutMessage && (
          <pre className="output-box">
            {logoutMessage}
          </pre>
        )}
      </div>
    </div>
  );
}

export default OrdersPage;
