// frontend/src/pages/OrdersPage.js

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import OrdersTable from '../components/OrdersTable';

function OrdersPage() {
  const [orders, setOrders] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [days, setDays] = useState(7);
  const [statusMessage, setStatusMessage] = useState('');
  const [progress, setProgress] = useState({ value: 0, max: 100 });
  const { token, api } = useAuth();
  
  const [logoutMessage, setLogoutMessage] = useState('');
  
  const eventSourceRef = useRef(null);

  const handleForceLogout = async () => {
    setLogoutMessage('Executing command...');
    try {
      const data = await api.post('/api/amazon-logout', {}, token);
      const fullMessage = `${data.message}\n\nOutput:\n${data.output || 'No output.'}`;
      setLogoutMessage(fullMessage);
    } catch (error) {
      setLogoutMessage(`Error: ${error.message}`);
    }
  };

  const handleFetchOrders = useCallback(() => {
    if (!token) {
      setError('You must be logged in to fetch orders.');
      return;
    }
    
    setError('');
    setIsLoading(true);
    setOrders([]);
    setStatusMessage('Connecting to the server...');
    setProgress({ value: 0, max: 100 });

    const url = `/api/orders?days=${days}&token=${token}`;
    
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const eventSource = new EventSource(url);
    eventSourceRef.current = eventSource;

    eventSource.onopen = () => {
      setStatusMessage('Connection established. Starting data fetch...');
    };

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      const payload = data.payload;

      switch (data.type) {
        case 'status':
          setStatusMessage(payload);
          if (payload === 'Done.') {
            setIsLoading(false);
            eventSource.close();
          }
          break;
        case 'progress_max':
          setProgress(prev => ({ ...prev, max: payload }));
          break;
        case 'progress_update':
          setProgress(prev => ({ ...prev, value: payload }));
          break;
        case 'data':
          setOrders(payload);
          break;
        case 'error':
          setError(payload);
          setIsLoading(false);
          eventSource.close();
          break;
        default:
          break;
      }
    };

    eventSource.onerror = () => {
      setError('Connection to the server failed. The stream has been closed.');
      setIsLoading(false);
      eventSource.close();
    };
  }, [token, days]);
  
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

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
        />
        <span>days</span>
        <button 
          onClick={handleFetchOrders} 
          disabled={isLoading} 
          className="btn btn-primary"
          style={{ width: 'auto' }}
        >
          {isLoading ? 'Loading...' : 'Load'} 
        </button>
      </div>

      {isLoading && (
        <div className="status-container">
          <p className="status-message">Status: {statusMessage}</p>
          <progress value={progress.value} max={progress.max} className="progress-bar"></progress>
        </div>
      )}
      
      {error && <p className="form-message error">Error: {error}</p>}
      {!isLoading && !error && <OrdersTable data={orders} />}

      <hr style={{ margin: '40px 0', border: 'none', borderTop: '1px solid var(--border-color)' }}/>
      
      <div className="session-tools-container">
        <h3>Session Tools</h3>
        <p>If you are having trouble loading orders, you can force a logout of the Amazon session on the server. This will clear any saved cookies and require a fresh login on the next attempt.</p>
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
