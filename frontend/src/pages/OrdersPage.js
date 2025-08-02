// frontend/src/pages/OrdersPage.js

import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import OrdersTable from '../components/OrdersTable';

function OrdersPage() {
  const [orders, setOrders] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [days, setDays] = useState(7);
  const [statusMessage, setStatusMessage] = useState('');
  const [progress, setProgress] = useState({ value: 0, max: 100 });
  const { token } = useAuth();

  // State for the Amazon logout button message
  const [logoutMessage, setLogoutMessage] = useState('');
  
  const eventSourceRef = useRef(null);

  // Handler for the Amazon logout button
  const handleForceLogout = async () => {
    setLogoutMessage('Executing command...');
    try {
      const response = await fetch('/api/amazon-logout', { // CHANGED: Use the new endpoint
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      const data = await response.json();
      if (response.ok) {
        const fullMessage = `${data.message}\n\nOutput:\n${data.output || 'No output.'}`;
        setLogoutMessage(fullMessage);
      } else {
        setLogoutMessage(`Error: ${data.error}\n\nDetails:\n${data.details || 'N/A'}`);
      }
    } catch (error) {
      setLogoutMessage('Failed to connect to the server.');
    }
  };

  const handleFetchOrders = () => {
    if (!token) {
      setError('You must be logged in to fetch orders.');
      return;
    }
    
    setError('');
    setIsLoading(true);
    setOrders([]);
    setStatusMessage('Connecting to the server...');
    setProgress({ value: 0, max: 100 });

    // Use a relative path for the EventSource URL
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
  };
  
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
      <div style={{ marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <label htmlFor="days-input">Fetch data for the last</label>
        <input
          id="days-input"
          type="number"
          value={days}
          onChange={(e) => setDays(e.target.value)}
          style={{ width: '80px', padding: '8px' }}
        />
        <label htmlFor="days-input">days</label>
        <button onClick={handleFetchOrders} disabled={isLoading} style={{ padding: '8px 16px' }}>
          {isLoading ? 'Loading...' : 'Load Orders'}
        </button>
      </div>

      {isLoading && (
        <div style={{ padding: '20px', border: '1px solid #eee', borderRadius: '8px' }}>
          <p style={{ fontStyle: 'italic', margin: '0 0 10px 0' }}>Status: {statusMessage}</p>
          <progress value={progress.value} max={progress.max} style={{ width: '50%', height: '25px' }}></progress>
        </div>
      )}
      
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      {!isLoading && !error && <OrdersTable data={orders} />}
      
      <hr style={{ margin: '40px 0' }}/>
      <div style={{ marginTop: '40px' }}>
        <h3>Session Tools</h3>
        <div style={{ padding: '20px', border: '1px solid #eee', borderRadius: '8px', maxWidth: '600px', margin: 'auto' }}>
          <p>If you are having trouble loading orders, you can force a logout of the Amazon session on the server. This will clear any saved cookies and require a fresh login on the next attempt.</p>
          <button 
            onClick={handleForceLogout} 
            style={{ backgroundColor: '#6c757d', color: 'white', padding: '10px 15px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
          >
            Force Amazon Session Logout
          </button>
          {logoutMessage && (
            <pre style={{ 
              marginTop: '20px', 
              whiteSpace: 'pre-wrap', 
              backgroundColor: '#f8f9fa', 
              border: '1px solid #dee2e6', 
              padding: '15px', 
              textAlign: 'left',
              borderRadius: '4px'
            }}>
              {logoutMessage}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

export default OrdersPage;
