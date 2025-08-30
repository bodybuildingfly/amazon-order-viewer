// frontend/src/context/AuthContext.js

import React, { createContext, useState, useContext, useMemo, useCallback, useRef, useEffect } from 'react';
import { jwtDecode } from 'jwt-decode';
import ApiService from '../utils/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  // --- Existing Auth State ---
  const [token, setToken] = useState(localStorage.getItem('authToken'));
  const [userRole, setUserRole] = useState(() => {
    const savedToken = localStorage.getItem('authToken');
    if (savedToken) {
      try {
        const decoded = jwtDecode(savedToken);
        return decoded.role;
      } catch (e) {
        localStorage.removeItem('authToken');
        return null;
      }
    }
    return null;
  });

  // --- New Orders State ---
  const [orders, setOrders] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [subStatusMessage, setSubStatusMessage] = useState('');
  const [progress, setProgress] = useState({ value: 0, max: 100 });
  const eventSourceRef = useRef(null);
  const incomingOrdersRef = useRef([]);

  // --- Existing Auth Functions ---
  const logout = useCallback(() => {
    setToken(null);
    setUserRole(null);
    localStorage.removeItem('authToken');
    // Also clear orders data on logout
    setOrders([]);
    setError('');
  }, []);

  const api = useMemo(() => new ApiService(logout), [logout]);

  const login = async (username, password) => {
    try {
      const data = await api.post('/api/login', { username, password });
      const receivedToken = data.access_token;
      setToken(receivedToken);
      localStorage.setItem('authToken', receivedToken);
      const decoded = jwtDecode(receivedToken);
      setUserRole(decoded.role);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  // --- New Orders Fetching Logic ---
  const fetchOrders = useCallback((days, summarize) => {
    if (!token) {
      setError('You must be logged in to fetch orders.');
      return;
    }
    
    setError('');
    setIsLoading(true);
    setOrders([]);
    incomingOrdersRef.current = []; // Reset the buffer
    setStatusMessage('Connecting to the server...');
    setSubStatusMessage('');
    setProgress({ value: 0, max: 100 });

    const url = `/api/orders?days=${days}&summarize=${summarize}&token=${token}`;
    
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
            // Sort the collected orders
            const sortedOrders = [...incomingOrdersRef.current].sort((a, b) => 
              new Date(b.order_placed_date) - new Date(a.order_placed_date)
            );
            // Set the final state
            setOrders(sortedOrders);

            setIsLoading(false);
            setSubStatusMessage('');
            eventSource.close();
          }
          break;
        case 'sub_status':
          setSubStatusMessage(payload);
          break;
        case 'progress_max':
          setProgress(prev => ({ ...prev, max: payload }));
          break;
        case 'progress_update':
          setProgress(prev => ({ ...prev, value: payload }));
          break;
        case 'order_data':
          // Push to the temporary buffer instead of setting state
          incomingOrdersRef.current.push(payload);
          break;
        case 'data': // Keep for backward compatibility or other uses
          setOrders(payload);
          break;
        case 'error':
          setError(payload);
          setIsLoading(false);
          setSubStatusMessage('');
          eventSource.close();
          break;
        default:
          break;
      }
    };

    eventSource.onerror = () => {
      setError('Connection to the server failed. The stream has been closed.');
      setIsLoading(false);
      setSubStatusMessage('');
      eventSource.close();
    };
  }, [token]);

  // --- Effect to clean up EventSource ---
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  // --- Combined Context Value ---
  const value = {
    token,
    userRole,
    isLoggedIn: !!token,
    isAdmin: userRole === 'admin',
    login,
    logout,
    api,
    orders,
    isLoading,
    error,
    statusMessage,
    subStatusMessage,
    progress,
    fetchOrders,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
