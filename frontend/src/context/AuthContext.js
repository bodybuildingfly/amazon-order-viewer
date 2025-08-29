// frontend/src/context/AuthContext.js

import React, { createContext, useState, useContext, useMemo, useCallback } from 'react';
import { jwtDecode } from 'jwt-decode';
import ApiService from '../utils/api'; // Import the new ApiService class

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('authToken'));
  const [userRole, setUserRole] = useState(() => {
    const savedToken = localStorage.getItem('authToken');
    if (savedToken) {
      try {
        const decoded = jwtDecode(savedToken);
        return decoded.role;
      } catch (e) {
        // If token is invalid, remove it
        localStorage.removeItem('authToken');
        return null;
      }
    }
    return null;
  });

  // Memoize the logout function to keep it stable
  const logout = useCallback(() => {
    setToken(null);
    setUserRole(null);
    localStorage.removeItem('authToken');
  }, []);

  // Create a memoized instance of the ApiService
  const api = useMemo(() => new ApiService(logout), [logout]);

  const login = async (username, password) => {
    try {
      // Use the new api service to log in
      const data = await api.post('/api/login', { username, password });
      
      const receivedToken = data.access_token;
      setToken(receivedToken);
      localStorage.setItem('authToken', receivedToken);
      
      const decoded = jwtDecode(receivedToken);
      setUserRole(decoded.role);
      
      return { success: true };
    } catch (error) {
      // The api service now throws an error with the message from the backend
      return { success: false, error: error.message };
    }
  };

  // The context value now includes the api instance
  const value = {
    token,
    userRole,
    isLoggedIn: !!token,
    isAdmin: userRole === 'admin',
    login,
    logout,
    api, // Provide the api service instance through the context
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Custom hook to use the auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
