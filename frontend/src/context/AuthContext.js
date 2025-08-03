// frontend/src/context/AuthContext.js

import React, { createContext, useState, useContext } from 'react';
import { jwtDecode } from 'jwt-decode';
// ADDED: Import the new api service
import { api } from '../utils/api';

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
        return null;
      }
    }
    return null;
  });

  // CHANGED: Refactored the login function to use the new api service
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
      // The api service now throws an error with the message from the backend
      return { success: false, error: error.message };
    }
  };

  const logout = () => {
    setToken(null);
    setUserRole(null);
    localStorage.removeItem('authToken');
  };

  const value = {
    token,
    userRole,
    isLoggedIn: !!token,
    isAdmin: userRole === 'admin',
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  return useContext(AuthContext);
};
