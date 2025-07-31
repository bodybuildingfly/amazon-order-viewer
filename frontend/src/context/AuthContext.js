// frontend/src/context/AuthContext.js

import React, { createContext, useState, useContext } from 'react';
import { jwtDecode } from 'jwt-decode';

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

  const login = async (username, password) => {
    try {
      // Use a relative path for the API call
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        const receivedToken = data.access_token;
        setToken(receivedToken);
        localStorage.setItem('authToken', receivedToken);
        const decoded = jwtDecode(receivedToken);
        setUserRole(decoded.role);
        return { success: true };
      } else {
        return { success: false, error: data.error };
      }
    } catch (error) {
      return { success: false, error: 'Could not connect to the server.' };
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
