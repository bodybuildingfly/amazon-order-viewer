// frontend/src/context/AuthContext.js

import React, { createContext, useState, useContext } from 'react';
import { jwtDecode } from 'jwt-decode'; // We need to install this package

// Create the context
const AuthContext = createContext(null);

// Create the AuthProvider component
export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('authToken'));
  // Add state for the user's role
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

  // The login function that will be called from our LoginForm
  const login = async (username, password) => {
    try {
      const response = await fetch('http://localhost:5001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        const receivedToken = data.access_token;
        setToken(receivedToken);
        localStorage.setItem('authToken', receivedToken);

        // Decode the token to get the user's role
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

  // The logout function
  const logout = () => {
    setToken(null);
    setUserRole(null); // Clear the role on logout
    localStorage.removeItem('authToken');
  };

  // The value provided to the children components
  const value = {
    token,
    userRole, // Expose the role
    isLoggedIn: !!token,
    isAdmin: userRole === 'admin', // Add a convenience flag for admin checks
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// A custom hook to easily use the AuthContext in other components
export const useAuth = () => {
  return useContext(AuthContext);
};
