// frontend/src/components/AdminRoute.js

import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function AdminRoute({ children }) {
  const { isLoggedIn, isAdmin } = useAuth();

  if (!isLoggedIn) {
    // If not logged in, redirect to login
    return <Navigate to="/login" replace />;
  }

  if (!isAdmin) {
    // If logged in but not an admin, redirect to the home page
    return <Navigate to="/" replace />;
  }

  // If logged in and is an admin, render the child component
  return children;
}

export default AdminRoute;
