// frontend/src/components/ProtectedRoute.js

import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// This component wraps our protected routes.
// It receives the component to render as its 'children'.
function ProtectedRoute({ children }) {
  const { isLoggedIn } = useAuth();

  if (!isLoggedIn) {
    // If the user is not logged in, redirect them to the /login page.
    // The 'replace' prop is used to prevent the user from navigating back
    // to the protected route after being redirected.
    return <Navigate to="/login" replace />;
  }

  // If the user is logged in, render the child component that was passed in.
  return children;
}

export default ProtectedRoute;
