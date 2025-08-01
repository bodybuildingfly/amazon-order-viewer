// frontend/src/App.js

import React from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import SettingsPage from './pages/SettingsPage';
import OrdersPage from './pages/OrdersPage';
import AdminPage from './pages/AdminPage';
import ProtectedRoute from './components/ProtectedRoute';
import AdminRoute from './components/AdminRoute';
import { useAuth } from './context/AuthContext';
import './App.css';

const API_URL = process.env.REACT_APP_API_BASE_URL || '';

// A simple navigation component
const Navbar = () => {
  const { isLoggedIn, isAdmin, logout, token } = useAuth();

  const handleForceLogout = async () => {
    alert("Attempting to force logout any active Amazon session. Please wait...");
    try {
      const response = await fetch(`${API_URL}/api/amazon/force-logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      alert(data.message || "Request sent.");
    } catch (error) {
      alert("Failed to send force logout request.");
    }
  };

  return (
    <nav style={{ padding: '10px', borderBottom: '1px solid #ccc', marginBottom: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div style={{ flex: 1 }}>
        {/* Intentionally empty to push center content */}
      </div>
      <div style={{ flex: 1, textAlign: 'center' }}>
        <Link to="/" style={{ marginRight: '15px' }}>Home</Link>
        {isLoggedIn && <Link to="/orders" style={{ marginRight: '15px' }}>Orders</Link>}
        {isLoggedIn && <Link to="/settings" style={{ marginRight: '15px' }}>Settings</Link>}
        {isAdmin && <Link to="/admin" style={{ marginRight: '15px' }}>Admin</Link>}
        {!isLoggedIn && <Link to="/login" style={{ marginRight: '15px' }}>Login</Link>}
      </div>
      <div style={{ flex: 1, textAlign: 'right' }}>
        {isLoggedIn && <button onClick={handleForceLogout} style={{ marginRight: '15px', backgroundColor: '#ffc107' }}>Force Amazon Logout</button>}
        {isLoggedIn && <button onClick={logout}>Logout</button>}
      </div>
    </nav>
  );
};

function App() {
  const { isLoggedIn } = useAuth();

  return (
    <div className="App">
      <header className="App-header">
        <h1>Amazon Order Viewer</h1>
      </header>
      <Navbar />
      <main>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          
          <Route 
            path="/settings" 
            element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} 
          />
          
          <Route 
            path="/orders" 
            element={<ProtectedRoute><OrdersPage /></ProtectedRoute>} 
          />
          
          <Route 
            path="/admin" 
            element={<AdminRoute><AdminPage /></AdminRoute>} 
          />

          <Route path="/" element={
            isLoggedIn ? <h2>Welcome back!</h2> : <h2>Welcome! Please log in.</h2>
          } />
        </Routes>
      </main>
    </div>
  );
}

export default App;
