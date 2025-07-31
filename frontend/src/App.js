// frontend/src/App.js

import React from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import SettingsPage from './pages/SettingsPage';
import OrdersPage from './pages/OrdersPage';
import AdminPage from './pages/AdminPage'; // Import the new Admin Page
import ProtectedRoute from './components/ProtectedRoute';
import AdminRoute from './components/AdminRoute'; // Import the new AdminRoute
import { useAuth } from './context/AuthContext';
import './App.css';

// A simple navigation component
const Navbar = () => {
  const { isLoggedIn, isAdmin, logout } = useAuth();
  return (
    <nav style={{ padding: '10px', borderBottom: '1px solid #ccc', marginBottom: '20px' }}>
      <Link to="/" style={{ marginRight: '15px' }}>Home</Link>
      {isLoggedIn && <Link to="/orders" style={{ marginRight: '15px' }}>Orders</Link>}
      {isLoggedIn && <Link to="/settings" style={{ marginRight: '15px' }}>Settings</Link>}
      {isAdmin && <Link to="/admin" style={{ marginRight: '15px' }}>Admin</Link>}
      {!isLoggedIn && <Link to="/login" style={{ marginRight: '15px' }}>Login</Link>}
      {isLoggedIn && <button onClick={logout}>Logout</button>}
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
          
          {/* This is our new admin-only route */}
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
