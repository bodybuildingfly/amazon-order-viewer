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
import './components/shared.css';

// A simple navigation component
const Navbar = () => {
  const { isLoggedIn, isAdmin, logout } = useAuth();
  return (
    <nav className="navbar">
      <div className="nav-links">
        <Link to="/">Home</Link>
        {isLoggedIn && <Link to="/orders">Orders</Link>}
        {isLoggedIn && <Link to="/settings">Settings</Link>}
        {isAdmin && <Link to="/admin">Admin</Link>}
        {!isLoggedIn && <Link to="/login">Login</Link>}
        {isLoggedIn && <button onClick={logout} className="logout-button">Logout</button>}
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
