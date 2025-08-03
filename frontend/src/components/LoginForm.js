// frontend/src/components/LoginForm.js

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');

    const result = await login(username, password);

    if (result.success) {
      setMessage('Login successful!');
      // In a real app, you would redirect the user here.
    } else {
      setMessage(`Error: ${result.error}`);
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username" className="form-label">Username:</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="form-input"
          />
        </div>
        <div className="form-group">
          <label htmlFor="password" className="form-label">Password:</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="form-input"
          />
        </div>
        <button type="submit" className="btn btn-success">
          Login
        </button>
      </form>
      {message && (
        <p className={`form-message ${message.startsWith('Error:') ? 'error' : 'success'}`}>
          {message}
        </p>
      )}
    </div>
  );
}

export default LoginForm;
