// frontend/src/components/LoginForm.js

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext'; // Import our custom auth hook

function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const { login } = useAuth(); // Get the login function from our context

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');

    const result = await login(username, password);

    if (result.success) {
      setMessage('Login successful!');
      // In a real app, you would redirect the user here, e.g., navigate('/dashboard')
    } else {
      setMessage(`Error: ${result.error}`);
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '20px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="username" style={{ display: 'block', marginBottom: '5px' }}>Username:</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
          />
        </div>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="password" style={{ display: 'block', marginBottom: '5px' }}>Password:</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
          />
        </div>
        <button type="submit" style={{ width: '100%', padding: '10px', backgroundColor: '#28a745', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
          Login
        </button>
      </form>
      {message && <p style={{ marginTop: '20px', color: message.startsWith('Error:') ? 'red' : 'green' }}>{message}</p>}
    </div>
  );
}

export default LoginForm;
