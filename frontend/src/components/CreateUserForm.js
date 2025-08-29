// frontend/src/components/CreateUserForm.js

import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

function CreateUserForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [message, setMessage] = useState('');
  const { token, api } = useAuth();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');

    try {
      const data = await api.post('/api/admin/create-user', { username, password, role }, token);
      setMessage(data.message);
      setUsername('');
      setPassword('');
      setRole('user');
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="create-username" className="form-label">Username:</label>
          <input
            type="text"
            id="create-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            className="form-input"
          />
        </div>
        <div className="form-group">
          <label htmlFor="create-password" className="form-label">Password:</label>
          <input
            type="password"
            id="create-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="form-input"
          />
        </div>
        <div className="form-group">
          <label htmlFor="create-role" className="form-label">Role:</label>
          <select id="create-role" value={role} onChange={(e) => setRole(e.target.value)} className="form-select">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <button type="submit" className="btn btn-primary">
          Create User
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

export default CreateUserForm;
