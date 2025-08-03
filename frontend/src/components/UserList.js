// frontend/src/components/UserList.js

import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../utils/api';

function UserList() {
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState('');
  const { token } = useAuth();

  const fetchUsers = useCallback(async () => {
    if (!token) return;
    try {
      const data = await api.get('/api/admin/users', token);
      setUsers(data);
    } catch (error) {
      setMessage(`Error fetching users: ${error.message}`);
    }
  }, [token]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handlePasswordChange = async (userId) => {
    // A modal would be a better UX, but prompt is used for simplicity here.
    const newPassword = prompt('Enter the new password for this user:');
    if (!newPassword) return;

    try {
      const data = await api.put(`/api/admin/users/${userId}/password`, { password: newPassword }, token);
      setMessage(data.message);
    } catch (error) {
      setMessage(`Error updating password: ${error.message}`);
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (window.confirm(`Are you sure you want to delete the user '${username}'?`)) {
      try {
        const data = await api.del(`/api/admin/users/${userId}`, token);
        setMessage(data.message);
        fetchUsers(); // Refresh the user list
      } catch (error) {
        setMessage(`Error deleting user: ${error.message}`);
      }
    }
  };

  return (
    <div className="table-container" style={{ maxWidth: '800px', margin: '20px auto' }}>
      <h3>Existing Users</h3>
      {message && (
        <p className={`form-message ${message.startsWith('Error:') ? 'error' : 'success'}`}>
          {message}
        </p>
      )}
      <table className="table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>{user.username}</td>
              <td>{user.role}</td>
              <td>
                <div className="btn-group">
                  <button onClick={() => handlePasswordChange(user.id)} className="btn btn-secondary">
                    Reset Password
                  </button>
                  <button onClick={() => handleDeleteUser(user.id, user.username)} className="btn btn-danger">
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default UserList;
