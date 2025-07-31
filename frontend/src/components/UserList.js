// frontend/src/components/UserList.js

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

function UserList() {
  const [users, setUsers] = useState([]);
  const [message, setMessage] = useState('');
  const { token } = useAuth();

  const fetchUsers = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/admin/users', {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (response.ok) {
        setUsers(data);
      } else {
        setMessage(`Error: ${data.error}`);
      }
    } catch (error) {
      setMessage('Error fetching users.');
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [token]);

  const handlePasswordChange = async (userId) => {
    const newPassword = prompt('Enter the new password for this user:');
    if (!newPassword) return;

    try {
      const response = await fetch(`http://localhost:5001/api/admin/users/${userId}/password`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ password: newPassword }),
      });
      const data = await response.json();
      setMessage(data.message || `Error: ${data.error}`);
    } catch (error) {
      setMessage('Error updating password.');
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (window.confirm(`Are you sure you want to delete the user '${username}'?`)) {
      try {
        const response = await fetch(`http://localhost:5001/api/admin/users/${userId}`, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await response.json();
        setMessage(data.message || `Error: ${data.error}`);
        // Refresh the user list after deletion
        fetchUsers();
      } catch (error) {
        setMessage('Error deleting user.');
      }
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '20px auto' }}>
      <h3>Existing Users</h3>
      {message && <p style={{ color: message.startsWith('Error:') ? 'red' : 'green' }}>{message}</p>}
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '2px solid #333' }}>
            <th style={{ padding: '10px', textAlign: 'left' }}>Username</th>
            <th style={{ padding: '10px', textAlign: 'left' }}>Role</th>
            <th style={{ padding: '10px', textAlign: 'left' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id} style={{ borderBottom: '1px solid #ddd' }}>
              <td style={{ padding: '10px' }}>{user.username}</td>
              <td style={{ padding: '10px' }}>{user.role}</td>
              <td style={{ padding: '10px' }}>
                <button onClick={() => handlePasswordChange(user.id)} style={{ marginRight: '10px' }}>
                  Reset Password
                </button>
                <button onClick={() => handleDeleteUser(user.id, user.username)} style={{ backgroundColor: '#dc3545', color: 'white' }}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default UserList;
