// frontend/src/pages/AdminPage.js

import React from 'react';
import CreateUserForm from '../components/CreateUserForm';
import UserList from '../components/UserList';

function AdminPage() {
  return (
    <div>
      <h2>Admin Panel</h2>
      
      {/* This section adds the "Create New User" form back to the page */}
      <div style={{ marginBottom: '40px' }}>
        <h3>Create New User</h3>
        <CreateUserForm />
      </div>
      
      <hr />
      
      {/* This is the existing user list */}
      <UserList />
    </div>
  );
}

export default AdminPage;