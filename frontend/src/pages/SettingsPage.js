// frontend/src/pages/SettingsPage.js
import React from 'react';
import SettingsForm from '../components/SettingsForm';

function SettingsPage() {
  const handleLogout = async () => {
    try {
      const response = await fetch('/api/logout', {
        method: 'POST'
      });
      if (!response.ok) {
        throw new Error('Failed to log out');
      }
      // Clear any local storage or cookies here
      sessionStorage.clear();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  return (
    <div>
      <h2>User Settings</h2>
      <p>Configure your Amazon credentials here. The password is write-only and will not be displayed.</p>
      <SettingsForm />
      <button onClick={handleLogout}>Log Out of Amazon</button>
    </div>
  );
}

export default SettingsPage;