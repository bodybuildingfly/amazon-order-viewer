// frontend/src/pages/SettingsPage.js

import React from 'react';
import SettingsForm from '../components/SettingsForm';

function SettingsPage() {
  return (
    <div>
      <h2>User Settings</h2>
      <p>Configure your Amazon credentials here. The password is write-only and will not be displayed.</p>
      <SettingsForm />
    </div>
  );
}

export default SettingsPage;
