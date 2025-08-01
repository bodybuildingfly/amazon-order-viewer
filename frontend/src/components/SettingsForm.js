// frontend/src/components/SettingsForm.js

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

const API_URL = process.env.REACT_APP_API_BASE_URL || '';

function SettingsForm() {
  const [amazonEmail, setAmazonEmail] = useState('');
  const [amazonPassword, setAmazonPassword] = useState('');
  const [amazonOtpSecretKey, setAmazonOtpSecretKey] = useState('');
  const [message, setMessage] = useState('');
  const [testMessage, setTestMessage] = useState('');
  const { token } = useAuth();

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await fetch(`${API_URL}/api/settings`, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` },
        });
        const data = await response.json();
        if (response.ok) {
          setAmazonEmail(data.amazon_email);
          setAmazonOtpSecretKey(data.amazon_otp_secret_key);
        } else {
          setMessage(`Error loading settings: ${data.error} - ${data.message || ''}`);
        }
      } catch (error) {
        setMessage(`Error: ${error.message}`);
      }
    };

    if (token) {
      fetchSettings();
    }
  }, [token]);

  const handleTestCredentials = async () => {
    setTestMessage('Testing...');
    setMessage('');
    try {
      const response = await fetch(`${API_URL}/api/test-credentials`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amazon_email: amazonEmail,
          amazon_password: amazonPassword,
          amazon_otp_secret_key: amazonOtpSecretKey
        }),
      });
      const data = await response.json();
      if (response.ok) {
        setTestMessage(data.message);
      } else {
        setTestMessage(`Error: ${data.error}`);
      }
    } catch (error) {
      setTestMessage(`Error: ${error.message}`);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');
    setTestMessage('');

    try {
      const response = await fetch(`${API_URL}/api/settings`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          amazon_email: amazonEmail,
          amazon_password: amazonPassword,
          amazon_otp_secret_key: amazonOtpSecretKey
        }),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setAmazonPassword('');
      } else {
        setMessage(`Error: ${data.error}`);
      }
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    }
  };

  return (
    <div style={{ maxWidth: '500px', margin: '20px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '8px' }}>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="amazonEmail" style={{ display: 'block', marginBottom: '5px' }}>Amazon Email:</label>
          <input
            type="email"
            id="amazonEmail"
            value={amazonEmail}
            onChange={(e) => setAmazonEmail(e.target.value)}
            required
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
          />
        </div>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="amazonPassword" style={{ display: 'block', marginBottom: '5px' }}>Amazon Password:</label>
          <input
            type="password"
            id="amazonPassword"
            value={amazonPassword}
            onChange={(e) => setAmazonPassword(e.target.value)}
            placeholder="Enter password to test or update"
            required
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
          />
        </div>
        <div style={{ marginBottom: '15px' }}>
          <label htmlFor="amazonOtpSecretKey" style={{ display: 'block', marginBottom: '5px' }}>2FA Key (Optional):</label>
          <input
            type="text"
            id="amazonOtpSecretKey"
            value={amazonOtpSecretKey}
            onChange={(e) => setAmazonOtpSecretKey(e.target.value)}
            placeholder="For accounts with 2-Factor Authentication"
            style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
          />
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button type="button" onClick={handleTestCredentials} style={{ flexGrow: 1, padding: '10px', backgroundColor: '#6c757d', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
            Test Credentials
          </button>
          <button type="submit" style={{ flexGrow: 2, padding: '10px', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
            Save Settings
          </button>
        </div>
      </form>
      {testMessage && <p style={{ marginTop: '20px', color: testMessage.startsWith('Error:') ? 'red' : 'green' }}>{testMessage}</p>}
      {message && <p style={{ marginTop: '20px', color: message.startsWith('Error:') ? 'red' : 'green' }}>{message}</p>}
    </div>
  );
}

export default SettingsForm;
