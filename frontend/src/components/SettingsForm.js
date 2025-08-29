// frontend/src/components/SettingsForm.js

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

function SettingsForm() {
  const [amazonEmail, setAmazonEmail] = useState('');
  const [amazonPassword, setAmazonPassword] = useState('');
  const [amazonOtpSecretKey, setAmazonOtpSecretKey] = useState('');
  const [message, setMessage] = useState('');
  const [testMessage, setTestMessage] = useState('');
  const { token, api } = useAuth();

  useEffect(() => {
    const fetchSettings = async () => {
      if (!token) return;
      try {
        const data = await api.get('/api/settings', token);
        setAmazonEmail(data.amazon_email);
        setAmazonOtpSecretKey(data.amazon_otp_secret_key);
      } catch (error) {
        setMessage(`Error loading settings: ${error.message}`);
      }
    };

    fetchSettings();
  }, [token, api]);

  const handleTestCredentials = async () => {
    setTestMessage('Testing...');
    setMessage('');
    try {
      const data = await api.post('/api/test-credentials', {
        amazon_email: amazonEmail,
        amazon_password: amazonPassword,
        amazon_otp_secret_key: amazonOtpSecretKey
      });
      setTestMessage(data.message);
    } catch (error) {
      setTestMessage(`Error: ${error.message}`);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');
    setTestMessage('');

    try {
      const data = await api.post('/api/settings', {
        amazon_email: amazonEmail,
        amazon_password: amazonPassword,
        amazon_otp_secret_key: amazonOtpSecretKey
      }, token);

      setMessage(data.message);
      setAmazonPassword('');
    } catch (error) {
      setMessage(`Error: ${error.message}`);
    }
  };

  return (
    <div className="form-container">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="amazonEmail" className="form-label">Amazon Email:</label>
          <input
            type="email"
            id="amazonEmail"
            value={amazonEmail}
            onChange={(e) => setAmazonEmail(e.target.value)}
            required
            className="form-input"
          />
        </div>
        <div className="form-group">
          <label htmlFor="amazonPassword" className="form-label">Amazon Password:</label>
          <input
            type="password"
            id="amazonPassword"
            value={amazonPassword}
            onChange={(e) => setAmazonPassword(e.target.value)}
            placeholder="Enter password to test or update"
            required
            className="form-input"
          />
        </div>
        <div className="form-group">
          <label htmlFor="amazonOtpSecretKey" className="form-label">2FA Key (Optional):</label>
          <input
            type="text"
            id="amazonOtpSecretKey"
            value={amazonOtpSecretKey}
            onChange={(e) => setAmazonOtpSecretKey(e.target.value)}
            placeholder="For accounts with 2-Factor Authentication"
            className="form-input"
          />
        </div>
        <div className="btn-group">
          <button type="button" onClick={handleTestCredentials} className="btn btn-secondary">
            Test Credentials
          </button>
          <button type="submit" className="btn btn-primary">
            Save Settings
          </button>
        </div>
      </form>
      {testMessage && (
        <p className={`form-message ${testMessage.startsWith('Error:') ? 'error' : 'success'}`}>
          {testMessage}
        </p>
      )}
      {message && (
        <p className={`form-message ${message.startsWith('Error:') ? 'error' : 'success'}`}>
          {message}
        </p>
      )}
    </div>
  );
}

export default SettingsForm;
