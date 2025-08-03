// frontend/src/utils/api.js

/**
 * A utility function to handle API requests, automatically adding the auth token
 * and handling common response scenarios.
 *
 * @param {string} url - The API endpoint to call (e.g., '/api/login').
 * @param {string} method - The HTTP method (GET, POST, PUT, DELETE).
 * @param {object} [body=null] - The request body for POST/PUT requests.
 * @param {string} [token=null] - The JWT token for authorization.
 * @returns {Promise<object>} - A promise that resolves to the JSON response data.
 * @throws {Error} - Throws an error if the network request fails or the server returns an error.
 */
const apiRequest = async (url, method, body = null, token = null) => {
  const headers = {
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = {
    method,
    headers,
  };

  if (body) {
    config.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(url, config);
    const data = await response.json();

    if (!response.ok) {
      // Use the error message from the backend, or a default one
      throw new Error(data.error || `HTTP error! status: ${response.status}`);
    }

    return data;
  } catch (error) {
    // Re-throw the error so the component can catch it
    throw error;
  }
};

// --- Exported API Service Functions ---

export const api = {
  get: (url, token) => apiRequest(url, 'GET', null, token),
  post: (url, body, token) => apiRequest(url, 'POST', body, token),
  put: (url, body, token) => apiRequest(url, 'PUT', body, token),
  del: (url, token) => apiRequest(url, 'DELETE', null, token),
};
