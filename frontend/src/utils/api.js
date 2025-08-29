// frontend/src/utils/api.js

/**
 * A class-based API service that handles token expiration and automatic logout.
 */
class ApiService {
  constructor(logout) {
    this.logout = logout;
  }

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
  async #apiRequest(url, method, body = null, token = null) {
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

      // If the token is expired, the backend returns a 401 error
      if (response.status === 401) {
        // Automatically log out the user
        this.logout();
        // Throw an error to stop the current action
        throw new Error('Your session has expired. Please log in again.');
      }

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
  }

  // --- Public API Methods ---

  get(url, token) {
    return this.#apiRequest(url, 'GET', null, token);
  }

  post(url, body, token) {
    return this.#apiRequest(url, 'POST', body, token);
  }

  put(url, body, token) {
    return this.#apiRequest(url, 'PUT', body, token);
  }

  del(url, token) {
    return this.#apiRequest(url, 'DELETE', null, token);
  }
}

export default ApiService;
