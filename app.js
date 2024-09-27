// OAuth configuration
const config = {};

// Dynamically set the redirect URI based on the current URL
config.redirectUri = window.location.href.split('?')[0];  // Remove any query parameters

// Function to update OAuth endpoints based on Recheck host
function updateOAuthEndpoints() {
  const recheckHost = document.getElementById('recheckHost').value.trim();
  config.authorizationEndpoint = `http://${recheckHost}/oauth/authorize/`;
  config.tokenEndpoint = `http://${recheckHost}/oauth/token/`;
}

// Function to update scope
function updateScope() {
  config.scope = document.getElementById('scope').value.trim();
}

// Function to save form values to local storage
function saveToLocalStorage(key, value) {
  localStorage.setItem(key, value);
}

// Function to load form values from local storage
function loadFromLocalStorage() {
  const recheckHostInput = document.getElementById('recheckHost');
  const clientIdInput = document.getElementById('clientId');
  const scopeInput = document.getElementById('scope');

  recheckHostInput.value = localStorage.getItem('recheckHost') || 'recheck.co';
  clientIdInput.value = localStorage.getItem('clientId') || '';
  scopeInput.value = localStorage.getItem('scope') || 'openid';

  // Update config with loaded values
  updateOAuthEndpoints();
  updateScope();
}

// Generate a random string for state
function generateRandomString(length) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// Generate code verifier and challenge
async function generateCodeVerifierAndChallenge() {
  const codeVerifier = generateRandomString(128);
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  const base64Digest = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return { codeVerifier, codeChallenge: base64Digest };
}

// Initiate OAuth flow
async function startOAuthFlow() {
  const clientIdInput = document.getElementById('clientId');
  const clientId = clientIdInput.value.trim();

  updateOAuthEndpoints();
  updateScope();

  const state = generateRandomString(16);
  const { codeVerifier, codeChallenge } = await generateCodeVerifierAndChallenge();
  
  localStorage.setItem('code_verifier', codeVerifier);
  localStorage.setItem('state', state);

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', clientId);
  authUrl.searchParams.append('redirect_uri', config.redirectUri);
  authUrl.searchParams.append('scope', config.scope);
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');

  window.location = authUrl.toString();
}

function addLogEntry(message, data = null, isError = false) {
    const responseElement = document.getElementById('response');
    const logEntry = document.createElement('div');
    logEntry.style.marginBottom = '1rem';
    
    let content = `<strong>${new Date().toLocaleTimeString()}</strong> — ${message}`;
    
    if (data) {
      content += `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    }
    
    logEntry.innerHTML = content;
    
    if (isError) {
      logEntry.style.color = 'red';
    }
    
    responseElement.appendChild(logEntry);
  }

// Exchange code for token
async function exchangeCodeForToken(code) {
  updateOAuthEndpoints();
  const clientId = localStorage.getItem('clientId');
  const codeVerifier = localStorage.getItem('code_verifier');
  const tokenRequest = new URLSearchParams();
  tokenRequest.append('grant_type', 'authorization_code');
  tokenRequest.append('code', code);
  tokenRequest.append('redirect_uri', config.redirectUri);
  tokenRequest.append('client_id', clientId);
  tokenRequest.append('code_verifier', codeVerifier);

  addLogEntry('Sending token request', {
    endpoint: config.tokenEndpoint,
    params: Object.fromEntries(tokenRequest)
  });

  try {
    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: tokenRequest
    });

    const responseData = await response.json();

    if (!response.ok) {
      addLogEntry('Token request failed', {
        status: response.status,
        statusText: response.statusText,
        response: responseData
      }, true);
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return responseData;
  } catch (error) {
    let errorInfo = {
      name: error.name,
      message: error.message,
      stack: error.stack
    };

    addLogEntry('Error during token exchange', errorInfo, true);
    throw error;
  }
}

// Handle OAuth callback
async function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  addLogEntry('Received callback with parameters', Object.fromEntries(urlParams));

  const code = urlParams.get('code');
  const state = urlParams.get('state');
  const error = urlParams.get('error');
  const storedState = localStorage.getItem('state');

  // Clear the URL parameters
  window.history.replaceState({}, document.title, window.location.pathname);

  if (error) {
    addLogEntry('Authorization error', { error }, true);
    return;
  }

  if (state !== storedState) {
    addLogEntry('Invalid state parameter', { 
      received: state, 
      expected: storedState 
    }, true);
    return;
  }

  addLogEntry('State parameter validated');

  try {
    addLogEntry('Exchanging code for ID token...');
    const tokenResponse = await exchangeCodeForToken(code);
    addLogEntry('Received ID token response', tokenResponse);    

    // Decode ID token
    const [headerB64, payloadB64, signature] = tokenResponse["id_token"].split('.');
    const header = JSON.parse(atob(headerB64));
    const payload = JSON.parse(atob(payloadB64));
    addLogEntry("ID token (JWT) values", {
        header: header,
        payload: payload,
        signature: signature
    });

  } catch (error) {
    addLogEntry('Error during ID token exchange', {
      name: error.name,
      message: error.message,
      stack: error.stack
    }, true);
  }
}

// Display an error message
function displayError(message) {
  addLogEntry('Error', { message }, true);
}


// Set up event listeners
function setupEventListeners() {
  const loginButton = document.getElementById('loginButton');
  const recheckHostInput = document.getElementById('recheckHost');
  const clientIdInput = document.getElementById('clientId');
  const scopeInput = document.getElementById('scope');

  // Add event listeners to save changes to local storage
  recheckHostInput.addEventListener('input', () => {
    saveToLocalStorage('recheckHost', recheckHostInput.value);
    updateOAuthEndpoints();
  });

  clientIdInput.addEventListener('input', () => {
    saveToLocalStorage('clientId', clientIdInput.value);
  });

  scopeInput.addEventListener('input', () => {
    saveToLocalStorage('scope', scopeInput.value);
    updateScope();
  });

  loginButton.addEventListener('click', startOAuthFlow);
}

// Main app logic
document.addEventListener('DOMContentLoaded', () => {
  // Load saved values from local storage
  loadFromLocalStorage();

  // Set up event listeners
  setupEventListeners();

  // Initial update of OAuth endpoints and display
  updateOAuthEndpoints();
  updateScope();

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('code') || urlParams.has('error')) {
    // We're in the callback phase
    handleCallback().catch(error => displayError(error.message));
  } else {
    // Clear previous logs when starting a new flow
    document.getElementById('response').innerHTML = '';
  }
});
