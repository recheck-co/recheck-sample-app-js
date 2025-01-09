// OAuth configuration
const config = {};
const SECRET_KEY = "123456"
// Dynamically set the redirect URI based on the current URL
config.redirectUri = window.location.href.split('?')[0];  // Remove any query parameters

// Function to update OAuth endpoints based on Recheck host
function updateOAuthEndpoints() {
  const recheckEndpoint = document.getElementById('recheckEndpoint').value.trim();
  config.authorizationEndpoint = `${recheckEndpoint}/oauth/authorize/`;
  config.tokenEndpoint = `${recheckEndpoint}/oauth/token/`;
  config.userinfoEndpoint = `${recheckEndpoint}/oauth/userinfo/`;
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
  const recheckEndpointInput = document.getElementById('recheckEndpoint');
  const clientIdInput = document.getElementById('clientId');
  const scopeInput = document.getElementById('scope');
  const emailInput = document.getElementById('userEmail');

  recheckEndpointInput.value = localStorage.getItem('recheckEndpoint') || 'https://recheck.co';
  clientIdInput.value = localStorage.getItem('clientId') || '';
  scopeInput.value = localStorage.getItem('scope') || 'openid';
  emailInput.value = localStorage.getItem('userEmail') || '';

  // Update config with loaded values
  updateOAuthEndpoints();
  updateScope();
}

// Generate a random string for state
// https://auth0.com/docs/secure/attack-protection/state-parameters
function generateRandomString(length) {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

async function signEmail(email) {
  const encoder = new TextEncoder();
  const key = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode('abc'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await window.crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(email)
  );
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function createState(email) {
  const signature = await signEmail(email);
  return encodeURIComponent(`${email}:${signature}`);
}

async function verifyState(state) {
  const [email, sig] = decodeURIComponent(state).split(':');
  const calculatedSig = await signEmail(email);
  return (sig === calculatedSig)
}

async function generateCodeVerifier(email) {
  const codeVerifier = email + SECRET_KEY;
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}


// Generate code verifier and challenge (PKCE)
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
async function generateCodeChallenge(email) {
  const codeVerifier = await generateCodeVerifier(email);
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
}

// Initiate OAuth flow
async function startOAuthFlow() {
  const clientId = document.getElementById('clientId').value.trim();
  const email = document.getElementById('userEmail').value.trim();

  updateOAuthEndpoints();
  updateScope();

  addLogEntry("Creating state based on user email");
  const state = await createState(email);
  localStorage.removeItem('state');
  addLogEntry("Generated state value", {
    state: state
  });

  const codeChallenge = await generateCodeChallenge(email)

  addLogEntry("Generated codeChallenge from email", {
    code_challenge: codeChallenge
  });

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', clientId);
  authUrl.searchParams.append('redirect_uri', config.redirectUri);
  authUrl.searchParams.append('scope', config.scope);
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');

  addLogEntry("Redirecting to authorization endpoint in 5 seconds...", {
    params: Object.fromEntries(authUrl.searchParams.entries()),
    url: authUrl.toString()
  });
  // A real implementation would not implement this delay. It is done here to provide a moment to read
  // the values logged above.
  setTimeout(() => {
    window.location = authUrl.toString();
  }, 5000);
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
async function exchangeCodeForToken(code, codeVerifier) {
  updateOAuthEndpoints();
  const clientId = localStorage.getItem('clientId');
  const tokenRequest = new URLSearchParams();
  tokenRequest.append('grant_type', 'authorization_code');
  tokenRequest.append('code', code);
  tokenRequest.append('redirect_uri', config.redirectUri);
  tokenRequest.append('client_id', clientId);
  tokenRequest.append('code_verifier', codeVerifier);

  addLogEntry(`Sending token request to ${config.tokenEndpoint}`, Object.fromEntries(tokenRequest));

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

  let email = decodeURIComponent(state).split(':')[0];
  if (await verifyState(state)) {
    addLogEntry('Verified state parameter for email ' + email, false);
  } else {
    addLogEntry(`Invalid state parameter for email ` + email, {
      received: state,
      expected: await createState(email)
    }, true);
    return;
  }

  try {
    const tokenResponse = await exchangeCodeForToken(code, await generateCodeVerifier(email));
    addLogEntry('Received token response', tokenResponse);    

    // Decode ID token
    const [headerB64, payloadB64, signature] = tokenResponse["id_token"].split('.');
    const header = JSON.parse(atob(headerB64));
    const payload = JSON.parse(atob(payloadB64));
    addLogEntry("ID token (JWT) values", {
        header: header,
        payload: payload,
        signature: signature
    });

    await requestUserInfo(tokenResponse.access_token);

  } catch (error) {
    addLogEntry('Error during ID token exchange', {
      name: error.name,
      message: error.message,
      stack: error.stack
    }, true);
  }
}

async function requestUserInfo(accessToken) {
  try {
    addLogEntry(`Fetching ${config.userinfoEndpoint}`);
    const response = await fetch(config.userinfoEndpoint, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const userInfo = await response.json();
    addLogEntry('Received userinfo', userInfo);
  } catch (error) {
    addLogEntry('Error fetching user info', {
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
  const recheckEndpointInput = document.getElementById('recheckEndpoint');
  const clientIdInput = document.getElementById('clientId');
  const scopeInput = document.getElementById('scope');
  const emailInput = document.getElementById('userEmail');

  // Add event listeners to save changes to local storage
  recheckEndpointInput.addEventListener('input', () => {
    saveToLocalStorage('recheckEndpoint', recheckEndpointInput.value);
    updateOAuthEndpoints();
  });

  clientIdInput.addEventListener('input', () => {
    saveToLocalStorage('clientId', clientIdInput.value);
  });

  scopeInput.addEventListener('input', () => {
    saveToLocalStorage('scope', scopeInput.value);
    updateScope();
  });

  emailInput.addEventListener('input', () => {
    saveToLocalStorage('userEmail', emailInput.value);
    updateEmail();
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
