// OAuth configuration
const config = {};

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

// Function to update login hint
function updateLoginHint() {
  config.loginHint = document.getElementById('loginHint').value.trim();
}

// Function to update recheck token
function updateRecheckToken() {
  config.recheckToken = document.getElementById('recheckToken').value.trim();
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
  const delayRedirectInput = document.getElementById('delayRedirect');
  const loginHintInput = document.getElementById('loginHint');

  const recheckTokenInput = document.getElementById('recheckToken');

  recheckEndpointInput.value = localStorage.getItem('recheckEndpoint') || 'http://localhost:8000';
  clientIdInput.value = localStorage.getItem('clientId') || 'lsGH3LjbcdCmCf2hAngVYL0Hvhz0U22DtVMW18oD';
  scopeInput.value = localStorage.getItem('scope') || 'openid';
  delayRedirectInput.checked = localStorage.getItem('delayRedirect') === 'true';
  loginHintInput.value = localStorage.getItem('loginHint') || '';
  recheckTokenInput.value = localStorage.getItem('recheckToken') || '';

  // Update config with loaded values
  updateOAuthEndpoints();
  updateScope();
  updateLoginHint();
  updateRecheckToken();
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

// Generate code verifier and challenge (PKCE)
// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
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
  updateLoginHint();
  updateRecheckToken();

  const state = generateRandomString(16);
  localStorage.setItem('state', state);
  localStorage.setItem('flow_type', config.recheckToken ? 'reverification' : 'standard');
  addLogEntry("Generated state value", {
    state: state
  });

  const { codeVerifier, codeChallenge } = await generateCodeVerifierAndChallenge();
  localStorage.setItem('code_verifier', codeVerifier);
  addLogEntry("Generated PKCE values", {
    code_verifier: codeVerifier,
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
  
  // Add login_hint if provided
  if (config.loginHint) {
    authUrl.searchParams.append('login_hint', config.loginHint);
  }

  // Add recheck_token if provided (triggers selfie re-verification flow)
  if (config.recheckToken) {
    authUrl.searchParams.append('recheck_token', config.recheckToken);
  }

  const fullUrl = authUrl.toString();

  addLogEntry("Redirecting to authorization endpoint...", {
    params: Object.fromEntries(authUrl.searchParams.entries()),
    url: fullUrl
  });
  
  // Check if delay is enabled
  const delayRedirect = document.getElementById('delayRedirect').checked;
  
  if (delayRedirect) {
    // A real implementation would not implement this delay. It is done here to provide a moment to read
    // the values logged above.
    addLogEntry("Delaying redirect to allow reading logs...");
    setTimeout(() => {
      window.location = fullUrl;
    }, 10000);
  } else {
    // Redirect immediately
    window.location = fullUrl;
  }
}

function addLogEntry(message, data = null, isError = false) {
    const logFn = isError ? console.error : console.log;
    logFn(`[recheck-app] ${message}`, data ?? '');

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
  const errorDescription = urlParams.get('error_description');
  const storedState = localStorage.getItem('state');
  const flowType = localStorage.getItem('flow_type') || 'standard';
  const isReverificationFlow = flowType === 'reverification';
  if (isReverificationFlow) {
    addLogEntry('Processing reverification callback');
  }

  // Clear the URL parameters
  window.history.replaceState({}, document.title, window.location.pathname);

  if (error) {
    addLogEntry('Authorization error', { error, error_description: errorDescription }, true);
    return;
  }

  if (state !== storedState) {
    addLogEntry('Invalid state parameter', { 
      received: state, 
      expected: storedState 
    }, true);
    return;
  }

  addLogEntry('State parameter validated. Now we exchange the code for a token...');

  try {
    const tokenResponse = await exchangeCodeForToken(code);
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

    if (isReverificationFlow) {
      // Extract the updated recheck token from the sub claim
      const newRecheckToken = payload.sub;
      addLogEntry('Updated recheck token from id_token sub claim', {
        recheck_token: newRecheckToken
      });

      // Update the form field and persist for next use
      document.getElementById('recheckToken').value = newRecheckToken;
      saveToLocalStorage('recheckToken', newRecheckToken);
      updateRecheckToken();
    }

    // Verify the authorization by fetching userinfo
    if (!tokenResponse.access_token) {
      addLogEntry('No access_token returned in token response — skipping userinfo verification', {
        token_response_keys: Object.keys(tokenResponse)
      }, true);
    } else {
      addLogEntry(isReverificationFlow
        ? 'Verifying reverification authorization by fetching userinfo...'
        : 'Fetching userinfo...');
      await requestUserInfo(tokenResponse.access_token);
    }
  } catch (error) {
    addLogEntry('Error during ID token exchange', {
      name: error.name,
      message: error.message,
      stack: error.stack
    }, true);
  }
}

// Handle reverification callback
async function handleReverificationCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  addLogEntry('Received reverification callback with parameters', Object.fromEntries(urlParams));

  const status = urlParams.get('status');
  const recheckToken = urlParams.get('recheck_token');
  const state = urlParams.get('state');
  const storedState = localStorage.getItem('state');

  // Clear the URL parameters
  window.history.replaceState({}, document.title, window.location.pathname);

  if (state !== storedState) {
    addLogEntry('Invalid state parameter', {
      received: state,
      expected: storedState
    }, true);
    return;
  }

  addLogEntry('State parameter validated');

  if (status !== 'pass') {
    addLogEntry('Reverification failed', { status, recheck_token: recheckToken }, true);
    return;
  }

  addLogEntry('Reverification passed — received new recheck token', {
    status: status,
    recheck_token: recheckToken
  });

  // Update the form field and persist for next use
  document.getElementById('recheckToken').value = recheckToken;
  saveToLocalStorage('recheckToken', recheckToken);
  updateRecheckToken();

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
  const delayRedirectInput = document.getElementById('delayRedirect');
  const loginHintInput = document.getElementById('loginHint');
  const recheckTokenInput = document.getElementById('recheckToken');

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
  
  delayRedirectInput.addEventListener('change', () => {
    saveToLocalStorage('delayRedirect', delayRedirectInput.checked);
  });

  loginHintInput.addEventListener('input', () => {
    saveToLocalStorage('loginHint', loginHintInput.value);
    updateLoginHint();
  });

  recheckTokenInput.addEventListener('input', () => {
    saveToLocalStorage('recheckToken', recheckTokenInput.value);
    updateRecheckToken();
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
  updateLoginHint();
  updateRecheckToken();

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has('code') || urlParams.has('error')) {
    // Standard OAuth callback phase
    handleCallback().catch(error => displayError(error.message));
  } else if (urlParams.has('recheck_token') || urlParams.has('status')) {
    // Reverification callback phase
    handleReverificationCallback().catch(error => displayError(error.message));
  } else {
    // Clear previous logs when starting a new flow
    document.getElementById('response').innerHTML = '';
  }
});
