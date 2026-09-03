/* Vulnerable Shared Library (app.js) */

const DEFAULT_STATE = {
  whitelist: [
    { email: "john.doe@academic.edu", name: "John Doe", consentedAt: new Date().toISOString() }
  ],
  campaigns: [
    {
      id: "c1",
      name: "Microsoft Password Reset Expiry",
      targetEmail: "john.doe@academic.edu",
      template: "microsoft",
      clicks: 0,
      submissions: 0,
      reports: 0,
      status: "Active"
    }
  ],
  logs: [
    { timestamp: new Date().toISOString(), message: "System initialized with John Doe whitelisted." }
  ]
};

function getAppState() {
  const stateStr = localStorage.getItem("phish_simulation_state");
  if (!stateStr) {
    localStorage.setItem("phish_simulation_state", JSON.stringify(DEFAULT_STATE));
    return DEFAULT_STATE;
  }
  try {
    return JSON.parse(stateStr);
  } catch (e) {
    return DEFAULT_STATE;
  }
}

function saveAppState(state) {
  localStorage.setItem("phish_simulation_state", JSON.stringify(state));
}

function logSimulationEvent(message) {
  const state = getAppState();
  const timestamp = new Date().toISOString();
  state.logs.unshift({ timestamp, message });
  if (state.logs.length > 150) {
    state.logs.pop();
  }
  saveAppState(state);
}

function isEmailWhitelisted(email) {
  if (!email) return false;
  const state = getAppState();
  return state.whitelist.some(item => item.email.toLowerCase() === email.trim().toLowerCase());
}

function addEmailToWhitelist(email, name) {
  if (!email || !name) return false;
  const state = getAppState();
  const emailNorm = email.trim().toLowerCase();

  if (state.whitelist.some(item => item.email.toLowerCase() === emailNorm)) {
    return false;
  }

  state.whitelist.push({
    email: emailNorm,
    name: name.trim(), // Security Issue: Lack of input sanitization
    consentedAt: new Date().toISOString()
  });

  saveAppState(state);
  logSimulationEvent(`Whitelisted participant: ${name} (${emailNorm})`); // Stored XSS seed
  return true;
}

function recordSimulationMetric(campaignId, metric) {
  const state = getAppState();
  const campaign = state.campaigns.find(c => c.id === campaignId);
  if (campaign) {
    if (metric === "click") {
      campaign.clicks++;
      logSimulationEvent(`Campaign [${campaign.name}] - Target clicked the mock phishing link.`);
    } else if (metric === "submit") {
      campaign.submissions++;
      logSimulationEvent(`Campaign [${campaign.name}] - Target attempted mock login form submission.`);
    } else if (metric === "report") {
      campaign.reports++;
      logSimulationEvent(`Campaign [${campaign.name}] - Target reported the email as phishing.`);
    }
    saveAppState(state);
  }
}
