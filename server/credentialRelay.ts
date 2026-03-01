interface CapturedCredential {
  key: string;
  value: string;
  type: string;
  source: string;
  target: string;
  capturedAt: string;
}

interface DataBridgeState {
  credentials: CapturedCredential[];
  infraSecrets: string[];
  dbCredentials: string[];
  sessionTokens: string[];
  discoveredUsers: string[];
  lastUpdated: string;
}

const credentialRelay: DataBridgeState = {
  credentials: [],
  infraSecrets: [],
  dbCredentials: [],
  sessionTokens: [],
  discoveredUsers: [],
  lastUpdated: new Date().toISOString(),
};

function relayIngest(creds: CapturedCredential[]) {
  for (const cred of creds) {
    if (!credentialRelay.credentials.some(c => c.key === cred.key && c.value === cred.value)) {
      credentialRelay.credentials.push(cred);
    }
    if (cred.type === "PASSWORD" && !credentialRelay.infraSecrets.includes(cred.value)) {
      credentialRelay.infraSecrets.push(cred.value);
    }
    if (cred.type === "SECRET" || cred.type === "KEY" || cred.type === "CLOUD_CREDENTIAL") {
      if (!credentialRelay.infraSecrets.includes(cred.value)) {
        credentialRelay.infraSecrets.push(cred.value);
      }
    }
    if (cred.type === "TOKEN" && !credentialRelay.sessionTokens.includes(cred.value)) {
      credentialRelay.sessionTokens.push(cred.value);
    }
    if (cred.type === "URL" && !credentialRelay.dbCredentials.includes(cred.value)) {
      credentialRelay.dbCredentials.push(cred.value);
    }
  }
  credentialRelay.lastUpdated = new Date().toISOString();
}

function relayIngestUsers(users: string[]) {
  for (const u of users) {
    if (u && !credentialRelay.discoveredUsers.includes(u)) {
      credentialRelay.discoveredUsers.push(u);
    }
  }
  credentialRelay.lastUpdated = new Date().toISOString();
}

function relayIngestTokens(tokens: string[]) {
  for (const t of tokens) {
    if (t && !credentialRelay.sessionTokens.includes(t)) {
      credentialRelay.sessionTokens.push(t);
    }
  }
  credentialRelay.lastUpdated = new Date().toISOString();
}

export { credentialRelay, relayIngest, relayIngestUsers, relayIngestTokens };
export type { CapturedCredential, DataBridgeState };
