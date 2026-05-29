const CLASSIFICATION_LABELS = {
  "public-trusted": "Mozilla-trusted public certificate",
  "local-trusted": "Local or system root certificate",
  problem: "Certificate attention needed",
  neutral: "Certificate status unknown"
};

const CLASSIFICATION_ICONS = {
  "public-trusted": "../icons/trusted.svg",
  "local-trusted": "../icons/local-trusted.svg",
  problem: "../icons/problem.svg",
  neutral: "../icons/neutral.svg"
};

function valueOrDash(value) {
  if (value === undefined || value === null || value === "") {
    return "Not reported";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  return String(value);
}

function parseDistinguishedName(value) {
  const text = String(value ?? "");
  const fields = {};
  const matches = text.matchAll(/(?:^|,)\s*([A-Z]+)=([^,]+)/gi);

  for (const match of matches) {
    const key = match[1].toUpperCase();
    const fieldValue = match[2].trim();
    if (!fields[key]) {
      fields[key] = [];
    }
    fields[key].push(fieldValue);
  }

  return fields;
}

function displayNameFromDn(value) {
  const fields = parseDistinguishedName(value);
  return fields.O?.[0] ?? fields.OU?.[0] ?? fields.CN?.[0] ?? valueOrDash(value);
}

function commonNameFromDn(value) {
  const fields = parseDistinguishedName(value);
  return fields.CN?.[0] ?? displayNameFromDn(value);
}

function organizationFromDn(value) {
  const fields = parseDistinguishedName(value);
  return fields.O?.[0] ?? fields.OU?.[0] ?? "Not reported";
}

function formatDate(value) {
  if (value === undefined || value === null || value === "") {
    return "Not reported";
  }

  const numeric = Number(value);
  const date = Number.isFinite(numeric) ? new Date(numeric) : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
}

function validityText(validity) {
  if (!validity) {
    return "Not reported";
  }

  const start = validity.start ?? validity.notBefore;
  const end = validity.end ?? validity.notAfter;
  if (!start && !end) {
    return "Not reported";
  }

  return `${formatDate(start)} to ${formatDate(end)}`;
}

function rootTrustSource(root) {
  if (!root) {
    return "Not reported";
  }

  if (root.isBuiltInRoot === true) {
    return "Built into Firefox";
  }

  if (root.isBuiltInRoot === false) {
    return "Local, system, or imported root";
  }

  return "Not reported";
}

function addFact(parent, label, value) {
  const row = document.createElement("div");
  const dt = document.createElement("dt");
  const dd = document.createElement("dd");
  dt.textContent = label;
  dd.textContent = valueOrDash(value);
  if (dd.textContent === "Not reported") {
    dd.className = "empty";
  }
  row.append(dt, dd);
  parent.append(row);
}

function renderSummary(leaf, root) {
  const summary = document.getElementById("summary");
  summary.textContent = "";

  addFact(summary, "Verified by", displayNameFromDn(leaf?.issuer));
  addFact(summary, "Root certificate", displayNameFromDn(root?.subject ?? leaf?.subject));
  addFact(summary, "Trust source", rootTrustSource(root));
  addFact(summary, "Valid for", commonNameFromDn(leaf?.subject));
  addFact(summary, "Valid until", formatDate(leaf?.validity?.end ?? leaf?.validity?.notAfter));
}

function renderConnection(securityInfo, checkedAt) {
  const connection = document.getElementById("connection");
  connection.textContent = "";

  if (!securityInfo) {
    addFact(connection, "TLS", "Not reported");
    addFact(connection, "Checked", checkedAt);
    return;
  }

  addFact(connection, "State", securityInfo.state);
  addFact(connection, "Protocol", securityInfo.protocolVersion);
  addFact(connection, "Cipher", securityInfo.cipherSuite);
  addFact(connection, "Certificate Transparency", securityInfo.certificateTransparencyStatus);
  addFact(connection, "HSTS", securityInfo.hsts);
  addFact(connection, "OCSP", securityInfo.usedOcsp);
  addFact(connection, "ECH", securityInfo.usedEch);
  addFact(connection, "Private DNS", securityInfo.usedPrivateDns);
  addFact(connection, "Domain mismatch", securityInfo.isDomainMismatch);
  addFact(connection, "Untrusted", securityInfo.isUntrusted);
  addFact(connection, "Checked", checkedAt);
}

function renderCertificate(sectionId, listId, certificate, root = null) {
  const section = document.getElementById(sectionId);
  const list = document.getElementById(listId);
  list.textContent = "";

  if (!certificate) {
    section.hidden = true;
    return;
  }

  section.hidden = false;
  addFact(list, "Common name", commonNameFromDn(certificate.subject));
  addFact(list, "Organization", organizationFromDn(certificate.subject));
  addFact(list, "Issuer", displayNameFromDn(certificate.issuer));
  addFact(list, "Validity", validityText(certificate.validity));
  if (root) {
    addFact(list, "Trust source", rootTrustSource(root));
  }
  addFact(list, "Serial", certificate.serialNumber);
  addFact(list, "SHA-256", certificate.fingerprintSha256);
}

function renderState(state) {
  const classification = state.classification ?? "neutral";
  const certificates = state.certificates ?? [];
  const leaf = certificates[0];
  const root = certificates.length > 1 ? certificates[certificates.length - 1] : null;

  const status = document.getElementById("status");
  status.className = `status ${classification}`;
  document.getElementById("status-icon").src =
    CLASSIFICATION_ICONS[classification] ?? CLASSIFICATION_ICONS.neutral;
  document.getElementById("host").textContent = state.host || "No active site";
  document.getElementById("classification").textContent =
    CLASSIFICATION_LABELS[classification] ?? CLASSIFICATION_LABELS.neutral;

  const reason = document.getElementById("reason");
  reason.className = `reason ${classification}`;
  reason.textContent = state.reason;

  renderSummary(leaf, root);
  renderConnection(state.securityInfo, state.checkedAt);
  renderCertificate("leaf-section", "leaf", leaf);
  renderCertificate("root-section", "root", root, root);
}

async function init() {
  try {
    const state = await browser.runtime.sendMessage({
      type: "get-active-certificate-state"
    });
    renderState(state);
  } catch (error) {
    renderState({
      classification: "problem",
      host: "Extension error",
      reason: error?.message ?? "Unable to read certificate state.",
      certificates: [],
      securityInfo: null
    });
  }
}

init();
