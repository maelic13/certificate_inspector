const STATUS_META = {
  "public-trusted": {
    icon: "icons/trusted.svg",
    title: "Trusted public certificate"
  },
  "local-trusted": {
    icon: "icons/local-trusted.svg",
    title: "Trusted by local or system certificate store"
  },
  problem: {
    icon: "icons/problem.svg",
    title: "Certificate or connection problem detected"
  },
  neutral: {
    icon: "icons/neutral.svg",
    title: "Certificate status unknown"
  }
};

const toolbarAction = browser.action ?? browser.browserAction;
const tabStates = new Map();
const hostStates = new Map();

function arrayBufferFromRawDer(rawDER) {
  if (!rawDER) {
    return null;
  }

  if (rawDER instanceof ArrayBuffer) {
    return rawDER;
  }

  if (ArrayBuffer.isView(rawDER)) {
    return rawDER.buffer.slice(rawDER.byteOffset, rawDER.byteOffset + rawDER.byteLength);
  }

  if (Array.isArray(rawDER)) {
    return new Uint8Array(rawDER).buffer;
  }

  return null;
}

function hexFromBuffer(buffer) {
  return [...new Uint8Array(buffer)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}

async function fingerprintFromRawDer(rawDER) {
  const buffer = arrayBufferFromRawDer(rawDER);
  if (!buffer) {
    return null;
  }

  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return hexFromBuffer(digest);
}

function cloneCertificateForPopup(certificate) {
  if (!certificate) {
    return null;
  }

  const { rawDER, ...rest } = certificate;
  return {
    ...rest,
    fingerprintSha256: null
  };
}

async function prepareCertificates(certificates = []) {
  const prepared = [];

  for (const certificate of certificates) {
    const clone = cloneCertificateForPopup(certificate);
    if (clone) {
      clone.fingerprintSha256 = await fingerprintFromRawDer(certificate.rawDER);
      prepared.push(clone);
    }
  }

  return prepared;
}

function hasSecurityProblem(securityInfo) {
  return (
    securityInfo.state === "insecure" ||
    securityInfo.state === "weak" ||
    securityInfo.state === "broken" ||
    securityInfo.isUntrusted === true ||
    securityInfo.isDomainMismatch === true ||
    securityInfo.isNotValidAtThisTime === true
  );
}

function getRootCertificate(certificates = []) {
  return certificates.length > 0 ? certificates[certificates.length - 1] : null;
}

function classifySecurityInfo(securityInfo, certificates) {
  if (!securityInfo || !Array.isArray(certificates) || certificates.length === 0) {
    return "problem";
  }

  if (hasSecurityProblem(securityInfo)) {
    return "problem";
  }

  const rootCertificate = getRootCertificate(certificates);
  if (rootCertificate?.isBuiltInRoot === false) {
    return "local-trusted";
  }

  return "public-trusted";
}

function buildReason(classification, securityInfo) {
  if (classification === "local-trusted") {
    return "Firefox trusts this certificate chain, but the root certificate is not built into Firefox. It likely comes from your operating system, organization, or a manually imported certificate authority.";
  }

  if (classification === "problem") {
    if (!securityInfo) {
      return "No TLS certificate details were captured for this HTTPS page.";
    }

    const reasons = [];
    if (securityInfo.state && securityInfo.state !== "secure") {
      reasons.push(`connection state is ${securityInfo.state}`);
    }
    if (securityInfo.isUntrusted) {
      reasons.push("Firefox could not build a chain to a trusted root");
    }
    if (securityInfo.isDomainMismatch) {
      reasons.push("certificate domain does not match the site");
    }
    if (securityInfo.isNotValidAtThisTime) {
      reasons.push("certificate is expired or not yet valid");
    }

    return reasons.length > 0
      ? `Attention needed: ${reasons.join(", ")}.`
      : "Attention needed: Firefox reported a certificate or TLS problem.";
  }

  if (classification === "public-trusted") {
    return "Firefox trusts this certificate chain and its root certificate is built into Firefox.";
  }

  return "Open an HTTPS page to inspect its certificate chain.";
}

function getHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function hostCandidates(host) {
  if (!host) {
    return [];
  }

  const candidates = [host];
  const parts = host.split(".");
  if (parts.length > 2) {
    candidates.push(parts.slice(-2).join("."));
  }

  return candidates;
}

function getStoredStateForUrl(url) {
  const host = getHost(url);
  for (const candidate of hostCandidates(host)) {
    const exact = hostStates.get(candidate);
    if (exact) {
      return exact;
    }

    for (const [storedHost, state] of hostStates.entries()) {
      if (storedHost === candidate || storedHost.endsWith(`.${candidate}`)) {
        return state;
      }
    }
  }

  return null;
}

function rememberState(state) {
  if (state.tabId >= 0) {
    tabStates.set(state.tabId, state);
  }

  if (state.host) {
    hostStates.set(state.host, state);
    const parts = state.host.split(".");
    if (parts.length > 2) {
      hostStates.set(parts.slice(-2).join("."), state);
    }
  }
}

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url ?? "");
}

function isHttpsUrl(url) {
  return /^https:\/\//i.test(url ?? "");
}

async function setActionState(tabId, classification) {
  if (tabId < 0) {
    return;
  }

  const meta = STATUS_META[classification] ?? STATUS_META.neutral;
  await toolbarAction.setIcon({
    tabId,
    path: {
      16: meta.icon,
      32: meta.icon,
      48: meta.icon,
      96: meta.icon
    }
  });
  await toolbarAction.setTitle({ tabId, title: meta.title });
}

async function setNeutralState(tabId, url) {
  const state = {
    tabId,
    url: url ?? "",
    host: getHost(url),
    classification: "neutral",
    reason: buildReason("neutral"),
    securityInfo: null,
    certificates: [],
    checkedAt: new Date().toISOString()
  };

  rememberState(state);
  await setActionState(tabId, "neutral");
}

async function setProblemState(tabId, url) {
  const state = {
    tabId,
    url: url ?? "",
    host: getHost(url),
    classification: "problem",
    reason: buildReason("problem", null),
    securityInfo: null,
    certificates: [],
    checkedAt: new Date().toISOString()
  };

  rememberState(state);
  await setActionState(tabId, "problem");
}

async function handleHeadersReceived(details) {
  if (details.type !== "main_frame" || !isHttpsUrl(details.url)) {
    return {};
  }

  try {
    const securityInfo = await browser.webRequest.getSecurityInfo(details.requestId, {
      certificateChain: true,
      rawDER: true
    });

    const certificates = await prepareCertificates(securityInfo.certificates ?? []);
    const classification = classifySecurityInfo(securityInfo, certificates);

    const state = {
      tabId: details.tabId,
      url: details.url,
      host: getHost(details.url),
      classification,
      reason: buildReason(classification, securityInfo),
      securityInfo: {
        certificateTransparencyStatus: securityInfo.certificateTransparencyStatus,
        cipherSuite: securityInfo.cipherSuite,
        hsts: securityInfo.hsts,
        isDomainMismatch: securityInfo.isDomainMismatch,
        isExtendedValidation: securityInfo.isExtendedValidation,
        isNotValidAtThisTime: securityInfo.isNotValidAtThisTime,
        isUntrusted: securityInfo.isUntrusted,
        keaGroupName: securityInfo.keaGroupName,
        protocolVersion: securityInfo.protocolVersion,
        secretKeyLength: securityInfo.secretKeyLength,
        signatureSchemeName: securityInfo.signatureSchemeName,
        state: securityInfo.state,
        usedDelegatedCredentials: securityInfo.usedDelegatedCredentials,
        usedEch: securityInfo.usedEch,
        usedOcsp: securityInfo.usedOcsp,
        usedPrivateDns: securityInfo.usedPrivateDns,
        weaknessReasons: securityInfo.weaknessReasons
      },
      certificates,
      checkedAt: new Date().toISOString()
    };

    rememberState(state);
  } catch (error) {
    console.error("Unable to inspect certificate", error);
    await setProblemState(details.tabId, details.url);
  }

  return {};
}

browser.webRequest.onHeadersReceived.addListener(
  handleHeadersReceived,
  {
    urls: ["https://*/*"],
    types: ["main_frame"]
  },
  ["blocking", "responseHeaders"]
);

browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url && !isHttpUrl(changeInfo.url)) {
    await setNeutralState(tabId, changeInfo.url);
  }

  if (changeInfo.status === "complete") {
    const url = tab.url ?? changeInfo.url;
    if (!isHttpUrl(url)) {
      await setNeutralState(tabId, url);
    } else {
      const state = tabStates.get(tabId) ?? getStoredStateForUrl(url);
      if (state) {
        rememberState({
          ...state,
          tabId,
          url,
          host: getHost(url)
        });
        await setActionState(tabId, state.classification);
      } else if (isHttpsUrl(url)) {
        await setActionState(tabId, "neutral");
      }
    }
  }
});

browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const state = tabStates.get(tabId);
  if (state) {
    await setActionState(tabId, state.classification);
    return;
  }

  try {
    const tab = await browser.tabs.get(tabId);
    if (!isHttpUrl(tab.url)) {
      await setNeutralState(tabId, tab.url);
    } else {
      await setActionState(tabId, "neutral");
    }
  } catch (error) {
    console.error("Unable to update active tab certificate state", error);
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

browser.runtime.onMessage.addListener((message) => {
  if (message?.type !== "get-active-certificate-state") {
    return false;
  }

  return browser.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
    if (!tab?.id) {
      return {
        classification: "neutral",
        reason: buildReason("neutral"),
        certificates: [],
        securityInfo: null
      };
    }

    const existingState = tabStates.get(tab.id) ?? getStoredStateForUrl(tab.url);

    if (!isHttpUrl(tab.url)) {
      await setNeutralState(tab.id, tab.url);
    } else if (existingState) {
      tabStates.set(tab.id, {
        ...existingState,
        tabId: tab.id
      });
      await setActionState(tab.id, existingState.classification);
    }

    const currentState = tabStates.get(tab.id);
    if (currentState) {
      await setActionState(tab.id, currentState.classification);
      return currentState;
    }

    return {
      tabId: tab.id,
      url: tab.url ?? "",
      host: getHost(tab.url),
      classification: "neutral",
      reason: buildReason("neutral"),
      securityInfo: null,
      certificates: [],
      checkedAt: null
    };
  });
});
