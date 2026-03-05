const express = require("express");
const axios = require("axios");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.static("public"));

// ─── Helper ──────────────────────────────────────────────────────────────────
function header(headers, key) {
  return headers[key.toLowerCase()] || null;
}

function normalizeUrl(url) {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return "https://" + url;
  }
  return url;
}


// ─── Main Scan Endpoint ───────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  let url = (req.query.url || "").trim();
  if (!url) return res.json({ error: "URL required" });

  url = normalizeUrl(url);

  try {
    const baseUrl = new URL(url);

    // ── 1. Main page request ─────────────────────────────────────────────────
    let mainResponse;
    try {
      mainResponse = await axios.get(url, {
        timeout: 15000,
        maxRedirects: 5,
        validateStatus: () => true,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; WPShield-SecurityScanner/2.0)",
        },
      });
    } catch (e) {
      return res.json({ error: `Website scan timeout. Target site may be slow or blocked` });
    }

    const headers = mainResponse.headers;
    const body = mainResponse.data || "";

    // ── 2. Probe secondary endpoints (parallel) ───────────────────────────────
    const xmlrpcUrl = `${baseUrl.origin}/xmlrpc.php`;
    const wpContentUrl = `${baseUrl.origin}/wp-content/`;
    const wpIncludesUrl = `${baseUrl.origin}/wp-includes/`;
    const readmeUrl = `${baseUrl.origin}/readme.html`;
    const loginUrl = `${baseUrl.origin}/wp-login.php`;

    const [xmlrpcRes, wpContentRes, readmeRes, loginRes] = await Promise.all([
      axios
        .get(xmlrpcUrl, { timeout: 5000, validateStatus: () => true })
        .catch(() => null),
      axios
        .get(wpContentUrl, { timeout: 5000, validateStatus: () => true })
        .catch(() => null),
      axios
        .get(readmeUrl, { timeout: 5000, validateStatus: () => true })
        .catch(() => null),
      axios
        .get(loginUrl, { timeout: 5000, validateStatus: () => true })
        .catch(() => null),
    ]);

    // ── 3. Evaluate each check ────────────────────────────────────────────────

    // SSL
    const ssl = url.startsWith("https") ? "PASS" : "FAIL";

    // X-Frame-Options
    const xFrameOptions = header(headers, "x-frame-options") ? "PASS" : "MISSING";

    // Content-Security-Policy
    const contentSecurityPolicy = header(headers, "content-security-policy")
      ? "PASS"
      : "MISSING";

    // XSS Protection
    const xssProtection = header(headers, "x-xss-protection") ? "PASS" : "MISSING";

    // X-Powered-By
    const poweredByVal = header(headers, "x-powered-by");
    const poweredBy = poweredByVal ? `VISIBLE (${poweredByVal})` : "HIDDEN";

    // HSTS
    const hstsVal = header(headers, "strict-transport-security");
    let strictTransport = "MISSING";
    if (hstsVal) {
      const maxAge = parseInt((hstsVal.match(/max-age=(\d+)/) || [])[1] || "0");
      if (maxAge >= 31536000) strictTransport = "PASS";
      else if (maxAge > 0) strictTransport = "PASS (weak max-age)";
      else strictTransport = "MISSING";
    }

    // Referrer-Policy
    const referrerPolicy = header(headers, "referrer-policy") ? "PASS" : "MISSING";

    // Permissions-Policy
    const permissionsPolicy =
      header(headers, "permissions-policy") ||
      header(headers, "feature-policy")
        ? "PASS"
        : "MISSING";

    // Cache-Control
    const cacheControlVal = header(headers, "cache-control");
    let cacheControl = "MISSING";
    if (cacheControlVal) {
      const hasNoStore = cacheControlVal.includes("no-store");
      const hasNoCache = cacheControlVal.includes("no-cache");
      cacheControl = hasNoStore || hasNoCache ? "PASS" : "PASS (review directives)";
    }

    // Server header
    const serverVal = header(headers, "server");
    let serverHeader = "HIDDEN";
    if (serverVal) {
      const detailed = /Apache\/[\d.]+|nginx\/[\d.]+|Microsoft-IIS\/[\d.]+/i.test(serverVal);
      serverHeader = detailed ? "VISIBLE (version exposed)" : "PASS (generic)";
    }

    // WordPress version exposure
    let wpVersion = "NONE";
    const wpGeneratorMatch = body.match(/<meta[^>]+generator[^>]+WordPress\s*([\d.]+)/i);
    const readmeBody = readmeRes?.data || "";
    const readmeVersionMatch = readmeBody.match(/Version\s*([\d.]+)/i);
    if (wpGeneratorMatch) {
      wpVersion = `DETECTED (v${wpGeneratorMatch[1]})`;
    } else if (readmeRes?.status === 200 && readmeVersionMatch) {
      wpVersion = `DETECTED via readme (v${readmeVersionMatch[1]})`;
    } else if (body.includes("/wp-content/") || body.includes("wp-includes")) {
      wpVersion = "HIDDEN";
    }

    // Directory listing
    let directoryListing = "RESTRICTED";
    if (
      wpContentRes?.status === 200 &&
      (wpContentRes.data || "").includes("Index of")
    ) {
      directoryListing = "OPEN";
    }

    // XML-RPC
    let xmlrpc = "DISABLED";
    if (xmlrpcRes) {
      const xmlrpcBody = xmlrpcRes.data || "";
      if (
        xmlrpcRes.status === 200 &&
        (xmlrpcBody.includes("XML-RPC server accepts POST requests only") ||
          xmlrpcBody.includes("xmlrpc"))
      ) {
        xmlrpc = "ENABLED";
      } else if (xmlrpcRes.status === 405) {
        xmlrpc = "ENABLED";
      }
    }

    // ── 4. Build report ───────────────────────────────────────────────────────
    const report = {
      ssl,
      xFrameOptions,
      contentSecurityPolicy,
      xssProtection,
      poweredBy,
      strictTransport,
      referrerPolicy,
      permissionsPolicy,
      cacheControl,
      serverHeader,
      wpVersion,
      directoryListing,
      xmlrpc,
    };

    res.json(report);
  } catch (err) {
    console.error("Scan error:", err.message);
    res.json({ error: "Unexpected scan error: " + err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
module.exports = app;