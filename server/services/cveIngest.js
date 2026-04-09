const axios = require("axios");
const { Pool } = require("pg");

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "threatforge",
  password: "password",
  port: 5432,
});

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

async function fetchLatestCVEs() {
  try {
    const response = await axios.get(NVD_API, {
      params: { resultsPerPage: 20 }
    });

    const vulnerabilities = response.data.vulnerabilities;

    for (let item of vulnerabilities) {
      const cve = item.cve;
      const cveId = cve.id;
      const description = cve.descriptions[0]?.value || "";
      const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0;
      const severity = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "UNKNOWN";

      await pool.query(
        `INSERT INTO cves (cve_id, description, cvss_score, severity)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (cve_id) DO NOTHING`,
        [cveId, description, cvss, severity]
      );
    }

    console.log("CVE sync completed.");
  } catch (err) {
    console.error("CVE ingestion error:", err.message);
  }
}

module.exports = { fetchLatestCVEs };