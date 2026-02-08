/**
 * Configuration — update these values for your deployment.
 */
var CONFIG = {
  API_URL: "https://your-backend-url.com/api/v1/analyze",
  API_KEY: "your-api-key-here",
};

/**
 * Send email content to the backend API for analysis.
 * @param {Object} emailContent - The email fields to analyze.
 * @returns {Object} The analysis result from the backend.
 */
function analyzeEmail(emailContent) {
  var payload = {
    email_content: emailContent,
  };

  var options = {
    method: "post",
    contentType: "application/json",
    headers: {
      "X-API-Key": CONFIG.API_KEY,
    },
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
  };

  var response = UrlFetchApp.fetch(CONFIG.API_URL, options);
  var code = response.getResponseCode();

  if (code !== 200) {
    throw new Error("API error (HTTP " + code + "): " + response.getContentText());
  }

  return JSON.parse(response.getContentText());
}
