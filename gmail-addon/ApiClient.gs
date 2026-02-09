/**
 * Configuration — update these values for your deployment.
 */
var CONFIG = {
  API_URL: "https://nonexpediently-nonenumerated-santa.ngrok-free.dev/api/v1/analyze",
  API_KEY: "my-secret-123",
};

/**
 * Send email content to the backend API for analysis.
 * @param {Object} emailContent - The email fields to analyze.
 * @returns {Object} The analysis result from the backend.
 */
function analyzeEmail(emailContent) {
  // Add this check at the very top:
  if (!emailContent) {
    throw new Error("The email content provided to analyzeEmail was empty or undefined.");
  }

  var payload = {
    email_content: emailContent,
  };

  var options = {
    method: "post",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": CONFIG.API_KEY,
      "ngrok-skip-browser-warning": "true",
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
