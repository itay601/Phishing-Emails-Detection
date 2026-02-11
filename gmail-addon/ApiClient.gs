/* ========================= ApiClient.gs ========================= */
/**
* Configuration — update these values for your deployment.
*/
var CONFIG = {
API_URL: PropertiesService.getScriptProperties().getProperty("API_URL") || "",
API_KEY: PropertiesService.getScriptProperties().getProperty("API_KEY") || "",
};


/**
 * Send email content to the backend API for analysis.
 * @param {Object} emailContent - The email fields to analyze.
 * @returns {Object} The analysis result or an error object.
 */
function analyzeEmail(emailContent) {
  // 1. Validation check
  if (!emailContent || Object.keys(emailContent).length === 0) {
    return {
      success: false,
      error: 'empty_email',
      message: 'No email content provided for analysis.'
    };
  }

  // 2. Configuration check
  if (!CONFIG.API_URL) {
    return { 
      success: false, 
      error: 'no_api_url', 
      message: 'API_URL is missing from Script Properties.' 
    };
  }

  // 3. Prepare Payload — match backend AnalyzeRequest / EmailContent schema
  var fromRaw = emailContent.from || '';
  var fromName = '';
  var fromAddress = fromRaw;

  // Parse "Display Name <email@example.com>" format
  var match = fromRaw.match(/^"?(.+?)"?\s*<(.+)>$/);
  if (match) {
    fromName = match[1].trim();
    fromAddress = match[2].trim();
  }

  var payload = {
    email_content: {
      from_address: fromAddress,
      from_name:    fromName,
      to:           emailContent.to      || '',
      subject:      emailContent.subject  || '',
      body_text:    emailContent.body     || emailContent.raw || '',
      body_html:    '',
      headers:      emailContent.headers  || {}
    }
  };

  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    headers: {}
  };

  if (CONFIG.API_KEY) {
    options.headers['X-Api-Key'] = CONFIG.API_KEY;
  }

  // 4. Execute Fetch
  try {
    var response = UrlFetchApp.fetch(CONFIG.API_URL, options);
    var code     = response.getResponseCode();
    var text     = response.getContentText();

    if (code >= 200 && code < 300) {
      try {
        return JSON.parse(text);
      } catch (e) {
        return { error: 'invalid_json', message: 'API response was not valid JSON.', raw: text };
      }
    } else {
      return { error: 'http_error', status: code, message: text };
    }
  } catch (e) {
    return { error: 'fetch_error', message: e.toString() };
  }
}