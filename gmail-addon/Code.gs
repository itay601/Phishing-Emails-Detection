/**
 * Entry point — builds the add-on card when an email is opened.
 */
function buildAddOn(e) {
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Phishing Detector"));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Scan this email for phishing indicators."
    )
  );

  var scanAction = CardService.newAction().setFunctionName(
    "onScanButtonClicked"
  );
  section.addWidget(
    CardService.newTextButton()
      .setText("Scan for Phishing")
      .setOnClickAction(scanAction)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  card.addSection(section);
  return [card.build()];
}

/**
 * Handler for the "Scan for Phishing" button.
 * Extracts email fields and sends them to the backend API.
 */
function onScanButtonClicked(e) {
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);

  var emailContent = {
    from_address: message.getFrom(),
    from_name: extractDisplayName(message.getFrom()),
    to: message.getTo(),
    subject: message.getSubject(),
    body_text: message.getPlainBody(),
    body_html: message.getBody(),
    headers: extractHeaders(message),
  };

  try {
    var result = analyzeEmail(emailContent);
    return buildResultCard(result);
  } catch (err) {
    return buildErrorCard(err.message);
  }
}

/**
 * Extract display name from a "Name <email>" format string.
 */
function extractDisplayName(fromField) {
  var match = fromField.match(/^(.+?)\s*<.*>$/);
  return match ? match[1].trim() : fromField;
}

/**
 * Extract relevant headers from a Gmail message.
 */
function extractHeaders(message) {
  var headers = {};
  try {
    var raw = message.getRawContent();
    var headerSection = raw.split("\r\n\r\n")[0];
    var replyToMatch = headerSection.match(/^Reply-To:\s*(.+)$/im);
    if (replyToMatch) {
      headers["reply-to"] = replyToMatch[1].trim();
    }
  } catch (e) {
    // If raw content is unavailable, skip headers
  }
  return headers;
}
