/**
 * Callback for the "Scan for Phishing" button.
 * Reads the current email and sends it to the backend for analysis.
 * @param {Object} e - The action event object.
 * @returns {CardService.ActionResponse}
 */
function onScanButtonClicked(e) {
  var params = e.commonEventObject.parameters || {};
  var messageId = params.messageId || "";

  if (!messageId) {
    var errCard = buildErrorCard("No message ID found. Please reopen the add-on.");
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(errCard))
      .build();
  }

  try {
    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      var errCard = buildErrorCard("Could not retrieve the email message.");
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().updateCard(errCard))
        .build();
    }

    var emailContent = {
      subject: message.getSubject(),
      from: message.getFrom(),
      to: message.getTo(),
      date: message.getDate().toISOString(),
      body: message.getPlainBody(),
      headers: {
        replyTo: message.getReplyTo(),
      }
    };

    var result = analyzeEmail(emailContent);

    if (result.error) {
      var errCard = buildErrorCard(result.message || "Unknown error occurred.");
      return CardService.newActionResponseBuilder()
        .setNavigation(CardService.newNavigation().updateCard(errCard))
        .build();
    }

    var resultCard = buildResultCard(result);
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(resultCard))
      .build();
  } catch (err) {
    Logger.log("onScanButtonClicked error: " + err.toString());
    var errCard = buildErrorCard("Error scanning email: " + err.toString());
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(errCard))
      .build();
  }
}

function buildAddOn(e) {
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Phishing Detector"));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText(
      "Scan this email for phishing indicators."
    )
  );

  var params = {};

  // ✅ SAFE CHECK
  if (e && e.messageMetadata) {
    params.messageId = e.messageMetadata.messageId || "";
    params.accessToken = e.messageMetadata.accessToken || "";
  } else {
    Logger.log("No messageMetadata found in event object.");
  }

  var scanAction = CardService.newAction()
    .setFunctionName("onScanButtonClicked")
    .setParameters(params);

  section.addWidget(
    CardService.newTextButton()
      .setText("Scan for Phishing")
      .setOnClickAction(scanAction)
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
  );

  card.addSection(section);
  return [card.build()];
}
