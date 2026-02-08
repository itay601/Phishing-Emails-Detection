/**
 * Build a result card with color-coded classification.
 * @param {Object} result - The analysis response from the backend.
 * @returns {CardService.ActionResponse}
 */
function buildResultCard(result) {
  var card = CardService.newCardBuilder();

  // Color-coded header
  var headerText = result.classification + " (" + Math.round(result.confidence_score * 100) + "% confidence)";
  card.setHeader(CardService.newCardHeader().setTitle(headerText));

  // Summary section
  var summarySection = CardService.newCardSection().setHeader("Summary");
  summarySection.addWidget(
    CardService.newTextParagraph().setText(result.summary)
  );

  // Classification icon
  var icon = getClassificationIcon(result.classification);
  summarySection.addWidget(
    CardService.newDecoratedText()
      .setText(result.classification)
      .setTopLabel("Risk Level")
      .setStartIcon(
        CardService.newIconImage().setIconUrl(icon)
      )
  );
  card.addSection(summarySection);

  // Heuristic details
  if (result.details && result.details.heuristics) {
    var detailSection = CardService.newCardSection().setHeader("Detection Details");

    result.details.heuristics.forEach(function (h) {
      if (h.indicators.length > 0) {
        var indicatorText = h.indicators.join("\n• ");
        detailSection.addWidget(
          CardService.newDecoratedText()
            .setText("• " + indicatorText)
            .setTopLabel(h.name + " (score: " + h.score.toFixed(2) + ")")
            .setWrapText(true)
        );
      }
    });

    card.addSection(detailSection);
  }

  // ML prediction if available
  if (result.details && result.details.ml_prediction) {
    var mlSection = CardService.newCardSection().setHeader("ML Analysis");
    mlSection.addWidget(
      CardService.newDecoratedText()
        .setText(
          "Prediction: " + (result.details.ml_prediction.is_phishing ? "Phishing" : "Legitimate") +
          "\nConfidence: " + Math.round(result.details.ml_prediction.confidence * 100) + "%"
        )
        .setWrapText(true)
    );
    card.addSection(mlSection);
  }

  var nav = CardService.newNavigation().pushCard(card.build());
  return CardService.newActionResponseBuilder().setNavigation(nav).build();
}

/**
 * Build an error card.
 * @param {string} errorMessage
 * @returns {CardService.ActionResponse}
 */
function buildErrorCard(errorMessage) {
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Error"));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText("Analysis failed: " + errorMessage)
  );
  card.addSection(section);

  var nav = CardService.newNavigation().pushCard(card.build());
  return CardService.newActionResponseBuilder().setNavigation(nav).build();
}

/**
 * Get an icon URL based on classification.
 */
function getClassificationIcon(classification) {
  switch (classification) {
    case "Phishing":
      return "https://www.gstatic.com/images/icons/material/system/1x/error_red_48dp.png";
    case "Suspicious":
      return "https://www.gstatic.com/images/icons/material/system/1x/warning_amber_48dp.png";
    default:
      return "https://www.gstatic.com/images/icons/material/system/1x/check_circle_green_48dp.png";
  }
}
