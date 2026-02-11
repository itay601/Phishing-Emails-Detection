/**
 * Build a result card with color-coded classification.
 * @param {Object} result - The analysis response from the backend.
 * @returns {CardService.Card}
 */
function buildResultCard(result) {
  // Safety check
  if (!result || typeof result !== "object") {
    Logger.log("buildResultCard called with invalid result: " + JSON.stringify(result));
    return buildErrorCard("Invalid or empty response from analysis service.");
  }

  // Safely get classification and confidence
  var classification = result.classification || "Unknown";
  var confidence = result.confidence_score ? Math.round(result.confidence_score * 100) : 0;

  // Create card builder
  var card = CardService.newCardBuilder();

  // Color-coded header
  var headerText = classification + " (" + confidence + "% confidence)";
  card.setHeader(CardService.newCardHeader().setTitle(headerText));

  // Summary section
  if (result.summary) {
    var summarySection = CardService.newCardSection().setHeader("Summary");
    summarySection.addWidget(
      CardService.newTextParagraph().setText(result.summary)
    );
    card.addSection(summarySection);
  }

  // Classification icon
  var icon = getClassificationIcon(classification);
  var iconSection = CardService.newCardSection();
  iconSection.addWidget(
    CardService.newDecoratedText()
      .setText(classification)
      .setTopLabel("Risk Level")
      .setStartIcon(CardService.newIconImage().setIconUrl(icon))
  );
  card.addSection(iconSection);

  // Heuristic details
  if (result.details && Array.isArray(result.details.heuristics)) {
    var detailSection = CardService.newCardSection().setHeader("Detection Details");
    var hasWidgets = false;

    result.details.heuristics.forEach(function (h) {
      if (h.indicators && h.indicators.length > 0) {
        var indicatorText = h.indicators.join("\n• ");
        detailSection.addWidget(
          CardService.newDecoratedText()
            .setText("• " + indicatorText)
            .setTopLabel(h.name + " (score: " + (h.score ? h.score.toFixed(2) : "0") + ")")
            .setWrapText(true)
        );
        hasWidgets = true;
      }
    });

    if (hasWidgets) {
      card.addSection(detailSection);
    }
  }

  // ML prediction if available
  if (result.details && result.details.ml_prediction) {
    var ml = result.details.ml_prediction;
    var mlSection = CardService.newCardSection().setHeader("ML Analysis");

    var prediction = ml.is_phishing === true ? "Phishing" : "Legitimate";
    var mlConfidence = ml.confidence ? Math.round(ml.confidence * 100) : 0;

    mlSection.addWidget(
      CardService.newDecoratedText()
        .setText("Prediction: " + prediction + "\nConfidence: " + mlConfidence + "%")
        .setWrapText(true)
    );

    card.addSection(mlSection);
  }

  return card.build();
}

/**
 * Build an error card.
 * @param {string} errorMessage
 * @returns {CardService.Card}
 */
function buildErrorCard(errorMessage) {
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Error"));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText("Analysis failed: " + errorMessage)
  );
  card.addSection(section);

  return card.build();
}

/**
 * Get an icon URL based on classification.
 * @param {string} classification
 * @returns {string}
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
