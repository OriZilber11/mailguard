/** Escapes text that comes from an email or backend before showing it. */
function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function resultCard(result) {
  const section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary)));

  result.signals.forEach(function (s) {
    section.addWidget(CardService.newTextParagraph().setText(
      "<b>[" + escapeHtml(s.severity) + "]</b> " + escapeHtml(s.title) +
      "<br>" + escapeHtml(s.explanation)
    ));
  });

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("MailGuard: " + escapeHtml(result.verdict).toUpperCase()))
    .addSection(section)
    .build();
}

function errorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("MailGuard"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(escapeHtml(message))))
    .build();
}
