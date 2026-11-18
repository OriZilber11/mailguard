/**
 * Card rendering. Every string that comes from the backend or the email is escaped before display;
 * colors come only from the constants below, never from data.
 */
var COLORS = { red: "#C5221F", amber: "#E37400", green: "#188038", gray: "#5F6368", muted: "#80868B", track: "#DADCE0" };

// Display order (rank) and color per severity. Unknown severities fall back to "low" so rendering never breaks.
var SEVERITY = {
  critical: { rank: 0, color: "#A50E0E" },
  high:     { rank: 1, color: COLORS.red },
  medium:   { rank: 2, color: COLORS.amber },
  low:      { rank: 3, color: "#B06000" },
  info:     { rank: 4, color: COLORS.green },
  trust:    { rank: 4, color: COLORS.green }
};

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function colored(text, color, bold) {
  const t = bold ? "<b>" + escapeHtml(text) + "</b>" : escapeHtml(text);
  return '<font color="' + color + '">' + t + "</font>";
}

function severityOf(s) {
  return SEVERITY.hasOwnProperty(s.severity) ? SEVERITY[s.severity] : SEVERITY.low;
}

/** Risk band of a score: 71-100 red, 31-70 amber, 0-30 green; no score (inconclusive) gray. */
function riskColor(score) {
  if (score === null) return COLORS.gray;
  return score >= 71 ? COLORS.red : score >= 31 ? COLORS.amber : COLORS.green;
}

/** Ten-segment bar, one segment per 10 points. Display only. */
function scoreBar(score, color) {
  const filled = Math.ceil(score / 10);
  return colored("■".repeat(filled), color) + colored("■".repeat(10 - filled), COLORS.track);
}

function signalWidget(s) {
  return CardService.newTextParagraph().setText(
    colored(String(s.severity).toUpperCase(), severityOf(s).color, true) + "  <b>" + escapeHtml(s.title) + "</b><br>" +
    escapeHtml(s.explanation));
}

function resultCard(result) {
  const score = typeof result.score === "number" ? result.score : null;
  const color = riskColor(score);

  const overview = CardService.newCardSection().setHeader("OVERALL ASSESSMENT")
    .addWidget(CardService.newDecoratedText().setTopLabel("VERDICT").setWrapText(true)
      .setText(colored(String(result.verdict).toUpperCase(), color, true)))
    .addWidget(CardService.newTextParagraph().setText(score === null
      ? colored("Score unavailable: some checks could not run", COLORS.gray, true)
      : scoreBar(score, color) + "  " + colored(score + " / 100", color, true)))
    .addWidget(CardService.newTextParagraph().setText(escapeHtml(result.summary)));

  const signals = result.signals.slice().sort(function (a, b) { return severityOf(a).rank - severityOf(b).rank; });
  const risks = signals.filter(function (s) { return severityOf(s).rank < 4; });
  const passed = signals.filter(function (s) { return severityOf(s).rank >= 4; });

  const findings = CardService.newCardSection().setHeader("FINDINGS (" + risks.length + ")");
  if (risks.length === 0) {
    findings.addWidget(CardService.newTextParagraph().setText(
      colored("No risk indicators were found by the checks that ran.", COLORS.green)));
  }
  risks.forEach(function (s, i) {
    if (i > 0) findings.addWidget(CardService.newDivider());
    findings.addWidget(signalWidget(s));
  });

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("MailGuard").setSubtitle("Email security analysis"))
    .addSection(overview)
    .addSection(findings);

  if (passed.length > 0) {
    const ok = CardService.newCardSection().setHeader("PASSED CHECKS (" + passed.length + ")")
      .setCollapsible(true).setNumUncollapsibleWidgets(0);
    passed.forEach(function (s) { ok.addWidget(signalWidget(s)); });
    card.addSection(ok);
  }

  return card.addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(
    colored("Engine v" + result.engine_version + " | Advisory result. Message text is analyzed on the MailGuard " +
            "backend; attachment files are never uploaded, only name, type, size and hash.", COLORS.muted))))
    .build();
}

function errorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("MailGuard").setSubtitle("Email security analysis"))
    .addSection(CardService.newCardSection().setHeader("ANALYSIS UNAVAILABLE")
      .addWidget(CardService.newTextParagraph().setText(colored(message, COLORS.amber, true)))
      .addWidget(CardService.newTextParagraph().setText(
        colored("No verdict was produced. Treat this email with caution.", COLORS.gray))))
    .build();
}
