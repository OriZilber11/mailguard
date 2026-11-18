/** Entry point: Gmail calls this every time an email is opened. */
function onOpenMessage(e) {
  try {
    const payload = buildPayload(e.gmail.messageId, e.gmail.accessToken);
    const result = analyze(payload);
    return resultCard(result);
  } catch (err) {
    console.error(err);
    return errorCard("Couldn't analyze this email; treat it with caution.");
  }
}
