/** Reads the opened email and returns the JSON body the backend expects. */
function buildPayload(messageId, accessToken) {
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const msg = GmailApp.getMessageById(messageId);

  // Raw source = headers, blank line, body. Keep only the headers part.
  const raw = msg.getRawContent();
  const headers = raw.split(/\r?\n\r?\n/, 1)[0];

  const attachments = msg.getAttachments({ includeInlineImages: false }).map(function (a) {
    const bytes = a.getBytes();
    return {
      filename: a.getName(),
      content_type: a.getContentType(),
      size: bytes.length,
      sha256: toHex(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes)),
      magic_b64: Utilities.base64Encode(bytes.slice(0, 16)) // only 16 bytes leave Gmail
    };
  });

  return {
    headers_raw: headers.slice(0, 128000),
    body_text: msg.getPlainBody().slice(0, 256000),
    body_html: msg.getBody().slice(0, 512000),
    attachments: attachments
  };
}

function toHex(bytes) {
  return bytes.map(function (b) { return ((b & 0xff) + 0x100).toString(16).slice(1); }).join("");
}
