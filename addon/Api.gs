/** Sends the payload to the backend. Set BACKEND_URL in Project Settings > Script properties. */
function analyze(payload) {
  const base = PropertiesService.getScriptProperties().getProperty("BACKEND_URL");
  if (!base) throw new Error("BACKEND_URL script property is not set");

  const res = UrlFetchApp.fetch(base.replace(/\/$/, "") + "/v1/analyze", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    headers: { "ngrok-skip-browser-warning": "1", Authorization: "Bearer " + ScriptApp.getIdentityToken() },
    muteHttpExceptions: true // so we can read error status codes ourselves
  });
  if (res.getResponseCode() !== 200) {
    throw new Error("Backend returned " + res.getResponseCode());
  }
  return JSON.parse(res.getContentText());
}
