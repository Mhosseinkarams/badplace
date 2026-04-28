/**
 * Simple HTTP Relay — Google Apps Script
 * ======================================
 * نسخه ساده‌تر برای تست
 */

function doPost(e) {
  try {
    const payload = JSON.parse(e.postData.contents);

    // Make the request
    const response = UrlFetchApp.fetch(payload.url, {
      method: payload.method || 'GET',
      headers: payload.headers || {},
      muteHttpExceptions: true,
      followRedirects: true
    });

    // Return response
    return ContentService.createTextOutput(JSON.stringify({
      status: response.getResponseCode(),
      headers: response.getAllHeaders(),
      body: response.getContentText()
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      error: error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "ok",
    message: "Simple HTTP Relay is working"
  })).setMimeType(ContentService.MimeType.JSON);
}