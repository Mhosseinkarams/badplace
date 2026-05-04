/**
 * HTTP/HTTPS Relay Proxy — Google Apps Script
 * ============================================
 * این اسکریپت به عنوان relay برای عبور از فیلترینگ ایران کار می‌کند.
 * فقط script.google.com و script.googleusercontent.com نیاز است باز باشند.
 * 
 * نحوه استفاده:
 * 1. به script.google.com بروید
 * 2. پروژه جدید بسازید
 * 3. این کد را کپی کنید
 * 4. Deploy → New deployment → Web app
 * 5. Execute as: Me
 * 6. Who has access: Anyone
 * 7. URL را در config.local.yaml قرار دهید
 */

function doPost(e) {
  try {
    if (!e.postData || !e.postData.contents) {
      return jsonOut({ error: "No POST data provided" });
    }

    const payload = JSON.parse(e.postData.contents);

    // --- Basic validation ---
    if (!payload.method || !payload.url) {
      return jsonOut({
        error: "Invalid payload",
        message: "Fields 'method' and 'url' are required"
      });
    }

    const method = String(payload.method).trim().toUpperCase();
    const url = String(payload.url).trim();
    const headers = payload.headers || {};

    // --- Body preparation ---
    let body = null;

    if (payload.body_b64) {
      try {
        const decodedBytes = Utilities.base64Decode(payload.body_b64);
        // Always treat as raw bytes – keep it as a Blob to avoid corrupting binary data
        body = Utilities.newBlob(decodedBytes);
      } catch (b64Error) {
        return jsonOut({ error: "Invalid Base64 body", details: b64Error.message });
      }
    } else if (payload.body !== undefined && payload.body !== null) {
      // Plain text body
      body = String(payload.body);
    }

    // --- Build fetch options ---
    const options = {
      method: method,
      headers: headers,
      muteHttpExceptions: true,
      followRedirects: payload.followRedirects !== undefined ? payload.followRedirects : true,
      validateHttpsCertificates: payload.validateSsl !== undefined ? payload.validateSsl : true
    };

    // Attach body for write methods
    if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && body !== null) {
      options.payload = body;
    }

    // Explicit content type if provided
    if (payload.contentType) {
      options.contentType = payload.contentType;
    }

    // --- Execute fetch ---
    const response = UrlFetchApp.fetch(url, options);
    const responseCode = response.getResponseCode();
    const responseHeaders = response.getAllHeaders();
    const responseBytes = response.getContent();

    // Decide how to return the body:
    //   - if it's text, return as plain string
    //   - otherwise, base64‑encode and return
    let result;
    try {
      // Attempt to decode as UTF‑8 text
      const textBody = Utilities.newBlob(responseBytes).getDataAsString();
      result = {
        status: responseCode,
        headers: responseHeaders,
        body: textBody
      };
    } catch (_) {
      // Binary content → return base64
      result = {
        status: responseCode,
        headers: responseHeaders,
        body_b64: Utilities.base64Encode(responseBytes)
      };
    }

    return jsonOut(result);

  } catch (error) {
    console.error("Relay Error:", error);
    return jsonOut({
      error: true,
      message: error.message,
      stack: error.stack || null
    });
  }
}

/**
 * GET endpoint (health check)
 */
function doGet(e) {
  return jsonOut({
    status: "ok",
    service: "HTTP/HTTPS Relay Proxy",
    version: "3.2",
    message: "Send POST requests to relay HTTP calls.",
    note: "Optimized for Iranian filtering conditions"
  });
}

/**
 * Helper: Safe JSON output
 */
function jsonOut(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
