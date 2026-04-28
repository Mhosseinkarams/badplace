/**
 * HTTP/HTTPS Relay Proxy — Google Apps Script v2.0
 * =================================================
 *
 * این اسکریپت به عنوان یک relay عمل می‌کند که درخواست‌های HTTP را
 * از طریق Google Apps Script به مقصد نهایی ارسال می‌کند.
 *
 * نحوه استفاده:
 * 1. این کد را در Google Apps Script Editor کپی کنید
 * 2. File → New → Script
 * 3. کد را paste کنید
 * 4. Deploy → New deployment
 * 5. Type: Web app
 * 6. Execute as: Me
 * 7. Who has access: Anyone
 * 8. Deploy و URL را کپی کنید
 * 9. URL را در config.local.yaml یا APPS_SCRIPT_URL قرار دهید
 */

/**
 * Handler اصلی برای درخواست‌های POST
 * Google Apps Script بعد از ریدایرکت، درخواست POST را اینجا پردازش می‌کند
 */
function doPost(e) {
  try {
    const payload = JSON.parse(e.postData.contents);

    if (!payload.method || !payload.url) {
      return ContentService
        .createTextOutput(JSON.stringify({error: "Invalid payload: method and url are required"}))
        .setMimeType(ContentService.MimeType.JSON);
    }

    const method = payload.method.toUpperCase();
    const url = payload.url;
    const headers = payload.headers || {};
    const body = payload.body;

    console.log(`[${method}] ${url}`);

    const options = {
      method: method,
      headers: headers,
      muteHttpExceptions: true,
      followRedirects: true
    };

    if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && body) {
      options.payload = body;
    }

    const response = UrlFetchApp.fetch(url, options);
    const responseCode = response.getResponseCode();
    const responseBody = response.getContentText();

    console.log(`Response: ${responseCode}`);

    return ContentService
      .createTextOutput(JSON.stringify({status: responseCode, body: responseBody}))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    console.error("Error:", error);
    return ContentService
      .createTextOutput(JSON.stringify({error: error.toString(), message: "Relay error occurred"}))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

/**
 * Handler برای درخواست‌های GET (برای تست)
 */
function doGet(e) {
  return ContentService
    .createTextOutput(JSON.stringify({
      status: "ok",
      service: "HTTP/HTTPS Relay Proxy",
      version: "2.0",
      message: "Use POST to relay HTTP requests"
    }))
    .setMimeType(ContentService.MimeType.JSON);
}