export function initAnalytics() {
  // loaded on every page, before any consent
  gtag("config", "G-XXXX");
  loadScript("https://www.google-analytics.com/analytics.js");
}
