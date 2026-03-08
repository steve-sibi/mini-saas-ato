window.addEventListener("DOMContentLoaded", () => {
  const token = document.body.dataset.csrfToken || "";
  const csrfCookieName = document.body.dataset.csrfCookieName || "ato_csrf";
  if (token) {
    document.cookie = `${csrfCookieName}=${token}; path=/; samesite=lax`;
  }

  const entropyParts = [
    Intl.DateTimeFormat().resolvedOptions().timeZone || "",
    navigator.language || "",
    navigator.platform || "",
    `${window.screen.width}x${window.screen.height}`,
    String(navigator.hardwareConcurrency || ""),
  ];
  const entropy = encodeURIComponent(entropyParts.join("|"));
  document.cookie = `device_entropy=${entropy}; path=/; samesite=lax`;

  document.body.addEventListener("htmx:configRequest", (event) => {
    if (token) {
      event.detail.headers["X-CSRF-Token"] = token;
    }
  });
});
