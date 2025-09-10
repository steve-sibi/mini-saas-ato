window.addEventListener('DOMContentLoaded', () => {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const lang = navigator.language;
  const entropy = `${tz}|${lang}`;
  const el = document.getElementById('device_data');
  if (el) el.value = entropy;
});
