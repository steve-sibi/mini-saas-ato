window.addEventListener('DOMContentLoaded', () => {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  const lang = navigator.language || '';
  const res = `${window.screen.width}x${window.screen.height}`; // screen resolution
  const cores = navigator.hardwareConcurrency || '';             // CPU cores (approx)
  const plat = navigator.platform || '';                        // OS hint (legacy)
  const entropy = [tz, lang, res, cores, plat].join('|');

  const el = document.getElementById('device_data');
  if (el) el.value = entropy;
});
