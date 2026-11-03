// The only job of the service worker: wipe the unlocked logins when the idle timer fires.
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'pv-lock') chrome.storage.session.remove('unlocked');
});
