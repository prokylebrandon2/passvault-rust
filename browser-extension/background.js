// The only job of the service worker: wipe the unlocked logins when the idle timer fires.
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'silk-lock') chrome.storage.session.remove('unlocked');
});
