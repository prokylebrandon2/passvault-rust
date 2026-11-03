// Which saved logins belong to a page. Same rule as core/src/autofill.rs::url_matches:
// a login matches when its host is the page's host or a parent domain of it.

export function hostOf(url) {
  const u = (url || '').trim().toLowerCase();
  const rest = u.includes('://') ? u.split('://')[1] : u;
  let host = rest.split('/')[0].split('?')[0].split('#')[0];
  host = host.includes('@') ? host.split('@').pop() : host;
  host = host.split(':')[0];
  return host.startsWith('www.') ? host.slice(4) : host;
}

export function urlMatches(entryUrl, pageUrl) {
  const u = (entryUrl || '').trim().toLowerCase();
  if (!u || u.startsWith('androidapp://')) return false;
  let page;
  try {
    page = new URL(pageUrl);
  } catch {
    return false;
  }
  if (page.protocol !== 'https:' && page.protocol !== 'http:') return false;
  const host = hostOf(u);
  const domain = hostOf(page.hostname);
  return host !== '' && (domain === host || domain.endsWith(`.${host}`));
}
