// Sets a flag so https://fda-wishlist-finds-protection.trycloudflare.com/app/install.html can detect that PhishGuard is already installed
try {
  window.phishGuardInstalled = true;
  document.documentElement.setAttribute('data-phishguard-installed', 'true');
  // Also dispatch an event for the page to listen to
  window.dispatchEvent(new CustomEvent('phishguard-installed', { detail: { installed: true } }));
} catch (e) {}
