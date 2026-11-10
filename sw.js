// CRM Meyaclo — service worker minimal : rend l'appli installable sur téléphone.
// Aucune mise en cache : le CRM affiche toujours la dernière version et les données en direct.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
