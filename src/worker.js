// aew-website: serves the static site. /api/* and /auth/* go to the aew-forms Worker over a service binding,
// so sign-in cookies and the orb's task calls stay on aiemployeeworkflow.com. Everything else is a static file.
const API_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
};
export default {
  async fetch(req, env) {
    const { pathname } = new URL(req.url);
    if (pathname.startsWith('/api/') || pathname.startsWith('/auth/')) {
      // The Mac Mini bridge talks to aew-forms on workers.dev; its endpoints aren't served on the public site
      if (pathname.startsWith('/api/agent/')) return new Response('not found', { status: 404 });
      const r = await env.FORMS.fetch(new Request(req, { redirect: 'manual' }));
      const h = new Headers(r.headers);
      for (const [k, v] of Object.entries(API_HEADERS)) h.set(k, v);
      if (!h.has('Cache-Control')) h.set('Cache-Control', 'no-store');
      return new Response(r.body, { status: r.status, statusText: r.statusText, headers: h });
    }
    return env.ASSETS.fetch(req);
  }
};
