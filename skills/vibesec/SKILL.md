---
name: vibesec
description: Security audit of a web application codebase and its deploy setup (Next.js, Supabase, auth, payments, OTP, LLM and MCP features, DNS). Use when asked to audit security, find vulnerabilities, check for a CVE, review auth, RLS, headers, secrets or rate limits, or to run a pre-launch security check. Read-only; the only file it writes is vibesec-report.md.
argument-hint: [folder]
---

# vibeSec security audit

You are auditing this project for the 48 vulnerability classes below plus leaked secrets.

The person running this is often not a developer. They built the app with AI and need to know
what is wrong, how bad it is, and what to change, without security jargon.

Scope: `$ARGUMENTS`. If that is empty, audit the whole project from its root. If it names a
folder, read code only under that folder, but still read root-level config (package manifests,
framework config, env files, deploy config, database migrations and policies) because the
checks depend on them.

## Rules

1. Read the real code, config, env files, migrations, policies and deploy setup. Never infer a
   finding from a file name, a framework default or general knowledge. If you cannot see the
   evidence, the status is "Needs manual check" and you say what to look at.
2. Never change code, config, data or git state. The only file you write is
   `vibesec-report.md` in the project root. Fixes happen later, one at a time, only after the
   user says yes to a specific one.
3. Never print the value of a secret you find. Quote the file, the line and the first 4
   characters followed by `...`.
4. Prefer the project's own stack. A fix snippet uses the framework, ORM and libraries the
   project already has.
5. Do not run the application, install packages, hit production endpoints with anything other
   than a HEAD or GET of a public URL the user gave you, or run scanners that send traffic.
   Never send attack payloads (smuggled requests, malicious headers, long regex inputs, stream
   floods, forged tokens) to any live system, even when a check below describes one.
6. Write for a non-developer. Explain **Why** and **Exploit** in plain English first ("anyone
   can read every customer's invoice"), then the technical detail. Name a term the first time
   you use it ("RLS, the rule that decides who can read a row").

## Step 1. Discovery (do this before any check)

Build a map of the project and keep it in the report's first section:

- Framework and versions: read `package.json`, lockfile, `next.config.*`, `middleware.ts`,
  `app/` or `pages/` layout, `vercel.json`, `netlify.toml`, `Dockerfile`, `fly.toml`,
  `railway.json`, GitHub Actions workflows.
- Backend: Supabase (`supabase/config.toml`, `supabase/migrations/`, `supabase/functions/`),
  Prisma or Drizzle schemas, custom API routes, serverless functions, edge functions.
- Auth: provider and flow, session storage, JWT handling, password reset, OTP and SMS paths,
  OAuth callbacks, account linking.
- Payments: Stripe, Paddle, LemonSqueezy, in-app purchase, any checkout or price logic.
- LLM and MCP: any call to Anthropic, OpenAI, Google, local models, tool use, MCP servers,
  prompts assembled from user data, retrieval of web pages or files.
- Secrets surface: every `.env*` file, `*.example` files, CI secrets usage, client bundles
  (`NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`, `VITE_*`), hardcoded keys.
- Public surface: domains, subdomains and DNS records you can read from config, deploy files
  or docs; storage buckets; public API routes; redirect helpers.
- Server and edge: who terminates HTTP (managed host, CDN, own nginx or proxy), caching rules,
  GraphQL endpoints, WebSocket or realtime servers, SSO (SAML, Entra), XML parsing, template
  engines, any custom crypto.

List every file you read. A check you could not evidence from files is "Needs manual check".

## Step 2. The checks

For every item produce exactly these fields:

- **Status**: Vulnerable / Safe / Not applicable / Needs manual check
- **Where**: file and line(s), or "no such code" for Not applicable
- **Why**: the evidence, in one or two sentences
- **Exploit**: how an attacker would use it, concretely
- **Fix**: the change, with a code snippet in the project's stack

The checks:

### 1. Next.js headers and middleware bypass
- CVE-2025-29927: a request carrying `x-middleware-subrequest` skips middleware on Next.js
  11.1.4 to 15.2.2 (fixed in 15.2.3, 14.2.25, 13.5.9, 12.3.5). Read the installed version in
  the lockfile, not the caret range. If middleware is the only auth gate for any route, that is
  Critical. Check whether the host (Vercel, Netlify) strips the header; self-hosted does not.
- Outdated Next.js in general: compare the installed version with the latest patch of its
  major line.
- Security headers: look for `headers()` in `next.config.*`, middleware `response.headers`,
  `vercel.json` headers, a CDN or proxy config. Required: `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Frame-Options` or CSP `frame-ancestors`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`. A CSP with `unsafe-inline` for scripts
  and no nonce is a finding, not Safe.

### 2. .git exposed
- Is `.git/` inside any directory that gets served or copied into the build output or image?
  Read `Dockerfile` COPY lines, `.dockerignore`, `vercel.json`, `public/`, static export
  output, nginx or Caddy roots.
- Manual: `GET https://<site>/.git/HEAD` must not return `ref:`.

### 3. Supabase storage
- Read every `storage.buckets` insert and every policy on `storage.objects` in migrations and
  in any schema dump. Public buckets (`public = true`) holding user uploads, documents, IDs,
  invoices or anything tied to a person are a finding.
- Weak storage RLS: policies with `USING (true)`, policies granted to `anon` on non-public
  content, policies without a `TO` role, read policies on buckets that should be owner-only.
- Guessable paths: object keys built from sequential IDs, user IDs, emails or dates in a
  public bucket. Signed URLs with very long expiry stored in the database.

### 4. Price from the browser
- Find every checkout, order, cart, subscription or credit purchase handler. Trace where
  `price`, `amount`, `total`, `discount`, `coupon`, `quantity` and `currency` come from. Any of
  them read from the request body, query string, cookie or client-side state and passed to
  the payment provider or written to an order is Critical.
- Safe looks like: server looks up the price by product or price ID, validates quantity bounds,
  applies discounts server-side, and verifies the provider webhook signature before fulfilment.

### 5. Credential stuffing
- Login, OTP verify and token exchange endpoints: is there a rate limit (per IP and per
  account), progressive delay or lockout, captcha or proof-of-work on failures, and a
  breached-password check (HIBP k-anonymity or provider setting)? Read middleware, API routes,
  edge functions, Supabase Auth settings in `config.toml` and any Upstash, Redis or
  database-backed limiter.
- Hosted-auth projects: report what the provider enforces by default and what the project
  turned on; the provider's dashboard settings are "Needs manual check".

### 6. Open database
- Every table in `public` (and any other exposed schema) with RLS disabled, or enabled with no
  policy, or with a policy `USING (true)` for `anon` or `authenticated` on sensitive data.
  Read migrations and schema dumps; list tables by name.
- `service_role` key anywhere the client can see it: `NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`,
  `VITE_*`, mobile app code, HTML, committed env files.
- Anon key reaching sensitive tables or RPCs: functions granted to `anon`, views that bypass
  RLS, `SECURITY DEFINER` functions without an `auth.uid()` check.
- Database open to the internet: direct Postgres connection strings in client code, firewall or
  allow-list settings in deploy config, default ports exposed in Docker compose.

### 7. Polyfill.io and third-party scripts
- Any `<script src>` or `next/script` pointing at `polyfill.io`, `cdn.polyfill.io`,
  `bootcdn`, `staticfile`, `unpkg` or `jsdelivr` without a pinned version and
  Subresource Integrity (`integrity=` plus `crossorigin`). Also tag managers and analytics
  loaded from third parties without a CSP that limits them.

### 8. SMS pumping
- OTP send, SMS send, WhatsApp send, phone verification endpoints: rate limit per phone, per IP
  and global; country or prefix allow-list; captcha or signed challenge before the first send;
  cooldown between sends; cap per day. Premium-rate and high-fraud prefixes allowed means
  Vulnerable. Read the edge function or API route, provider settings in config and any
  limiter table.

### 9. Prompt injection
- For each LLM or MCP feature: where do untrusted inputs enter the prompt (user text, fetched
  pages, uploaded files, database rows written by other users, tool results)? Can that input
  change instructions, reveal the system prompt or secrets, or cause a tool call the user did
  not ask for? Are tool calls that write, pay, send or delete gated by server-side permission
  checks that do not depend on the model? Are model outputs rendered as HTML or executed?
- Safe looks like: untrusted content wrapped and labelled as data, tools scoped per user with
  least privilege, destructive tools confirmed out of band, no secrets in prompts, output
  escaped.

### 10. Weak JWT
- Secret length and source (short, default, example value, committed to git), `alg: none` or
  algorithm not pinned on verify, tokens decoded without signature verification
  (`jwt.decode` where `verify` was meant, `atob` on the payload then trusted), access tokens
  with expiry over 1 hour or refresh tokens that never rotate, claims trusted from the client.
- Hosted auth: check that the server verifies with the provider's JWKS or `getUser()`, not
  by trusting a cookie or `getSession()` alone in server code.
- Algorithm confusion: an RS256 public key that can also be used as an HS256 secret (a verify
  call that accepts both families with the same key), `alg` read from the token header and
  passed to verify, `jku`, `x5u` or `kid` headers used to fetch or pick a key without an
  allow-list (`kid` reaching a file path or SQL query is also #15 or injection). Safe: the
  allowed algorithms are pinned in the verify call (`algorithms: ['RS256']`), one key per
  algorithm, keys only from a fixed JWKS URL.

### 11. Race conditions
- Coupons, promo codes, invite codes, referral rewards, credits, balances, inventory, one-time
  tokens: is redemption guarded by a transaction with row lock (`SELECT ... FOR UPDATE`), an
  atomic `UPDATE ... WHERE used_at IS NULL RETURNING`, a unique constraint, or an idempotency
  key? A read-then-write across two queries without any of those is Vulnerable.

### 12. Account pre-hijacking
- Can someone create an account with a victim's email before the victim signs up, and does a
  later OAuth or magic-link sign-in merge into that account? Is email verified before it is
  used to match accounts? Are OAuth accounts linked only when the provider reports the email
  as verified? Can a password be set on an OAuth-only account without re-authentication?

### 13. Subdomain takeover
- Collect every hostname from DNS config files, deploy config, docs, CORS allow-lists,
  `NEXT_PUBLIC_*` URLs and marketing config. For each, note the target (Vercel, Netlify,
  Railway, Heroku, S3, GitHub Pages, Azure, Fastly) and whether the project still has that
  resource. Dangling CNAME or NS records are Vulnerable. Use `dig` only if available; otherwise
  this is "Needs manual check" with the exact hostnames to test.

### 14. SSRF
- Any server code that fetches a URL supplied by a user or stored from user input (importers,
  link previews, webhooks, image proxies, PDF fetchers, OAuth discovery). Safe requires:
  scheme allow-list (https only), DNS resolution checked against private, loopback,
  link-local and metadata ranges (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`,
  `::1`, `fc00::/7`, `fe80::/10`), redirects re-validated, response size and time limits.
  Blocking only the literal string `169.254.169.254` is not enough (decimal, hex, IPv6-mapped
  and DNS rebinding bypass it).

### 15. Path traversal
- User input in file paths, upload destinations, download handlers, storage keys, template or
  include paths, zip extraction. Look for `path.join` or string concatenation with request
  data without `path.resolve` plus a prefix check, missing normalisation, `..` or encoded
  `%2e%2e` not rejected, filenames taken from `Content-Disposition` or the multipart field.

### 16. Password reset poisoning
- Reset or magic-link URLs built from `Host`, `X-Forwarded-Host`, `Origin`, `Referer` or
  `request.url` instead of a fixed configured origin. Tokens that are reusable, do not expire,
  expire after more than 1 hour, survive a password change, or are not invalidated when a new
  one is issued. Redirect-after-reset parameters that accept any URL.

### 17. Source maps in production
- `productionBrowserSourceMaps: true`, Sentry or similar config uploading and also deploying
  `.map` files, a `.map` file in build output or `public/`, `GENERATE_SOURCEMAP` not false in
  CRA or Vite `build.sourcemap` true. Manual: request any `.js.map` next to a production bundle.

### 18. Clickjacking
- Login, payment, settings, invite acceptance and consent pages reachable in a frame: no
  `X-Frame-Options: DENY` or `SAMEORIGIN` and no CSP `frame-ancestors`. Check route-level
  overrides that remove the header.

### 19. Open redirect
- Parameters named `redirect`, `redirect_to`, `redirectTo`, `next`, `return`, `returnUrl`,
  `returnTo`, `callback`, `callbackUrl`, `url`, `continue`, `dest` and the OAuth `state` or
  `redirect_uri` handling. Safe requires an allow-list of exact origins or relative paths that
  start with a single `/` and not `//` or `/\`. Protocol-relative URLs, `javascript:`, and
  `https://trusted.com.evil.com` must be rejected.

### 20. User enumeration
- Do login, sign-up, forgot-password, invite and OTP responses differ by text, status code,
  response shape or timing depending on whether the email or phone exists? Sign-up that says
  "already registered", reset that says "no account", OTP send that errors for unknown phones.
  Hosted auth providers often leak this by default; report the provider setting as "Needs
  manual check" if it cannot be read from config.
- Timing: login that returns early for unknown users without hashing (run a dummy hash so
  both paths take the same time), and secrets compared with `==`, `===`, `!=` or
  `.equals()`: API keys, webhook signatures (`stripe-signature`, HMAC of a body), reset and
  invite tokens, OTP codes, admin passwords from env. A byte-by-byte compare leaks how many
  leading characters were right. Fix: `crypto.timingSafeEqual` on equal-length buffers (check
  length first), `hmac.compare_digest` in Python, `secure_compare` in Rails, or the provider
  SDK's own verify (`stripe.webhooks.constructEvent`).

### 21. HTTP/2 Rapid Reset (CVE-2023-44487)
- Only for servers the project runs itself: a custom Node `http2` server, nginx, Caddy,
  HAProxy, Envoy, Go `net/http`, Java or .NET servers in `Dockerfile`, compose files, `fly.toml`
  or k8s manifests. Read the pinned image or binary version. Vulnerable before: Node 18.18.2
  and 20.8.1, nginx 1.25.3, Go 1.21.3, Envoy 1.27.1, HAProxy and Caddy releases of Oct 2023.
  Also look for limits: nginx `http2_max_concurrent_streams`, `keepalive_requests`.
- Fully managed hosting (Vercel, Netlify, Cloudflare, Render, Supabase) is Not applicable; say
  the provider patched it at the edge.
- Fix: upgrade the server or base image, cap concurrent streams, or put it behind a patched
  CDN or managed proxy.

### 22. bcrypt 72-byte truncation
- bcrypt reads only the first 72 bytes of its input and ignores the rest. Find every
  `bcrypt.hash`, `bcrypt.compare`, `hashpw`, `password_hash(PASSWORD_BCRYPT)`. Vulnerable if
  the input is several fields joined together (`userId + username + password`, cache keys,
  API key derivation): a long username pushes the password past byte 72, so any password
  matches. Also a finding: no maximum password length, so two long passwords that share a
  72-byte prefix are the same password.
- Fix: hash only the password, reject passwords over 72 bytes (count bytes, not characters,
  because emoji take 4), or pre-hash with HMAC-SHA256 then bcrypt, or move to argon2id. Never
  use bcrypt as a general-purpose hash or cache key.

### 23. SAML bypass
- Any SAML SSO: `samlify`, `passport-saml`, `@node-saml/node-saml`, `saml2-js`, `xml-crypto`,
  `ruby-saml`, `python3-saml`, `onelogin`, BoxyHQ or a custom XML verifier. Read the installed
  version in the lockfile and compare with its latest advisories (`xml-crypto` before 6.0.1,
  `ruby-saml` before 1.18.0 had signature bypasses in 2024 and 2025).
- In the config: `wantAssertionsSigned` off, only the response (not the assertion) signed,
  audience, issuer, `NotBefore`/`NotOnOrAfter` or `InResponseTo` not checked, the IdP
  certificate taken from the message instead of pinned config.
- Exploit: a signed element is wrapped and a forged assertion added (XML signature wrapping),
  so the attacker logs in as any user, including admins.
- Fix: upgrade the library, require signed assertions, pin the IdP certificate, validate
  audience, issuer, time window and `InResponseTo`, reject replayed assertion IDs.

### 24. nOAuth email spoof
- OAuth or OIDC logins (Microsoft Entra / Azure AD above all, also any multi-tenant provider
  or "Sign in with X" where users can edit their own email) that find or link the local user
  by the `email`, `preferred_username` or `upn` claim. In Entra the `email` claim is editable
  and unverified, so an attacker sets it to the victim's address and logs in as them.
- Read NextAuth/Auth.js callbacks (`signIn`, `jwt`), `allowDangerousEmailAccountLinking`,
  Supabase identity linking settings, Clerk or custom `findUserByEmail` after OAuth.
- Fix: key accounts on the immutable `sub` plus issuer (or `oid` plus `tid` for Entra), trust
  an email only when the provider marks it verified (`email_verified: true`), never auto-merge
  accounts on email. Related to #12.

### 25. GraphQL aliases and batching
- Any GraphQL server (Apollo, Yoga, Mercurius, Hasura, pg_graphql, Supabase GraphQL, Hot
  Chocolate, graphene). One request can call the same mutation 1,000 times under different
  aliases (`a1: login(...) a2: login(...)`), or send an array of operations, so a per-request
  rate limit lets through 1,000 password, OTP or coupon guesses per request.
- Look for: depth limit, cost or complexity limit, alias and batch caps, introspection
  disabled in production, rate limits keyed per operation or per resolver call.
- Fix: `graphql-depth-limit`, `graphql-query-complexity` or Armor, cap aliases and batch
  size, rate-limit sensitive resolvers inside the resolver, disable introspection in prod.

### 26. 2FA and OTP code replay
- TOTP (authenticator app), email or SMS codes, backup codes. Vulnerable if: a code that
  already worked works again inside its window, there is no limit on wrong attempts per code
  or per account (a 6-digit code falls to 1 million guesses), the verify endpoint does not
  check the code belongs to this user and this purpose, or the 2FA step can be skipped by
  calling the next endpoint directly.
- Fix: store the last used TOTP time step per user and reject the same or older step, delete
  or mark one-time codes used in the same atomic update that checks them (see #11), lock out
  after 5 failures, expire codes in 10 minutes or less, enforce 2FA on the server, not only
  in the UI.

### 27. ReDoS (regex denial of service)
- Regexes that take exponential time on crafted input, run on user input: nested quantifiers
  `(a+)+`, `(\w+)*`, `(.*)*`, overlapping alternation `(a|a)*` or `(\w|\d)+`, in validators
  (email, URL, slug, phone), routing, markdown or log parsing, `new RegExp(userInput)`. Also
  outdated packages with ReDoS advisories (`ua-parser-js`, `semver`, `path-to-regexp`,
  `validator`, `moment`); read their versions.
- Exploit: one request with a 50-character string pins a CPU core for minutes; a few of them
  take the server down.
- Fix: rewrite the pattern without nested quantifiers, use RE2 (`re2` npm package) or a
  library validator, cap input length before matching, never build a regex from user input
  without escaping it.

### 28. HTTP request smuggling
- Applies when there are two HTTP parsers in a row the project controls: a proxy or load
  balancer (nginx, HAProxy, Caddy, Traefik, AWS ALB, Varnish) in front of an app server, or
  any custom HTTP parsing. Read proxy and server versions and config. Red flags: outdated
  proxy, HTTP/1.1 between proxy and app, the proxy forwarding both `Content-Length` and
  `Transfer-Encoding`, Node started with `--insecure-http-parser`, custom header parsing.
- Fully managed hosting with no own proxy is Not applicable.
- Exploit: a request hides a second request inside its body, which the backend treats as the
  next user's request, stealing their session or bypassing front-end auth rules.
- Fix: upgrade proxy and server, reject requests that carry both headers, use HTTP/2 end to
  end, never enable lenient parsing.

### 29. Web cache poisoning and deception
- CDN or framework caches: `Cache-Control: public` or `s-maxage` on routes, ISR or
  `revalidate`, `vercel.json` or Cloudflare cache rules, nginx `proxy_cache`, Varnish. Vulnerable
  if a cached response changes with a header that is not part of the cache key
  (`X-Forwarded-Host` used to build URLs, `X-Original-URL`, `X-HTTP-Method-Override`, a
  language or user-agent header without `Vary`), or a cached response contains one user's data
  (cache deception: `/account/profile.css` served by the account page and cached).
- Fix: `Cache-Control: private, no-store` on anything that depends on the session, cache keys
  or `Vary` covering every input that changes the response, ignore forwarding headers unless
  set by your own proxy, never cache by file extension alone.

### 30. Spoofed client IP headers
- Rate limits, IP allow-lists, geo blocks, fraud scores or audit logs that read
  `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` or `Forwarded`
  directly. Anyone can send these headers, so the attacker gets a fresh "IP" per request and
  every limit in #5, #8 and #26 stops working.
- Read how the IP is taken: `req.headers['x-forwarded-for']`, `split(',')[0]` (the first entry
  is the one the client controls), Express `trust proxy` set to `true`.
- Fix: use the platform's verified IP (`request.ip` on Vercel, `CF-Connecting-IP` only when
  the origin accepts traffic from Cloudflare alone, Express `trust proxy` set to the exact
  number of proxies), or take the right-most entry added by your own proxy.

### 31. Views and functions that bypass RLS
- Postgres views run with the rights of their owner (usually `postgres`), so RLS on the
  tables underneath is skipped. Find every `create view` and `create materialized view` in
  `public` or any exposed schema. Vulnerable if `security_invoker = true` is missing and the
  view exposes a table with RLS. Materialized views have no RLS at all.
- `SECURITY DEFINER` functions in exposed schemas callable by `anon` or `authenticated`
  without an `auth.uid()` check, or without `set search_path = ''`.
- Fix: `create view ... with (security_invoker = true)`, `revoke select on <view> from anon,
  authenticated` where it should not be public, move materialized views and definer functions
  to a private schema, add the owner check and a fixed `search_path`. Supabase's database
  linter flags these; suggest running it as a manual check. Extends #6.

### 32. Weak random tokens
- `Math.random()`, `Date.now()`, `uuid` v1, `random.random()`, `rand()`, short counters, or
  hashes of the email or timestamp used for anything secret: password reset and magic link
  tokens, invite and referral codes, session IDs, API keys, OTPs, unguessable file or share
  URLs.
- Exploit: these values are predictable; an attacker who sees a few can compute the next ones
  and reset someone's password or open their shared file.
- Fix: `crypto.randomBytes(32).toString('base64url')`, `crypto.randomUUID()`,
  `crypto.getRandomValues` in the browser or edge, `secrets.token_urlsafe(32)` in Python. At
  least 128 bits for tokens; OTPs via `crypto.randomInt(0, 1_000_000)`.

### 33. Padding oracle and home-made encryption
- Custom encryption of cookies, tokens, share links or stored data: `aes-*-cbc` or `aes-*-ecb`
  in `createCipheriv`, CryptoJS `AES.encrypt` defaults, encryption without a MAC, decrypt
  errors that differ from "bad data" errors, a fixed or reused IV, keys hardcoded or derived
  from a short password without a KDF.
- Exploit: by watching which error comes back, an attacker decrypts and re-encrypts the
  token one byte at a time, then forges a session or admin cookie.
- Fix: AES-256-GCM with a random 12-byte IV per message, or libsodium `secretbox`, or the
  framework's sealed sessions (iron-session, Rails encrypted cookies); one generic error for
  every decrypt failure.

### 34. Prototype pollution
- Deep merge, clone or set helpers on request data: a hand-written recursive merge,
  `lodash.merge`, `_.set`, `_.defaultsDeep`, `deepmerge`, `merge`, `dot-prop`, `qs` with
  nested parsing, `Object.assign` from parsed JSON into a shared object. Vulnerable if keys
  `__proto__`, `constructor` or `prototype` are not rejected, or the library version has a
  prototype pollution advisory.
- Exploit: `{"__proto__":{"isAdmin":true}}` sets `isAdmin` on every object in the server
  process; this can grant admin, bypass checks or, with some template engines, run code.
- Fix: validate the body with a schema (zod, valibot) that strips unknown keys, reject those
  three keys, use `Object.create(null)` or `Map` for lookup tables, upgrade the library.

### 35. Server-side template injection (SSTI)
- User input used as the template source, not as a value: `Handlebars.compile(userText)`,
  `ejs.render(userText)`, `nunjucks.renderString`, `_.template`, Jinja
  `Template(user_input)` or `render_template_string`, Liquid, Pug, Twig. Common in custom email
  templates, invoice or PDF builders, "personalize your message" features and LLM output fed
  to a template.
- Exploit: the attacker writes template code such as `{{7*7}}`, then escalates to reading env
  variables or running commands on the server.
- Fix: templates come only from files you ship; user text is passed as a variable; use a
  logic-less or sandboxed engine (Liquid, Handlebars without custom helpers) for any template
  users may edit; keep autoescaping on.

### 36. XXE (XML external entities)
- Anything that parses XML: SAML (#23), SVG uploads, DOCX, XLSX or PPTX imports, RSS or
  sitemap fetchers, SOAP, XML APIs. Libraries: `libxmljs` with `noent: true`, `xml2js` old
  versions, `fast-xml-parser` with entity processing on, Python `lxml` with
  `resolve_entities=True`, `xml.etree` (use `defusedxml`), Java `DocumentBuilderFactory`
  defaults.
- Exploit: an uploaded file declares an entity pointing at `file:///etc/passwd` or the cloud
  metadata URL, and the server includes that file in its response.
- Fix: disable DTDs and external entities in the parser, use `defusedxml` in Python, convert
  SVGs with a sanitizer, or reject XML you do not need.

### 37. WebSocket hijacking
- WebSocket, Socket.IO, Pusher-style or Supabase Realtime connections. Vulnerable if the
  handshake authenticates with cookies only and does not check `Origin` (another site can open
  a socket as the logged-in user and read their messages), or if any connected user can join
  any room or channel, or messages are not authorized one by one.
- Supabase Realtime: private channels need RLS on `realtime.messages`; Postgres Changes follow
  table RLS (#6).
- Fix: check `Origin` against an allow-list in the upgrade handler, pass a short-lived token in
  the handshake instead of relying on cookies, authorize each channel join and each message
  server-side.

### 38. Unicode username and email takeover
- Usernames, handles or emails that are compared after transformations applied in only some
  places: `toLowerCase()` or NFKC on sign-up but not on reset, or the other way round. Example:
  `ᴮᴵᴳᴮᴵᴿᴰ` normalizes to `bigbird`, so a lookalike account's reset email can land on the real
  account (the Spotify takeover). Also case-sensitive unique indexes that allow `Bob` and
  `bob`, and lookalike handles with Cyrillic letters.
- Read sign-up, login, reset, invite and profile-update code and the unique constraints in the
  schema.
- Fix: canonicalize once (`value.normalize('NFKC').toLowerCase().trim()`) at write time, store
  the canonical form in a unique column (or `citext`), use the same function on every lookup,
  block mixed-script and confusable handles. Related to #12.

### 39. Someone else's data by changing an ID (IDOR)
- The most common bug in AI-built apps. Find every API route, route handler, server action,
  tRPC procedure, RPC and edge function that loads, updates or deletes a record using an ID
  from the URL, query, body or form (`/api/orders/[id]`, `getInvoice(id)`,
  `prisma.order.findUnique({ where: { id } })`, `.from('orders').select().eq('id', id)` with
  the service role key). Vulnerable if nothing ties the record to the logged-in user or their
  organization. Sequential or guessable IDs make it worse but UUIDs do not fix it.
- `userId`, `orgId` or `tenantId` read from the request instead of the verified session is the
  same bug. Supabase calls made with the user's token are covered by RLS (#6); calls made with
  the service role key, Prisma or Drizzle are not.
- Exploit: change `123` to `124` in the address bar or request and see another customer's
  order, invoice, chat or file.
- Fix: scope every query by the session user (`where: { id, userId: session.user.id }`),
  return 404 for records the user does not own, and run user-facing Supabase queries with the
  user's token so RLS applies.

### 40. XSS (attacker code running in your users' browsers)
- User-controlled content put into the page as HTML: `dangerouslySetInnerHTML`, `v-html`,
  `{@html}`, `innerHTML`, `document.write`, `insertAdjacentHTML`; markdown rendered with raw
  HTML allowed (`rehype-raw`, `marked` without sanitizing); LLM output rendered as HTML; links
  with user `href` (a `javascript:` URL runs code on click); user SVG or HTML uploads served
  from your domain (see #45); data put into inline `<script>` tags with `JSON.stringify` and no
  escaping.
- Exploit: a comment, profile name or AI reply containing a script runs in every visitor's
  browser and can act as them or steal their session.
- Fix: render as text (React does this by default), sanitize with DOMPurify when HTML is
  needed, allow only `http`, `https` and `mailto` in user links, and a CSP with nonces (#1).

### 41. SQL and NoSQL injection
- Queries built by joining strings with user input: Prisma `$queryRawUnsafe` or
  `$executeRawUnsafe`, Drizzle `sql.raw`, Knex `raw` with `${}`, `pg` `query()` with template
  strings, Supabase `.or()`, `.filter()` or `.textSearch()` with unescaped user text, plpgsql
  `EXECUTE` with `||`. MongoDB: query objects taken from the request body, so
  `{"password": {"$ne": null}}` matches any password.
- Exploit: input like `' OR 1=1 --` reads, changes or deletes the whole database.
- Fix: parameters (`$queryRaw` tagged template, `sql` tagged template, `$1` placeholders),
  `format('%I', ...)` and `USING` in plpgsql, validate the body with a schema so operators like
  `$ne` cannot get in.

### 42. CORS and CSRF
- CORS: `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials:
  true`, an origin reflected back from the request, or a check like `origin.includes('myapp')`
  or `endsWith('myapp.com')` (which `evilmyapp.com` passes). Read middleware, route handlers,
  `next.config` headers, the `cors` package options and edge functions.
- CSRF: cookie-authenticated handlers that change data (POST, PUT, PATCH, DELETE, and any GET
  that changes data) with no CSRF token, no `Origin` check and cookies without `SameSite`.
  Next.js server actions check `Origin` themselves; custom route handlers do not.
- Exploit: a page on another site makes the logged-in user's browser change their email,
  transfer credits or read their data.
- Fix: an exact list of allowed origins, no credentials with a wildcard, `SameSite=Lax` or
  `Strict` session cookies plus an `Origin` check or CSRF token on every state-changing route.

### 43. Mass assignment
- Request bodies passed straight into a create or update: `prisma.user.update({ data: body })`,
  `.update(req.body)`, `Object.assign(user, body)`, `{ ...body }` into an insert, Supabase
  `.update(body)` from the client on a table with sensitive columns. Vulnerable if the table
  has columns the user must not set: `role`, `is_admin`, `credits`, `balance`, `plan`,
  `org_id`, `user_id`, `email_verified`, `stripe_customer_id`.
- Supabase: an RLS update policy that checks the row owner but not which columns change lets
  any user set their own `role` or `plan` from the browser.
- Exploit: sign up, then send `{"role":"admin"}` with a normal profile update.
- Fix: pick allowed fields explicitly or with a strict schema (zod `.strict()` or `.pick()`);
  in Supabase move sensitive columns to a table users cannot write, or use column grants
  (`revoke update (role) on profiles from authenticated`) or a trigger.

### 44. Unprotected admin pages, server actions and debug routes
- Admin areas hidden only in the UI (a button not shown, a client-side `if (isAdmin)`), pages
  or API routes under `admin`, `internal`, `dashboard`, `manage` with no role check on the
  server, roles read from `user_metadata` (users can edit it) instead of `app_metadata` or a
  server-side table.
- Next.js server actions (`'use server'`) are public POST endpoints anyone can call, even if
  the page that uses them is protected. Every action needs its own auth and role check inside.
- Debug, test, seed, migration, cron and `/api/health` routes that expose data or do work in
  production without a secret; cron routes without `CRON_SECRET` checking.
- Fix: a server-side `requireAdmin()` at the top of every admin route and action, roles from a
  trusted source, delete debug routes or gate them behind an env check and a secret.

### 45. File uploads
- Upload handlers and storage uploads (also #3 and #15): file type trusted from the file name
  or the browser's `Content-Type`, no size limit, HTML, SVG, XML or JS files accepted and later
  served from the main domain (they run as #40), uploaded images not re-encoded, archives
  extracted without limits, signed upload URLs without a size or type restriction.
- Fix: check the real type from the first bytes (`file-type` package), cap the size on the
  server and in the storage policy, serve user files from a separate domain or with
  `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, re-encode images
  with `sharp`, refuse SVG and HTML unless sanitized.

### 46. Fake or vulnerable packages
- Read `package.json` and the lockfile (or `requirements.txt`, `pyproject.toml`, `Gemfile`).
  Flag packages you do not recognise or whose names look like a misspelling of a popular one
  (`reqeusts`, `lodahs`); AI assistants sometimes invent package names and attackers register
  them ("slopsquatting"). Flag `postinstall` or `preinstall` scripts in direct dependencies,
  dependencies pulled from git URLs or tarballs, and unpinned `*` or `latest` versions.
- Known vulnerable versions: do not install anything or call any registry. Report which
  advisory command to run as a manual check (`npm audit`, `pnpm audit`, `pip-audit`) and
  whether Dependabot or Renovate is configured in `.github/`.
- Fix: remove or replace unknown packages after checking them on the registry, pin versions,
  commit the lockfile, enable Dependabot alerts.

### 47. Unverified webhooks
- Every webhook handler: Stripe, Paddle, Lemon Squeezy, Clerk, Supabase auth hooks and
  database webhooks, GitHub, Resend, Twilio, Shopify, RevenueCat. Vulnerable if it acts on the
  body without checking the signature, checks it against a re-serialized body
  (`JSON.stringify(await req.json())`) instead of the raw body, compares signatures with `===`
  (#20), ignores the timestamp so old events can be replayed, or processes the same event ID
  twice. #4 covers payment fulfilment; this covers every webhook.
- Exploit: anyone who finds the URL posts a fake "payment succeeded" or "user created" event.
- Fix: the provider's verify function on the raw body (`stripe.webhooks.constructEvent(await
  req.text(), sig, secret)`, `svix` for Clerk and Resend), reject old timestamps, store
  processed event IDs and skip repeats.

### 48. Cookies and sessions
- Session, auth and refresh cookies set without `HttpOnly`, `Secure` or `SameSite`; access or
  refresh tokens stored in `localStorage` or `sessionStorage` (any XSS, #40, steals them);
  session not rotated after login (session fixation); logout that only deletes the cookie in
  the browser; sessions that survive a password change; "remember me" sessions with no upper
  limit.
- Fix: `HttpOnly; Secure; SameSite=Lax` (or `Strict`) with a `__Host-` prefix, tokens in
  cookies not storage, rotate the session ID on login, revoke server-side on logout and on
  password change (Supabase `signOut({ scope: 'global' })`).

### Plus: hardcoded secrets in the repo and git history
- Grep the working tree and `git log -p` (or `git grep` across `--all`) for: `sk_live_`,
  `sk_test_`, `rk_live_`, `whsec_`, `sk-ant-`, `sk-`, `AIza`, `AKIA`, `ghp_`, `gho_`,
  `xox[abp]-`, `sb_secret_`, `service_role`, `eyJhbGciOi` (JWT), `-----BEGIN` private keys,
  `SUPABASE_SERVICE`, `DATABASE_URL=postgres`, `TWILIO_AUTH_TOKEN`, `RESEND_API_KEY`,
  `STRIPE_SECRET`, long hex or base64 strings assigned to `secret`, `token`, `key`,
  `password`. Committed `.env`, `.env.local`, `.env.production` files are findings even if
  later deleted, because history keeps them.
- Confirm a hit is a secret first: decode `eyJ` tokens and report only `role: service_role`
  (the anon key is public by design); match `sk-` only after a quote, `=` or `:`, and
  `service_role` only as a value, not in SQL or variable names.
- For every hit: file, line or commit, key type, whether it is still valid is "Needs manual
  check", and the fix is rotate first, then purge from history, then add a pre-commit scan.

## Step 3. The report

Write `vibesec-report.md` in the project root with this structure:

1. **Scope and method**: scope path, date, framework and versions, files read.
2. **Findings**: items 1 to 48 plus Secrets, in order, each with the five fields. Group
   sub-findings under their item. Not applicable items get one line each, not five fields.
3. **Summary table**: columns `#`, `Issue`, `Status`, `Severity` (Critical / High / Medium /
   Low; blank for Safe and Not applicable).
   Severity guide: Critical = unauthenticated data access, payment manipulation, account
   takeover, RCE or SSRF to metadata; High = authenticated data exposure, auth weaknesses,
   missing RLS on non-public tables, exposed secrets; Medium = headers, enumeration,
   clickjacking, source maps, rate limits on low-value paths; Low = hardening with no direct
   exploit. Usually Critical: #39 IDOR on personal data, #41 injection, #43 mass assignment to
   a role or balance, #44 an open admin route, #47 an unverified payment webhook. Usually
   High: #40 stored XSS, #42 credentialed CORS or CSRF on account changes. Usually Medium: #48
   cookie flags, #46 unpinned versions.
4. **Top 5 fixes, in order**: the five changes that remove the most risk soonest, one line
   each with the item number.
5. **Manual tests on the live site**: a checklist of exact requests to make against
   production (URLs, headers, expected safe response) for everything you marked "Needs manual
   check" and for items 1, 2, 17, 18 and 19. Only plain, harmless requests a normal browser
   would send. Where they apply, also include:
   - #29: `curl -sI` a logged-in page and an API route; `Cache-Control` must be `private` or
     `no-store`, and `x-vercel-cache` / `cf-cache-status` must not be `HIT`.
   - #37: in the browser console on another site, `new WebSocket('wss://<site>/<path>')`;
     the server must refuse the connection.
   - #31: run the Supabase dashboard's Security Advisor and list what it flags.
   - #21, #28: read the `server` header of a HEAD request to confirm what is in front of the
     app; never send a stream flood or a smuggled request.
   - #42: `curl -sI -H 'Origin: https://example.org' https://<site>/<api-route>`; the response
     must not echo that origin in `Access-Control-Allow-Origin` with credentials allowed.
   - #48: in the browser's DevTools, Application tab, Cookies: the session cookie must show
     `HttpOnly`, `Secure` and `SameSite`; Local Storage must hold no access or refresh token.
   - #39: logged in as one test account, open a record URL that belongs to a second test
     account you own; it must return 404 or 403. Never try IDs of real users.
   - #46: run `npm audit` (or the stack's equivalent) locally and list Critical and High.

After saving the report, show the summary table in the chat and ask which issue to fix first.
Fix one issue at a time, show the diff before applying, and wait for an explicit yes. Do not
batch fixes and do not touch anything the user did not approve.
