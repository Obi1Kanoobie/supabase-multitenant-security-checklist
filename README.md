# Supabase Multi-Tenant Security Checklist

A practical audit checklist for multi-tenant apps built on Supabase — the kind that get shipped fast with Lovable, Bolt, v0 or Cursor and go to production before anyone reads the RLS docs.

Every item below is something I have actually found in a real codebase. Most of them are one SQL query away from being confirmed or ruled out. Run them in the Supabase SQL editor against your own project.

**Nothing here touches anyone else's database.** Run it on projects you own or have written permission to test.

---

## How to use this

1. Open the SQL editor in your Supabase project.
2. Work top to bottom. Each section has a "check" you can run and a "what bad looks like".
3. Anything in the **Critical** sections that comes back non-empty is very likely a real data leak, not a theoretical one.
4. Fix, then re-run. Keep the output — it is your before/after evidence.

Roughly 30–60 minutes for a small app.

---

## 1. RLS is actually on — Critical

Row Level Security is opt-in per table. A table without it is readable by anyone holding the anon key, which is in your frontend bundle by design.

```sql
select c.relname as table_without_rls
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relrowsecurity = false
order by 1;
```

**Bad:** any row at all. Every table in an API-exposed schema needs RLS, including join tables, lookup tables and the "it's just settings" table.

### RLS on, but zero policies

Technically safe (default deny), but usually means someone enabled RLS to silence a warning and the feature using that table is quietly broken — or reads through a `service_role` path that bypasses RLS entirely.

```sql
select c.relname as rls_on_no_policies
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relrowsecurity
group by c.relname
having count(p.oid) = 0
order by 1;
```

---

## 2. Policies that do not restrict anything — Critical

The most common real-world leak. A policy exists, the dashboard shows a green shield, and the policy body is `true`.

```sql
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and (
    qual in ('true')
    or with_check in ('true')
    or qual is null
  )
order by tablename, policyname;
```

**Bad:** a `SELECT` policy with `qual = true` on any table holding tenant data. Also bad: an `INSERT` policy with `with_check = true`, which lets a user write rows attributed to someone else's tenant.

### Review every policy by hand

There is no query that tells you a policy is *logically* correct. Read them:

```sql
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
order by tablename, cmd, policyname;
```

Things to look for:

- **`USING` without `WITH CHECK` on UPDATE.** The user can read only their own row but can update it into another tenant by changing `tenant_id`. Very common.
- **Policy keyed on a column the client controls.** `USING (tenant_id = current_setting('request.headers')::json->>'x-tenant-id')` is not authorization, it is a suggestion.
- **Membership check that forgets the row's own tenant.** `USING (exists (select 1 from memberships m where m.user_id = auth.uid()))` returns true for *every* row as long as the user belongs to *any* organization. The join back to the row is missing.
- **Recursive policy** — a policy on `memberships` that queries `memberships`. Either errors or gets worked around with a `SECURITY DEFINER` function that then becomes the hole (see §5).

A correct tenant-scoped read policy usually looks like this:

```sql
create policy "read own tenant rows"
on public.orders for select
to authenticated
using (
  tenant_id in (
    select m.tenant_id from public.memberships m
    where m.user_id = (select auth.uid())
  )
);
```

Note `(select auth.uid())` rather than bare `auth.uid()` — it lets the planner evaluate it once per query instead of per row, which is the difference between a policy that works and one that gets ripped out for being slow.

---

## 3. Prove isolation, don't assume it — Critical

Reading policies is not testing them. Impersonate a real user inside the SQL editor:

```sql
begin;
select set_config('role', 'authenticated', true);
select set_config(
  'request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000000","role":"authenticated"}',
  true
);

-- now run the queries your app runs
select count(*) from public.orders;
select count(*) from public.documents;
select count(*) from public.memberships;

rollback;
```

Swap in a real user UUID from tenant A, note the counts. Repeat with a user from tenant B. Then compare against the unrestricted count as `postgres`. If tenant A's count equals the total count, you have your finding.

Do the same for writes — try to insert a row with another tenant's `tenant_id`, and try to update a row you should not own. A read-only audit misses half the bugs.

---

## 4. Role grants — High

RLS filters rows. Grants decide whether the role can touch the table at all. `anon` is the unauthenticated public.

```sql
select table_name, grantee, string_agg(privilege_type, ', ' order by privilege_type) as privs
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon', 'authenticated')
group by table_name, grantee
order by table_name, grantee;
```

**Bad:** `anon` with `INSERT`, `UPDATE` or `DELETE` anywhere. `anon` with `SELECT` on anything that is not genuinely public content. Revoke rather than rely on RLS alone — defense in depth, and it makes intent obvious to the next person.

Also check what the API actually exposes: Settings → API → Exposed schemas. If `public` is not the only entry, everything in the other schema is reachable too.

---

## 5. SECURITY DEFINER functions — Critical

These run with the owner's privileges and bypass RLS. They are the standard workaround for recursive policies, which means most multi-tenant apps have at least one.

```sql
select n.nspname as schema,
       p.proname as function,
       pg_get_userbyid(p.proowner) as owner,
       p.proconfig
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname not in ('pg_catalog', 'information_schema', 'extensions')
  and p.prosecdef
  and (
    p.proconfig is null
    or not exists (
      select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'
    )
  )
order by 1, 2;
```

**Bad:** any `SECURITY DEFINER` function without a pinned `search_path` — a user who can create objects in a schema earlier in the path can hijack what the function calls. Fix with `set search_path = ''` and fully-qualified names inside the body.

Then read each one. A `SECURITY DEFINER` function callable by `authenticated` that takes a `tenant_id` argument and does not verify the caller belongs to that tenant is a full tenant-hopping primitive, and it will not show up in any RLS review.

List what is callable over the API:

```sql
select p.proname, pg_get_function_identity_arguments(p.oid) as args, p.prosecdef
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
order by 1;
```

---

## 6. Views bypass RLS by default — High

A view runs with the privileges of its *owner* unless created with `security_invoker`. A view over an RLS-protected table, owned by `postgres`, hands out every row.

```sql
select c.relname as view_name,
       coalesce(
         (select option_value
          from pg_options_to_table(c.reloptions)
          where option_name = 'security_invoker'),
         'false'
       ) as security_invoker
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind in ('v', 'm')
order by 1;
```

**Bad:** `security_invoker = false` on any view touching tenant data. Fix: `alter view public.my_view set (security_invoker = on);`

Materialized views do not support `security_invoker` at all — do not expose them through the API.

---

## 7. Realtime — High

Realtime respects RLS for `postgres_changes`, but only if the tables are in the publication for the right reasons and your policies cover the `SELECT` path. The frequent mistake is adding a table to the publication and assuming the channel filter is the security boundary. It is not — a client can subscribe with any filter it likes.

```sql
select schemaname, tablename
from pg_publication_tables
where pubname = 'supabase_realtime'
order by 1, 2;
```

Check each table in that list has a correct `SELECT` policy. Also check `REPLICA IDENTITY` — set to `FULL` it ships the entire old row on updates and deletes, including columns you never intended to expose.

```sql
select c.relname, c.relreplident
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' and c.relreplident = 'f';
```

---

## 8. Storage — Critical

```sql
select id, name, public, file_size_limit, allowed_mime_types
from storage.buckets
order by name;
```

**Bad:** `public = true` on a bucket holding anything user-specific. A public bucket means object URLs are guessable-or-enumerable and need no token at all.

Storage policies live on `storage.objects`:

```sql
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by policyname;
```

Look for path-prefix policies that trust a client-supplied folder name, and for `INSERT` policies that let a user write into another user's prefix. The idiomatic pattern is `(storage.foldername(name))[1] = (select auth.uid())::text`.

Manual checks:

- Signed URL expiry. A 7-day (or 1-year) signed URL is a permanent public link for practical purposes.
- Are signed URLs generated server-side, or is the client asking for a URL to an arbitrary path?
- Is there any upload-size or MIME restriction, or can a user park 2 GB of anything in your bucket?

---

## 9. Key handling — Critical

The `anon` key in the frontend is fine and by design. The `service_role` key in the frontend is game over: it bypasses RLS completely.

Manual, but fast:

- Search the built frontend bundle for `service_role`, `sb_secret`, `SUPABASE_SERVICE`, and for JWTs whose payload contains `"role":"service_role"` (paste any `eyJ...` you find into a decoder — the payload is base64, not encrypted).
- Check `.env`, `.env.local`, `.env.production` are gitignored, and check the repo *history*, not just the working tree. A key committed once and removed later is still a leaked key.
- Check Vercel/Netlify env vars: anything named `NEXT_PUBLIC_*` or `VITE_*` is shipped to the browser. A service key under a `VITE_` prefix is a live incident.
- Check Edge Function code for a service key used to serve a user-facing endpoint without re-checking authorization itself.

If a service key has ever been exposed, rotate it. There is no "probably nobody noticed" — bundles get scraped.

---

## 10. Edge Functions — High

- `verify_jwt` disabled? Then the function is a public endpoint. Sometimes that is intended (webhooks); usually it is not.
- Does the function verify the *caller* rather than trusting a `user_id` in the request body? Passing `{ "user_id": "..." }` and trusting it is the single most common Edge Function bug.
- CORS: `Access-Control-Allow-Origin: *` together with credentials, or reflecting the request origin unconditionally.
- Webhook endpoints: is the signature actually verified (Stripe, Clerk, whatever), or just parsed?
- Secrets read from the environment, not hardcoded and not passed from the client.
- Rate limiting on anything that sends email, SMS or calls a paid API. This is a billing vulnerability even when it is not a data one.

---

## 11. Auth configuration — Medium/High

Dashboard checks, all of them quick:

- **Email confirmation on.** Off means anyone can register as `someone@yourcustomer.com` and, if you key anything off email domain, walk straight into their tenant.
- **Anonymous sign-ins.** If enabled, `authenticated` is no longer a meaningful trust boundary — anyone can get that role. Every policy written `to authenticated` needs re-reading with that in mind.
- **Leaked-password protection** on, minimum length sane.
- **JWT expiry.** The default is an hour; longer values widen every stolen-token window.
- **Redirect URL allowlist** with no wildcards that permit an attacker-controlled host. This is how auth codes get stolen.
- **MFA** available for admin-ish accounts.
- **Email change** requires confirmation on both old and new address.

---

## 12. Data at rest and recovery — Medium

- Point-in-time recovery enabled, or at least daily backups — and has a restore ever been tested? An untested backup is a belief, not a backup.
- Do logs contain PII, tokens, or full request bodies?
- Does any table store secrets in plaintext (API keys for third-party services that your users connect)? Those want `pgsodium`/Vault or at least envelope encryption, not a `text` column.
- Soft deletes: does `deleted_at is null` appear in the RLS policy, or only in the application query? If only in the app, deleted rows are still readable over the API.

---

## 13. The quiet ones

- **`count` leaks.** PostgREST can return an exact count even when rows are filtered. Knowing that tenant B has 14,203 orders is itself information.
- **Error messages.** A foreign-key violation that echoes another tenant's row id is a leak.
- **Enumerable ids.** Sequential integer ids in URLs plus a weak policy equals trivial scraping. UUIDs are not authorization, but they buy you a lot.
- **`pg_net` / `http` extension** callable by `authenticated` is an SSRF primitive out of your database.
- **Extensions installed into `public`** rather than `extensions`, which widens the `search_path` attack surface from §5.

---

## Severity, so the report means something

| Level | Meaning |
|---|---|
| Critical | Cross-tenant data access, or full bypass, reachable by any authenticated user or the public |
| High | Requires a specific condition or a chained step, but leads to data exposure |
| Medium | Hardening gap; no direct exposure today |
| Low | Hygiene, defense in depth |

A finding is only worth writing down with three things: how to reproduce it, what an attacker gets, and roughly how long the fix takes.

---

## Contributing

Found a pattern that belongs here, or a query that is wrong? Open an issue or a PR. Real-world findings preferred over theory.

---

## About

I do fixed-price security reviews of multi-tenant Supabase applications — RLS and tenant isolation, storage, Edge Functions, key handling — and deliver a written report with reproduction steps and an estimate of the work to fix each finding. Written and asynchronous; no calls required.

If you shipped fast and want to know what you shipped, get in touch: **[your email]** · [dev.to/obi1kanoobie](https://dev.to/obi1kanoobie)

---

*MIT licensed. Use it, fork it, run it against your own projects.*
