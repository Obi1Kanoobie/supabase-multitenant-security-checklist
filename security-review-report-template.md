# Security Review — {{CLIENT_OR_PRODUCT_NAME}}

**Multi-tenant data isolation review — Supabase**

| | |
|---|---|
| Client | {{CLIENT_LEGAL_NAME}} |
| Application | {{APP_NAME}} — {{URL_OR_REPO}} |
| Environment reviewed | {{staging / production / dedicated review project}} |
| Review period | {{START_DATE}} – {{END_DATE}} |
| Reviewer | Artiom Psenicinii |
| Report version | 1.0 — {{DATE}} |

> **Confidential.** This report describes unfixed security defects in a live application. Share only with people who need it to authorise or perform the remediation. Findings marked Critical or High should be treated as exploitable until confirmed fixed.

---

## 1. Executive summary

*Three to six sentences, written for whoever signs the invoice, not for the engineer. What was reviewed, what the overall state is, what the single most important thing to do this week is. No jargon that needs a glossary.*

{{Example: The application isolates tenants correctly in most places, but three defects allow any registered user to read data belonging to other organisations, and one allows them to modify it. All four are reachable from a normal user account with no special tooling — a signed-up user with a browser console can reproduce them. Two are single-line policy fixes. The most urgent item is FND-001: the user's role is stored in a field the user can rewrite themselves, which makes every administrative check in the application advisory rather than enforced. Estimated total remediation effort is 9–13 hours.}*

### Findings at a glance

| ID | Finding | Severity | Effort |
|---|---|---|---|
| FND-001 | {{title}} | Critical | {{2–3 h}} |
| FND-002 | {{title}} | High | {{1 h}} |
| FND-003 | {{title}} | High | {{3–4 h}} |
| FND-004 | {{title}} | Medium | {{2 h}} |
| FND-005 | {{title}} | Low | {{1 h}} |

| Severity | Count |
|---|---|
| Critical | {{n}} |
| High | {{n}} |
| Medium | {{n}} |
| Low | {{n}} |

---

## 2. Scope and authorisation

**In scope**

- Postgres schema, Row Level Security policies, role grants, functions and views in the `{{public}}` schema
- Supabase Auth configuration
- Supabase Storage buckets and object policies
- Edge Functions: authentication, authorisation and secret handling
- Client bundle inspection for exposed credentials
- Tenant isolation testing with {{n}} test accounts across {{n}} tenants

**Out of scope**

- {{Third-party integrations: Stripe, ...}}
- {{Infrastructure and network layer, DDoS, availability}}
- {{Frontend XSS, CSRF and dependency vulnerabilities}}
- {{Business logic unrelated to tenant boundaries}}
- {{Load, performance and cost}}

**Authorisation.** Testing was carried out against {{ENVIRONMENT}} with the written permission of {{AUTHORISING_PERSON, ROLE}}, granted on {{DATE}}. Credentials used: {{test accounts provided by the client / accounts created through normal sign-up}}. No production customer data was accessed, copied or retained beyond what was necessary to demonstrate each finding, and all screenshots in this report are redacted.

**Method.** Read-only inspection of schema and configuration, manual review of every policy and definer function, and behavioural testing: each protected resource was requested through the REST API as an authenticated user of a different tenant, and each write path was tested for cross-tenant assignment. Automated scanning was used only to enumerate objects, not to establish findings.

**Limitations.** A review of this kind establishes the presence of defects, not their absence. Findings reflect the state of the system as of {{END_DATE}}; subsequent changes are not covered. {{Any areas that could not be reached, and why.}}

---

## 3. Severity definitions

| Level | Meaning |
|---|---|
| **Critical** | Cross-tenant read or write, or full authorisation bypass, reachable by any authenticated user or by the public |
| **High** | Data exposure that requires a specific condition or one chained step |
| **Medium** | Hardening gap with no direct exposure today, or exposure limited to non-sensitive data |
| **Low** | Defence in depth and hygiene |

Effort estimates are engineering hours for a developer already familiar with the codebase, including a test of the fix. They exclude release and regression testing.

---

## 4. Findings

### FND-001 — {{Short, factual title}}

| | |
|---|---|
| **Severity** | Critical |
| **Component** | {{table / function / bucket / Edge Function}} |
| **Estimated fix** | {{2–3 hours}} |
| **Status** | Open |

**What it is**

{{One paragraph in plain language. What the mechanism is and why it does not do what it appears to do. Assume the reader knows their own product but may not know Postgres internals.}}

**Evidence**

```sql
-- the policy as it exists today
{{...}}
```

**Reproduction**

1. {{Sign in as user A (tenant A) — test account a@example.com}}
2. {{Run:}}
   ```bash
   {{curl / SQL / console snippet}}
   ```
3. {{Observed: N rows returned, of which M belong to tenant B. Expected: only tenant A's rows.}}

{{Screenshot or redacted output. Show enough to make it undeniable, not enough to be a data leak in itself.}}

**Impact**

{{Who can do this, what they get, and what it means in the client's own terms — "any user who signs up for the free plan can read every customer's invoices, including amounts and contact details". Name the regulatory angle only if it genuinely applies.}}

**Recommended fix**

{{Concrete and specific. Where possible, the exact statement to run.}}

```sql
{{corrected policy / function / configuration}}
```

{{If there is a cheap partial mitigation that can ship today while the proper fix is scheduled, say so and mark it clearly as temporary.}}

**How to verify the fix**

{{The same reproduction steps, with the expected result after remediation. This is what the client runs to close the finding without needing me.}}

---

### FND-002 — {{title}}

*(repeat the block above for each finding)*

---

## 5. Observations

Items that are not defects but are worth knowing. No remediation is implied.

- {{e.g. RLS policies call `auth.uid()` per row rather than `(select auth.uid())`, which will become a performance problem above roughly N thousand rows.}}
- {{e.g. No backup restore has been tested; PITR is enabled but untried.}}
- {{e.g. Several tables carry both `org_id` and `tenant_id` with overlapping meaning — a future source of policy mistakes.}}

---

## 6. Remediation plan

Suggested order, highest exposure first:

1. **{{Today}}** — FND-001, FND-002. {{Both are single-statement changes and close cross-tenant read access.}}
2. **{{This week}}** — FND-003, FND-004.
3. **{{Before the next release}}** — FND-005 and the observations in section 5.

**Credential rotation.** {{If any key was found exposed: which one, and the fact that rotation is required regardless of whether misuse is visible in logs. List every place the key has to be updated.}}

**Retest.** A retest of the findings in this report is included / available for {{TERMS}}. It covers verification of the listed findings only, not a fresh review of changes made since.

---

## 7. Appendix — checks performed

The queries and checks behind this report are published as an open checklist:
https://github.com/Obi1Kanoobie/supabase-multitenant-security-checklist

{{Optionally: raw output of the enumeration queries, so the client can re-run them and compare. Keep it to the queries and counts, not the data.}}

---

*Prepared by Artiom Psenicinii · {{DATE}} · {{EMAIL}}*
