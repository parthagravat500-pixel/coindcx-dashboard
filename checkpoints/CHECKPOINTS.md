# ScopeGuard: 1,000 research checkpoints

Version: 2026.09.26.1 · Authored: 2026-09-26

Original ScopeGuard research prompts, organized with background reading from established public security guides. Not copied standard requirements, an OWASP certification, an exhaustive list, or a claim that every researcher or AI uses these exact checks.

Catalog entries are not executed tests, testing permission, confirmed bugs, or promised earnings. Applicability depends on actual features and current program rules. Some areas require specialist tools and controlled environments.

Each numbered item is an investigation question or expected control, not a completed test. The dashboard identifies the small subset with existing automatic evidence support. The rest require contextual review, appropriate tooling, and separate permission.

## Background references

- [OWASP Web Security Testing Guide v4.2](https://wstg.owasp.org/v4.2/) · checked 2026-09-26
- [OWASP API Security Top 10 (2023)](https://api-security.owasp.org/editions/2023/en/0x11-t10/) · checked 2026-09-26
- [OWASP Mobile Application Security Verification Standard](https://mas.owasp.org/MASVS/) · checked 2026-09-26
- [OWASP GenAI security project risk guidance](https://genai.owasp.org/llm-top-10/) · checked 2026-09-26
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) · checked 2026-09-26

References are background reading at category level, not exact requirement mappings. Checkpoint wording and identifiers belong to this catalog.

## Automatic and AI support

Eleven entries have partial automatic evidence support: four policy metadata checks (SG-0001, SG-0002, SG-0006, SG-0008) and seven existing Python pattern checks (SG-0781 through SG-0787). Evidence support is not whole-control validation.

Twelve entries are also used as guidance in the existing experimental private AI review: six per fixed owned-code excerpt. AI suggestions remain unverified and do not change testing permissions, confirmed-bug counts, or checklist completion.

## Permission and research boundaries

Suggested contexts: all. Method: document review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Official policy source, read time, exact wording needed for the decision, and unresolved conditions. A listing never supplies permission.

- **SG-0001** — Record the official policy URL and the time it was read.
- **SG-0002** — Confirm that the program is currently accepting security research.
- **SG-0003** — Match the proposed hostname to an explicit scope entry.
- **SG-0004** — Check whether wildcard scope includes the proposed subdomain.
- **SG-0005** — Record path restrictions within an otherwise eligible host.
- **SG-0006** — Resolve conflicts between scope inclusions and exclusions.
- **SG-0007** — Identify assets operated by a third party rather than the program.
- **SG-0008** — Record which automated methods the program explicitly allows.
- **SG-0009** — Record any numeric request limit without inventing a default permission.
- **SG-0010** — Check whether production testing is prohibited or restricted.
- **SG-0011** — Identify the required test environment before preparing requests.
- **SG-0012** — Determine whether researcher-owned accounts are mandatory.
- **SG-0013** — Determine whether identity verification or residency affects eligibility.
- **SG-0014** — Record required researcher headers or traffic identifiers.
- **SG-0015** — List prohibited techniques and map them to disabled methods.
- **SG-0016** — Check whether linked policy documents add further restrictions.
- **SG-0017** — Record stop conditions for errors, sensitive data, and service impact.
- **SG-0018** — Separate submission eligibility from eligibility for a monetary reward.
- **SG-0019** — Record the policy expiry or the next required review date.
- **SG-0020** — Keep uncertain permission unresolved instead of approving a target.

## Asset inventory and environment

Suggested contexts: all. Method: document review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Versioned inventory entry, ownership/source provenance, environment, and exact scope match. Do not enumerate extra assets.

- **SG-0021** — Distinguish the production service from its staging counterpart.
- **SG-0022** — Record the exact application version covered by the research.
- **SG-0023** — Identify API versions explicitly covered by the program.
- **SG-0024** — Record which mobile package identifiers are in scope.
- **SG-0025** — Record which desktop release channels are eligible.
- **SG-0026** — Map documented service owners to the listed assets.
- **SG-0027** — Identify deprecated endpoints from authorized documentation.
- **SG-0028** — Check whether legacy interfaces share the current permission boundary.
- **SG-0029** — Identify supported protocols without probing additional ports.
- **SG-0030** — Record source repository branches covered by permission.
- **SG-0031** — Identify public documentation that describes eligible features.
- **SG-0032** — Separate public pages from authenticated functionality.
- **SG-0033** — Record geographic deployment restrictions affecting the test environment.
- **SG-0034** — Identify customer-managed installations that require separate consent.
- **SG-0035** — Record sandbox endpoints independently from live payment endpoints.
- **SG-0036** — Identify feature flags that change the available security surface.
- **SG-0037** — Record redirects as new destinations requiring separate scope review.
- **SG-0038** — Track renamed assets without silently extending old approval.
- **SG-0039** — Identify cached inventory entries that need fresh confirmation.
- **SG-0040** — Preserve the provenance of every asset added to the research plan.

## Threat model and trust boundaries

Suggested contexts: all. Method: document review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Data-flow or workflow description, identities, trust boundary, and a concrete abuse hypothesis with stated assumptions.

- **SG-0041** — Identify the data that must remain private for each user role.
- **SG-0042** — Map where untrusted input first enters the application.
- **SG-0043** — Identify which services can perform privileged actions.
- **SG-0044** — Document transitions between anonymous and authenticated states.
- **SG-0045** — Identify boundaries between customer organizations.
- **SG-0046** — Record assumptions about trusted network locations.
- **SG-0047** — Identify browser-controlled fields that the server must revalidate.
- **SG-0048** — Map trust placed in upstream identity providers.
- **SG-0049** — Identify background jobs that act with elevated privileges.
- **SG-0050** — Document who may change a resource's ownership.
- **SG-0051** — Identify workflows that move money or spend credits.
- **SG-0052** — Record which operations are irreversible in production.
- **SG-0053** — Identify external integrations that can introduce attacker-controlled content.
- **SG-0054** — Map where sensitive data crosses regional boundaries.
- **SG-0055** — Identify default privileges granted to newly created identities.
- **SG-0056** — Record the intended audience of shared links.
- **SG-0057** — Identify security decisions delegated to client-side code.
- **SG-0058** — Document how administrators impersonate or assist users.
- **SG-0059** — Identify assumptions that fail when a dependency is unavailable.
- **SG-0060** — Prioritize hypotheses by plausible impact and reachable prerequisites.

## Registration and identity changes

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0061** — Verify email ownership before granting email-dependent privileges.
- **SG-0062** — Keep unverified registrations separate from existing verified identities.
- **SG-0063** — Bind invitation acceptance to the intended recipient.
- **SG-0064** — Prevent registration fields from assigning privileged roles.
- **SG-0065** — Apply the same identity uniqueness rules across signup routes.
- **SG-0066** — Handle email case differences consistently during identity matching.
- **SG-0067** — Handle phone-number normalization consistently during account matching.
- **SG-0068** — Require renewed verification after a primary email change.
- **SG-0069** — Require renewed verification after a primary phone change.
- **SG-0070** — Notify the previous contact address of a sensitive identity change.
- **SG-0071** — Protect account merging with proof for both identities.
- **SG-0072** — Preserve organization restrictions during social-account signup.
- **SG-0073** — Expire unused registration verification links.
- **SG-0074** — Invalidate a verification link after its first successful use.
- **SG-0075** — Prevent invite reuse after its recipient or organization changes.
- **SG-0076** — Keep disabled identities from being silently reactivated through signup.
- **SG-0077** — Apply age or eligibility gates on the server where required.
- **SG-0078** — Avoid exposing sensitive profile fields in signup error responses.
- **SG-0079** — Ensure account deletion does not let old tokens reach a replacement account.
- **SG-0080** — Keep invitation cancellation effective on already opened acceptance pages.

## Password authentication

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0081** — Require authentication on alternate login endpoints.
- **SG-0082** — Avoid revealing whether a private account exists in login errors.
- **SG-0083** — Ensure a disabled account cannot obtain a new session.
- **SG-0084** — Check that password comparison does not silently truncate input.
- **SG-0085** — Reject empty passwords through every supported login route.
- **SG-0086** — Enforce the intended password policy on server-side password changes.
- **SG-0087** — Store passwords with an appropriate salted password-hashing scheme.
- **SG-0088** — Keep password material out of diagnostic logs.
- **SG-0089** — Require a secure transport channel for submitted credentials.
- **SG-0090** — Apply the configured attempt budget consistently across login aliases.
- **SG-0091** — Prevent lockout messages from disclosing private identity details.
- **SG-0092** — Require fresh authentication before changing a password.
- **SG-0093** — Invalidate appropriate existing sessions after a password change.
- **SG-0094** — Reject temporary passwords after their intended lifetime.
- **SG-0095** — Keep service-account login separate from human-user login rules.
- **SG-0096** — Verify that remember-me tokens are independently revocable.
- **SG-0097** — Prevent fallback authentication from weakening the main login policy.
- **SG-0098** — Ensure an interrupted login does not create a fully authenticated session.
- **SG-0099** — Bind authentication callbacks to the initiating login attempt.
- **SG-0100** — Document the limited scope of any password-policy observation.

## Multifactor authentication and passkeys

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0101** — Require the second factor before granting normal session privileges.
- **SG-0102** — Bind each factor challenge to the correct account.
- **SG-0103** — Expire abandoned factor challenges.
- **SG-0104** — Reject a successfully consumed one-time factor code.
- **SG-0105** — Enforce a bounded attempt policy for factor verification.
- **SG-0106** — Require appropriate reauthentication before enrolling a new factor.
- **SG-0107** — Require appropriate reauthentication before removing a factor.
- **SG-0108** — Prevent backup codes from being reused.
- **SG-0109** — Protect backup-code regeneration from an untrusted session.
- **SG-0110** — Invalidate old backup codes after replacement.
- **SG-0111** — Keep recovery flows from bypassing enrolled-factor policy.
- **SG-0112** — Verify the passkey relying-party identifier matches the service.
- **SG-0113** — Validate the origin in a passkey authentication ceremony.
- **SG-0114** — Bind passkey registration challenges to the initiating session.
- **SG-0115** — Check user-verification requirements for sensitive passkey operations.
- **SG-0116** — Handle unavailable authenticators without granting elevated access.
- **SG-0117** — Notify the account owner when factor settings change.
- **SG-0118** — Distinguish remembered devices from permanently exempt identities.
- **SG-0119** — Revoke remembered-factor trust when a device is removed.
- **SG-0120** — Protect factor-enrollment secrets from logs and client analytics.

## Account recovery

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0121** — Send recovery messages only to verified recovery destinations.
- **SG-0122** — Use unpredictable reset tokens with sufficient entropy.
- **SG-0123** — Expire reset tokens after a documented short lifetime.
- **SG-0124** — Invalidate a reset token after successful use.
- **SG-0125** — Bind each reset token to a single account and purpose.
- **SG-0126** — Invalidate older recovery links when policy requires replacement.
- **SG-0127** — Do not construct reset links from an untrusted host header.
- **SG-0128** — Avoid putting reset tokens in third-party tracking requests.
- **SG-0129** — Require the new password to satisfy the normal password policy.
- **SG-0130** — Keep recovery responses from disclosing private account existence.
- **SG-0131** — Protect recovery-destination changes with fresh authentication.
- **SG-0132** — Ensure canceled account recovery cannot later complete.
- **SG-0133** — Revoke appropriate sessions after recovery succeeds.
- **SG-0134** — Treat recovery for organization-managed accounts according to enterprise policy.
- **SG-0135** — Avoid using publicly discoverable facts as recovery secrets.
- **SG-0136** — Protect assisted recovery actions with recorded authorization.
- **SG-0137** — Keep reset forms from accepting unrelated account identifiers.
- **SG-0138** — Check that account suspension survives password recovery.
- **SG-0139** — Prevent recovery links from being valid for another application tenant.
- **SG-0140** — Verify that recovery completion does not expose the replacement password.

## Sessions and cookies

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0141** — Rotate the session identifier after successful login.
- **SG-0142** — Rotate session state after a privilege elevation.
- **SG-0143** — Invalidate the server-side session on logout.
- **SG-0144** — Enforce inactivity expiry on the server.
- **SG-0145** — Enforce an absolute maximum session lifetime.
- **SG-0146** — Prevent a pre-login identifier from fixing the authenticated session.
- **SG-0147** — Scope session cookies to the intended host and path.
- **SG-0148** — Require Secure on cookies carrying authentication state.
- **SG-0149** — Require HttpOnly on session cookies that scripts do not need.
- **SG-0150** — Choose SameSite behavior appropriate to the application's workflows.
- **SG-0151** — Keep session secrets out of URLs and browser history.
- **SG-0152** — Reject expired sessions on background API requests.
- **SG-0153** — Revoke selected device sessions independently.
- **SG-0154** — Ensure logout from one account cannot affect an unrelated account.
- **SG-0155** — Invalidate sessions after administrator-initiated account suspension.
- **SG-0156** — Avoid persisting privileged sessions in shared browser storage.
- **SG-0157** — Keep session state consistent across horizontally scaled servers.
- **SG-0158** — Prevent duplicate cookie names from changing the selected identity.
- **SG-0159** — Require fresh authentication after a high-risk account event.
- **SG-0160** — Distinguish an observed cookie attribute from proven account compromise.

## Object and function authorization

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0161** — Check ownership before returning a private object's details.
- **SG-0162** — Check ownership before updating a private object.
- **SG-0163** — Check ownership before deleting a private object.
- **SG-0164** — Apply authorization to bulk object operations.
- **SG-0165** — Apply authorization to nested resources and their parents.
- **SG-0166** — Check privileges on administrative functions at the server.
- **SG-0167** — Enforce read-only roles on write endpoints.
- **SG-0168** — Recheck permissions when an object's owner changes.
- **SG-0169** — Recheck access when group membership is removed.
- **SG-0170** — Enforce authorization on alternate representations of the same resource.
- **SG-0171** — Protect private object exports with the original access boundary.
- **SG-0172** — Enforce access rules on search results containing private objects.
- **SG-0173** — Prevent hidden form fields from overriding the acting identity.
- **SG-0174** — Apply object checks before generating temporary download links.
- **SG-0175** — Avoid treating an unpredictable identifier as authorization.
- **SG-0176** — Restrict access to archived resources after permission revocation.
- **SG-0177** — Protect restore operations with the same ownership checks as deletion.
- **SG-0178** — Verify authorization on server-side previews of private content.
- **SG-0179** — Require explicit privilege for impersonation functions.
- **SG-0180** — Record both allowed and denied controls using researcher-owned accounts.

## Organization and tenant isolation

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0181** — Derive the active tenant from trusted membership data.
- **SG-0182** — Keep tenant identifiers in URLs from overriding authenticated membership.
- **SG-0183** — Isolate database queries by the authorized tenant.
- **SG-0184** — Partition tenant-scoped caches correctly.
- **SG-0185** — Keep background job results within their originating tenant.
- **SG-0186** — Enforce tenant boundaries on organization search.
- **SG-0187** — Reject invitations created for a different organization context.
- **SG-0188** — Revoke access after a user leaves an organization.
- **SG-0189** — Apply tenant boundaries to audit-log downloads.
- **SG-0190** — Keep organization administrators from controlling platform administrators.
- **SG-0191** — Isolate custom domain configuration between organizations.
- **SG-0192** — Bind enterprise identity-provider settings to their organization.
- **SG-0193** — Protect tenant-specific webhook secrets from other tenants.
- **SG-0194** — Avoid exposing organization billing data through shared identifiers.
- **SG-0195** — Keep tenant exports from including cross-tenant attachments.
- **SG-0196** — Isolate saved reports and dashboard widgets by tenant.
- **SG-0197** — Prevent tenant switching from retaining earlier elevated privileges.
- **SG-0198** — Keep shared templates from leaking private tenant configuration.
- **SG-0199** — Validate tenant boundaries in service-to-service calls.
- **SG-0200** — Test isolation with two expressly authorized test organizations only.

## OAuth and OpenID Connect

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0201** — Validate authorization redirects against registered callback addresses.
- **SG-0202** — Bind authorization state to the initiating browser session.
- **SG-0203** — Enforce PKCE when required for the client type.
- **SG-0204** — Reject authorization codes issued to another client.
- **SG-0205** — Reject authorization codes after successful redemption.
- **SG-0206** — Validate the identity-token issuer.
- **SG-0207** — Validate the identity-token audience.
- **SG-0208** — Validate the nonce when the flow requires one.
- **SG-0209** — Reject tokens outside their validity interval.
- **SG-0210** — Restrict requested scopes to those the user approved.
- **SG-0211** — Preserve scope reductions when refreshing a token.
- **SG-0212** — Revoke refresh tokens when the connection is disconnected.
- **SG-0213** — Protect refresh-token rotation against reuse of an invalidated token.
- **SG-0214** — Keep confidential-client credentials off public client bundles.
- **SG-0215** — Avoid sending bearer tokens to callback destinations outside the client.
- **SG-0216** — Bind account linking to an authenticated local identity.
- **SG-0217** — Prevent login callbacks from silently linking an attacker's account.
- **SG-0218** — Distinguish provider identity from a mutable email address.
- **SG-0219** — Require explicit consent when an integration gains new privileges.
- **SG-0220** — Record provider-specific requirements before treating a flow as vulnerable.

## SAML and enterprise federation

Suggested contexts: web, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0221** — Validate the signature on the SAML element actually consumed.
- **SG-0222** — Reject assertions from an untrusted identity provider.
- **SG-0223** — Validate the intended audience restriction.
- **SG-0224** — Validate the assertion recipient.
- **SG-0225** — Validate the response destination.
- **SG-0226** — Match solicited responses to the initiating request.
- **SG-0227** — Apply the documented policy to unsolicited SAML responses.
- **SG-0228** — Reject expired assertions.
- **SG-0229** — Reject assertions that are not yet valid.
- **SG-0230** — Prevent an already consumed assertion from being replayed.
- **SG-0231** — Keep duplicate XML identifiers from selecting an unsigned element.
- **SG-0232** — Disable external entity resolution in federation XML parsing.
- **SG-0233** — Treat role attributes according to the local authorization policy.
- **SG-0234** — Prevent an email attribute alone from linking an existing privileged user.
- **SG-0235** — Bind federation metadata changes to organization administration privileges.
- **SG-0236** — Handle signing-certificate rotation without accepting arbitrary certificates.
- **SG-0237** — Enforce the intended session lifetime after federated login.
- **SG-0238** — Restrict RelayState destinations to the intended application context.
- **SG-0239** — Preserve account suspension when the identity provider authenticates a user.
- **SG-0240** — Record authentication context when sensitive actions require stronger login.

## Tokens, API keys, and signatures

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0241** — Validate token signatures before trusting token claims.
- **SG-0242** — Restrict accepted token algorithms to a configured allowlist.
- **SG-0243** — Reject unsigned tokens when signatures are required.
- **SG-0244** — Keep symmetric and asymmetric verification keys from being confused.
- **SG-0245** — Validate the issuer for service-issued bearer tokens.
- **SG-0246** — Validate the audience for service-issued bearer tokens.
- **SG-0247** — Enforce expiration even when a token remains cryptographically valid.
- **SG-0248** — Handle clock skew within a bounded documented interval.
- **SG-0249** — Reject tokens with malformed or contradictory claims.
- **SG-0250** — Limit token key selection to trusted key material.
- **SG-0251** — Keep token key identifiers from becoming file paths or network destinations.
- **SG-0252** — Support revocation for high-privilege API keys.
- **SG-0253** — Apply key scopes to every operation using that key.
- **SG-0254** — Show a newly created secret only where the product requires it.
- **SG-0255** — Keep masked-key displays from revealing a usable credential.
- **SG-0256** — Separate production keys from sandbox keys.
- **SG-0257** — Prevent key rotation from re-enabling a revoked key.
- **SG-0258** — Bind request signatures to the relevant method and destination.
- **SG-0259** — Include freshness or replay protection in signed requests.
- **SG-0260** — Distinguish an exposed public verification key from a secret credential.

## Cross-site request protection

Suggested contexts: web, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0261** — Require anti-forgery protection for browser-authenticated state changes.
- **SG-0262** — Bind anti-forgery tokens to the intended authenticated context.
- **SG-0263** — Reject absent anti-forgery tokens on protected operations.
- **SG-0264** — Reject malformed anti-forgery tokens on protected operations.
- **SG-0265** — Reject another session's anti-forgery token.
- **SG-0266** — Avoid accepting a query parameter as an unintended token fallback.
- **SG-0267** — Keep safe HTTP methods free of state-changing side effects.
- **SG-0268** — Apply protection to alternate content types accepted by a write endpoint.
- **SG-0269** — Protect login transitions against cross-site account confusion.
- **SG-0270** — Protect logout when forced logout has meaningful workflow impact.
- **SG-0271** — Validate browser origin information where the defense relies on it.
- **SG-0272** — Handle missing Origin or Referer according to explicit policy.
- **SG-0273** — Do not rely solely on a user-controlled requested-with header.
- **SG-0274** — Protect account email changes from cross-site submission.
- **SG-0275** — Protect payment-destination changes from cross-site submission.
- **SG-0276** — Protect file-upload forms that use ambient cookies.
- **SG-0277** — Cover GraphQL mutations when cookie authentication is used.
- **SG-0278** — Cover WebSocket setup when the socket can change state.
- **SG-0279** — Verify protection remains effective after a session renewal.
- **SG-0280** — Use local or owned-account controls rather than involving other users.

## Cross-origin resource access

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0281** — Compare allowed origins using an exact trusted-origin policy.
- **SG-0282** — Reject untrusted origins when credentialed responses are available.
- **SG-0283** — Avoid reflecting an arbitrary Origin as an allowed origin.
- **SG-0284** — Handle the null origin according to a deliberate policy.
- **SG-0285** — Keep origin suffix checks from trusting unrelated domains.
- **SG-0286** — Consider scheme and port when matching allowed origins.
- **SG-0287** — Apply origin rules consistently to preflight and actual responses.
- **SG-0288** — Restrict allowed methods to the intended cross-origin operations.
- **SG-0289** — Restrict allowed request headers to the intended integration needs.
- **SG-0290** — Keep exposed response headers from revealing sensitive values.
- **SG-0291** — Vary cached responses appropriately when allowed origins differ.
- **SG-0292** — Apply credential rules consistently across successful and error responses.
- **SG-0293** — Avoid extending a trusted frontend's access to every subdomain.
- **SG-0294** — Remove obsolete partner origins from the allowlist.
- **SG-0295** — Protect development-origin exceptions from reaching production configuration.
- **SG-0296** — Verify whether the response actually contains private information.
- **SG-0297** — Verify browser behavior before treating a header combination as exploitable.
- **SG-0298** — Separate public unauthenticated APIs from private credentialed APIs.
- **SG-0299** — Check cross-origin rules on alternate API versions.
- **SG-0300** — Record the exact origin and response context for a CORS observation.

## Browser rendering and script injection

Suggested contexts: web, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0301** — Encode untrusted text inserted into HTML element content.
- **SG-0302** — Encode untrusted values inserted into HTML attributes.
- **SG-0303** — Constrain untrusted values used in script execution contexts.
- **SG-0304** — Validate schemes for user-controlled navigation URLs.
- **SG-0305** — Keep user content out of executable JavaScript strings.
- **SG-0306** — Sanitize rich text with an appropriate maintained parser.
- **SG-0307** — Preserve sanitization when rich text is edited and saved again.
- **SG-0308** — Prevent markdown rendering from introducing executable HTML unexpectedly.
- **SG-0309** — Treat SVG uploads according to their active-content capabilities.
- **SG-0310** — Avoid assigning untrusted data directly to innerHTML.
- **SG-0311** — Avoid evaluating URL-fragment data as code.
- **SG-0312** — Validate origins and message structure in postMessage handlers.
- **SG-0313** — Keep DOM identifiers from overriding security-sensitive objects.
- **SG-0314** — Apply output handling to administrator views of user content.
- **SG-0315** — Apply output handling to notification and email preview pages.
- **SG-0316** — Keep template autoescaping enabled for untrusted values.
- **SG-0317** — Handle client-side template expressions as data where appropriate.
- **SG-0318** — Assess script execution in the correct origin and user context.
- **SG-0319** — Use inert markers or isolated fixtures before any active demonstration.
- **SG-0320** — Separate missing browser hardening from demonstrated script execution.

## SQL database boundaries

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Authorized source location or local database fixture, input path, bound-query control, and minimal redacted result.

- **SG-0321** — Bind externally influenced query values through parameters.
- **SG-0322** — Allowlist dynamic database column names.
- **SG-0323** — Allowlist dynamic database table names.
- **SG-0324** — Constrain dynamic sort directions.
- **SG-0325** — Avoid concatenating pagination inputs into SQL fragments.
- **SG-0326** — Preserve parameter binding inside stored procedures.
- **SG-0327** — Review ORM raw-query escape hatches.
- **SG-0328** — Keep query-builder expressions from accepting raw user syntax.
- **SG-0329** — Validate numeric conversions before constructing numeric SQL clauses.
- **SG-0330** — Treat wildcard search semantics separately from SQL structure.
- **SG-0331** — Apply tenant restrictions to joined tables.
- **SG-0332** — Use database credentials with only required privileges.
- **SG-0333** — Avoid returning raw database errors to clients.
- **SG-0334** — Keep connection strings out of responses and logs.
- **SG-0335** — Bind array membership queries without building quoted value lists.
- **SG-0336** — Review second-use queries that consume previously stored user input.
- **SG-0337** — Protect report builders that expose selectable query components.
- **SG-0338** — Verify transaction rollback preserves authorization invariants.
- **SG-0339** — Compare a suspected query path with a parameterized negative control.
- **SG-0340** — Record reachable input-to-query evidence instead of assuming every dynamic query is exploitable.

## NoSQL, search, and expression queries

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0341** — Require expected scalar types in document lookup fields.
- **SG-0342** — Reject unexpected query operators from user-provided objects.
- **SG-0343** — Build search filters from an allowlisted schema.
- **SG-0344** — Keep regular-expression search inputs within bounded syntax and size.
- **SG-0345** — Apply tenant filters to every document collection lookup.
- **SG-0346** — Prevent client-provided projections from returning private fields.
- **SG-0347** — Restrict document update operators accepted through public APIs.
- **SG-0348** — Keep aggregation pipelines under server control.
- **SG-0349** — Avoid evaluating user input as server-side database script.
- **SG-0350** — Protect graph queries from untrusted query-language fragments.
- **SG-0351** — Bind LDAP filter values with context-appropriate escaping.
- **SG-0352** — Escape search-engine query syntax where literal search is intended.
- **SG-0353** — Keep geospatial query bounds within documented limits.
- **SG-0354** — Separate object identifiers from operator-bearing request objects.
- **SG-0355** — Restrict search-index administration to authorized roles.
- **SG-0356** — Preserve ownership checks in bulk document updates.
- **SG-0357** — Avoid exposing backend query plans to unauthenticated users.
- **SG-0358** — Validate recursive filter depth in an isolated fixture.
- **SG-0359** — Compare filtered results against an authorized baseline dataset.
- **SG-0360** — Distinguish a query parse error from proven unauthorized data access.

## Commands, templates, and object loading

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0361** — Pass process arguments without invoking an unnecessary shell.
- **SG-0362** — Constrain executable selection to intended commands.
- **SG-0363** — Separate option values from command-line flags.
- **SG-0364** — Keep environment variables from selecting unintended interpreters.
- **SG-0365** — Avoid evaluating user-controlled template source.
- **SG-0366** — Constrain template helper functions to intended capabilities.
- **SG-0367** — Keep template loaders inside authorized template directories.
- **SG-0368** — Disable unsafe object construction when loading YAML.
- **SG-0369** — Avoid deserializing untrusted Python pickle data.
- **SG-0370** — Reject untrusted native object serialization formats.
- **SG-0371** — Apply explicit type restrictions to polymorphic deserialization.
- **SG-0372** — Keep serialized object signatures separate from encryption assumptions.
- **SG-0373** — Validate serialized object size before allocating large structures.
- **SG-0374** — Prevent object hydration from invoking unintended lifecycle hooks.
- **SG-0375** — Avoid interpreting user input as a general expression language.
- **SG-0376** — Protect plugin loaders from user-controlled import paths.
- **SG-0377** — Constrain document-conversion subprocess parameters.
- **SG-0378** — Review image-processing delegates that can launch external programs.
- **SG-0379** — Use harmless local fixtures for interpreter-boundary experiments.
- **SG-0380** — Require a reachable untrusted input path before escalating a dangerous-call signal.

## Server-side outbound requests

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0381** — Allowlist intended destinations for server-side URL fetching.
- **SG-0382** — Validate the destination scheme before creating a request.
- **SG-0383** — Reject embedded credentials in fetched URLs.
- **SG-0384** — Resolve and validate all destination addresses before connecting.
- **SG-0385** — Reject private and reserved destinations where public fetching is intended.
- **SG-0386** — Keep redirect destinations within the same approved outbound policy.
- **SG-0387** — Prevent a second DNS resolution from changing the validated destination.
- **SG-0388** — Constrain outbound ports to documented service needs.
- **SG-0389** — Keep cloud metadata destinations outside public fetch functionality.
- **SG-0390** — Prevent URL parsers from disagreeing on the actual host.
- **SG-0391** — Treat encoded address forms consistently during validation.
- **SG-0392** — Bound connection and response-read timeouts.
- **SG-0393** — Bound downloaded response size.
- **SG-0394** — Do not forward incoming authentication headers to arbitrary destinations.
- **SG-0395** — Separate webhook delivery credentials by destination.
- **SG-0396** — Keep proxy settings from bypassing destination restrictions.
- **SG-0397** — Review preview generators that fetch user-supplied URLs.
- **SG-0398** — Review import features that fetch remote documents.
- **SG-0399** — Use controlled local endpoints when validating outbound restrictions.
- **SG-0400** — Record outbound-request evidence without contacting unrelated infrastructure.

## File uploads and media processing

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0401** — Allow only file types required by the feature.
- **SG-0402** — Validate content independently from the supplied filename extension.
- **SG-0403** — Normalize filenames before applying filename restrictions.
- **SG-0404** — Prevent uploaded filenames from selecting storage paths.
- **SG-0405** — Store uploads outside executable application directories.
- **SG-0406** — Assign server-generated storage identifiers.
- **SG-0407** — Check ownership before replacing an existing upload.
- **SG-0408** — Protect upload completion callbacks with the uploader's authorization.
- **SG-0409** — Bound upload size before processing content.
- **SG-0410** — Bound image dimensions before full decoding.
- **SG-0411** — Strip unnecessary embedded metadata where privacy requires it.
- **SG-0412** — Serve untrusted active content from an appropriately isolated origin.
- **SG-0413** — Set content disposition according to the intended download behavior.
- **SG-0414** — Prevent media conversion from fetching arbitrary external resources.
- **SG-0415** — Keep temporary upload files private until validation completes.
- **SG-0416** — Remove abandoned multipart uploads according to retention policy.
- **SG-0417** — Revalidate files after server-side transformations when needed.
- **SG-0418** — Keep antivirus status from being a client-controlled field.
- **SG-0419** — Apply quota checks to the final stored size.
- **SG-0420** — Use non-sensitive sample files for upload validation.

## Downloads and filesystem paths

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0421** — Resolve requested files within a designated storage root.
- **SG-0422** — Normalize path separators before validating containment.
- **SG-0423** — Handle encoded path components consistently across routing layers.
- **SG-0424** — Prevent symbolic links from escaping permitted storage.
- **SG-0425** — Check object authorization before streaming a file.
- **SG-0426** — Apply permission checks to partial-content requests.
- **SG-0427** — Avoid using client-supplied absolute filesystem paths.
- **SG-0428** — Keep temporary download tokens bound to the intended object.
- **SG-0429** — Expire signed download links as documented.
- **SG-0430** — Limit signed links to intended HTTP methods where supported.
- **SG-0431** — Keep response filenames from injecting headers.
- **SG-0432** — Prevent public directory listings from exposing private documents.
- **SG-0433** — Protect backup and export download routes.
- **SG-0434** — Handle file-not-found errors without disclosing internal paths.
- **SG-0435** — Keep archive extraction paths inside the destination directory.
- **SG-0436** — Reject conflicting canonical names during archive extraction.
- **SG-0437** — Apply safe permissions to extracted files.
- **SG-0438** — Prevent overwriting security-sensitive files during import.
- **SG-0439** — Remove generated downloads after their retention period.
- **SG-0440** — Use synthetic files rather than reading unrelated system data.

## Structured parsers and document formats

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0441** — Disable external entity expansion in untrusted XML.
- **SG-0442** — Disable unnecessary document type definitions.
- **SG-0443** — Bound nested XML element depth.
- **SG-0444** — Bound JSON nesting before expensive processing.
- **SG-0445** — Reject duplicate security-sensitive JSON keys consistently.
- **SG-0446** — Use strict schema validation for signed structured messages.
- **SG-0447** — Keep parser error details from exposing internal resources.
- **SG-0448** — Limit archive expansion relative to the compressed input.
- **SG-0449** — Bound the number of archive members.
- **SG-0450** — Reject unexpected archive member types.
- **SG-0451** — Keep CSV exports from being interpreted as spreadsheet commands.
- **SG-0452** — Handle delimiter and quote escaping in CSV output.
- **SG-0453** — Validate multipart boundaries and part counts consistently.
- **SG-0454** — Reject ambiguous content encodings at parser boundaries.
- **SG-0455** — Keep PDF rendering from loading arbitrary external resources.
- **SG-0456** — Constrain document macros in server-side preview pipelines.
- **SG-0457** — Validate image parser inputs before invoking native decoders.
- **SG-0458** — Reject unsupported character encodings consistently.
- **SG-0459** — Handle numeric precision differences in structured financial inputs.
- **SG-0460** — Use bounded local samples to investigate parser disagreement.

## REST and general API behavior

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0461** — Require authentication on every documented private API route.
- **SG-0462** — Apply authorization after routing to the selected API version.
- **SG-0463** — Reject unsupported HTTP methods explicitly.
- **SG-0464** — Treat alternate method override mechanisms consistently.
- **SG-0465** — Enforce request schemas for writable properties.
- **SG-0466** — Exclude server-controlled fields from mass assignment.
- **SG-0467** — Return only fields authorized for the caller's role.
- **SG-0468** — Apply pagination limits on the server.
- **SG-0469** — Keep list filters from selecting unauthorized records.
- **SG-0470** — Validate content types before deserializing requests.
- **SG-0471** — Apply consistent authorization to batch API calls.
- **SG-0472** — Protect API documentation containing private schemas or credentials.
- **SG-0473** — Keep deprecated APIs subject to current account restrictions.
- **SG-0474** — Use idempotency semantics for sensitive retryable operations.
- **SG-0475** — Bind idempotency keys to the authenticated operation context.
- **SG-0476** — Avoid returning secrets in API error objects.
- **SG-0477** — Document resource-cost limits without stress-testing production.
- **SG-0478** — Apply authorization to asynchronous result retrieval.
- **SG-0479** — Prevent client-specified callback addresses from bypassing outbound policy.
- **SG-0480** — Confirm API behavior with an allowed baseline before interpreting differences.

## GraphQL

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0481** — Authorize each field resolver that returns private data.
- **SG-0482** — Authorize mutations independently of query permissions.
- **SG-0483** — Apply ownership checks to node lookups by global identifier.
- **SG-0484** — Keep aliases from bypassing per-operation policy.
- **SG-0485** — Bound query depth according to documented limits.
- **SG-0486** — Bound query cost using an appropriate cost model.
- **SG-0487** — Limit batch operations where batching is supported.
- **SG-0488** — Apply pagination bounds to nested collections.
- **SG-0489** — Prevent unapproved fields from being writable through input objects.
- **SG-0490** — Protect introspection according to the deployment's intended exposure.
- **SG-0491** — Avoid leaking secrets through detailed resolver errors.
- **SG-0492** — Preserve tenant boundaries in data-loader caches.
- **SG-0493** — Apply access checks before resolving related objects.
- **SG-0494** — Ensure subscriptions respect current membership changes.
- **SG-0495** — Keep persisted-query registries from accepting unauthorized replacements.
- **SG-0496** — Protect file-upload mutations with normal upload controls.
- **SG-0497** — Enforce anti-forgery protection for cookie-authenticated mutations.
- **SG-0498** — Keep query response caches separated by authorization context.
- **SG-0499** — Validate custom scalar parsing without evaluating executable syntax.
- **SG-0500** — Use small local queries when assessing resource-limit enforcement.

## Streaming, WebSockets, and RPC

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0501** — Authenticate before accepting a privileged WebSocket session.
- **SG-0502** — Validate browser origins for cookie-authenticated WebSockets.
- **SG-0503** — Authorize each WebSocket message action.
- **SG-0504** — Recheck permissions after a socket user's role changes.
- **SG-0505** — Expire or reauthenticate long-lived socket sessions.
- **SG-0506** — Validate message schemas before dispatch.
- **SG-0507** — Bound individual streaming message sizes.
- **SG-0508** — Keep broadcast channels separated by tenant membership.
- **SG-0509** — Protect subscription identifiers from unauthorized reuse.
- **SG-0510** — Handle reconnect tokens as scoped authentication material.
- **SG-0511** — Authenticate gRPC calls at the correct service boundary.
- **SG-0512** — Authorize gRPC methods independently from connection authentication.
- **SG-0513** — Validate protobuf fields used for ownership decisions.
- **SG-0514** — Keep RPC metadata from overriding trusted identity.
- **SG-0515** — Restrict reflection services according to deployment policy.
- **SG-0516** — Bound streaming duration and outstanding messages in a local fixture.
- **SG-0517** — Clean up subscriptions after account suspension.
- **SG-0518** — Avoid returning internal stack traces through streaming errors.
- **SG-0519** — Protect event replay endpoints with the original subscription permissions.
- **SG-0520** — Record message direction and identity in reproducible stream evidence.

## Business workflow integrity

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0521** — Enforce required workflow steps on the server.
- **SG-0522** — Reject state transitions that skip mandatory approval.
- **SG-0523** — Bind approval to the exact item and version reviewed.
- **SG-0524** — Revoke an approval when material input changes.
- **SG-0525** — Keep canceled operations from being completed later.
- **SG-0526** — Require separate privileges for proposing and approving sensitive changes.
- **SG-0527** — Prevent users from approving their own request where separation is required.
- **SG-0528** — Enforce per-user limits using trusted identity data.
- **SG-0529** — Apply organization limits across alternate client channels.
- **SG-0530** — Handle negative quantities according to business rules.
- **SG-0531** — Handle zero quantities without granting unintended benefits.
- **SG-0532** — Bound monetary and quantity precision before calculations.
- **SG-0533** — Recalculate authoritative totals on the server.
- **SG-0534** — Keep promotional eligibility independent of client-supplied labels.
- **SG-0535** — Prevent expired offers from being redeemed through stale requests.
- **SG-0536** — Validate ownership when transferring credits or entitlements.
- **SG-0537** — Keep trial conversion from restoring already consumed benefits.
- **SG-0538** — Protect administrative workflow overrides with explicit privilege.
- **SG-0539** — Model abuse cases with synthetic balances and harmless objects.
- **SG-0540** — Distinguish unexpected business behavior from a security boundary violation.

## Payments, billing, and value transfer

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0541** — Derive payable amounts from trusted product and pricing data.
- **SG-0542** — Validate currency consistently across checkout and settlement.
- **SG-0543** — Bind a payment intent to its intended customer.
- **SG-0544** — Bind a payment intent to the intended order.
- **SG-0545** — Verify payment-provider notifications before granting value.
- **SG-0546** — Prevent a canceled payment from fulfilling an order.
- **SG-0547** — Prevent duplicate payment callbacks from duplicating fulfillment.
- **SG-0548** — Keep refund amounts within the settled amount.
- **SG-0549** — Require authorization before changing a payout destination.
- **SG-0550** — Reauthenticate sensitive billing-profile changes.
- **SG-0551** — Apply coupon limits after calculating eligible items.
- **SG-0552** — Keep tax and shipping inputs from overriding the payable total.
- **SG-0553** — Handle partial refunds without restoring excess credits.
- **SG-0554** — Preserve ledger balance invariants across failed transactions.
- **SG-0555** — Restrict invoice access to authorized customer identities.
- **SG-0556** — Keep test payment credentials separate from production credentials.
- **SG-0557** — Verify subscription cancellation stops future entitlement renewal as designed.
- **SG-0558** — Apply proration rules without creating negative payment obligations unexpectedly.
- **SG-0559** — Use provider sandboxes without placing real charges or orders.
- **SG-0560** — Record financial impact as a bounded hypothesis until independently validated.

## Concurrency and retry safety

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Owned local fixture, operation order, expected invariant, observed state, and a sequential negative control. No production concurrency exercise.

- **SG-0561** — Make single-use token consumption atomic.
- **SG-0562** — Make inventory reservation atomic with order acceptance.
- **SG-0563** — Enforce invitation redemption limits under concurrent requests.
- **SG-0564** — Prevent simultaneous withdrawals from exceeding an authorized balance.
- **SG-0565** — Apply coupon-use limits atomically.
- **SG-0566** — Prevent repeated task retries from duplicating value transfers.
- **SG-0567** — Keep account deletion and update races from restoring deleted data.
- **SG-0568** — Recheck authorization when an asynchronous job begins execution.
- **SG-0569** — Protect permission changes against stale writes.
- **SG-0570** — Use consistent version checks for approval-state updates.
- **SG-0571** — Ensure retry tokens cannot be reused for a different operation.
- **SG-0572** — Keep lock ownership from surviving an expired transaction unexpectedly.
- **SG-0573** — Handle worker crashes without losing required rollback actions.
- **SG-0574** — Bound the lifetime of distributed transaction leases.
- **SG-0575** — Avoid performing an external side effect before the durable intent is saved.
- **SG-0576** — Detect duplicate events before applying irreversible changes.
- **SG-0577** — Keep cancellation effective against queued but unstarted work.
- **SG-0578** — Preserve quota limits across multiple application instances.
- **SG-0579** — Reproduce concurrency hypotheses only in an authorized controlled environment.
- **SG-0580** — Record operation order and negative controls for a race hypothesis.

## Caches, proxies, and routing

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0581** — Partition private cached responses by authorization context.
- **SG-0582** — Keep tenant-specific responses out of shared public cache entries.
- **SG-0583** — Include relevant content-negotiation fields in cache variation.
- **SG-0584** — Avoid trusting unvalidated forwarded-host values.
- **SG-0585** — Keep proxy rewrite rules consistent with application authorization.
- **SG-0586** — Treat ambiguous request framing as a controlled-lab investigation.
- **SG-0587** — Ensure frontend and backend parsers agree on message boundaries.
- **SG-0588** — Avoid using unkeyed user input to construct cached security-sensitive output.
- **SG-0589** — Keep redirects generated from untrusted input out of shared caches.
- **SG-0590** — Protect cache invalidation endpoints from unauthorized use.
- **SG-0591** — Avoid caching authentication and recovery responses publicly.
- **SG-0592** — Handle path normalization consistently across CDN and origin.
- **SG-0593** — Separate static asset caching from authenticated document caching.
- **SG-0594** — Ensure error responses cannot expose another user's cached body.
- **SG-0595** — Preserve authentication headers only across intended trusted hops.
- **SG-0596** — Prevent alternate hostnames from bypassing origin access rules.
- **SG-0597** — Keep debug routing headers inaccessible to untrusted clients.
- **SG-0598** — Validate cache lifetimes for signed private content.
- **SG-0599** — Use isolated caches and synthetic responses for poisoning experiments.
- **SG-0600** — Do not infer exploitable cache behavior from a single response header.

## Transport and browser response controls

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0601** — Verify certificate validation is enabled for outbound HTTPS clients.
- **SG-0602** — Check the intended hostname during certificate validation.
- **SG-0603** — Require encrypted transport for authentication and private data.
- **SG-0604** — Record HSTS behavior on the exact observed response.
- **SG-0605** — Record content-type sniffing protection on untrusted downloads.
- **SG-0606** — Record frame restrictions on sensitive interactive pages.
- **SG-0607** — Assess content security policy against the application's actual script needs.
- **SG-0608** — Avoid treating a missing header alone as a bounty-worthy vulnerability.
- **SG-0609** — Prevent insecure mixed content on authenticated pages.
- **SG-0610** — Set referrer behavior appropriate to sensitive navigation.
- **SG-0611** — Restrict browser permissions that the application does not need.
- **SG-0612** — Use cross-origin isolation controls where the feature requires them.
- **SG-0613** — Serve sensitive responses with an appropriate cache policy.
- **SG-0614** — Keep transport downgrades out of authentication redirect chains.
- **SG-0615** — Validate mutual-TLS client identity when it is an authorization factor.
- **SG-0616** — Protect internal service transport according to its trust model.
- **SG-0617** — Expire and rotate certificates without disabling verification.
- **SG-0618** — Keep certificate private keys outside distributable client assets.
- **SG-0619** — Distinguish HEAD observations from untested GET response behavior.
- **SG-0620** — Record exact timestamps and response context for transport observations.

## Secrets and cryptographic use

Suggested contexts: web, api, source, cloud. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0621** — Generate security tokens with a cryptographically appropriate random source.
- **SG-0622** — Keep encryption keys separate from the encrypted data where required.
- **SG-0623** — Use authenticated encryption for data requiring integrity protection.
- **SG-0624** — Avoid reusing nonces with algorithms that require unique nonces.
- **SG-0625** — Use algorithms and key sizes appropriate to the data lifetime.
- **SG-0626** — Keep encryption failures from returning partial plaintext.
- **SG-0627** — Use distinct keys for unrelated cryptographic purposes.
- **SG-0628** — Support rotation without exposing historical key material.
- **SG-0629** — Store service credentials in a controlled secret store.
- **SG-0630** — Keep production secrets out of source repositories.
- **SG-0631** — Keep secrets out of client-side bundles.
- **SG-0632** — Redact credentials in application telemetry.
- **SG-0633** — Apply least privilege to secret retrieval.
- **SG-0634** — Revoke secrets when their integration is removed.
- **SG-0635** — Protect backup copies of encryption keys.
- **SG-0636** — Compare authentication secrets using appropriate constant-time routines.
- **SG-0637** — Avoid inventing custom cryptographic protocols.
- **SG-0638** — Handle cryptographic exceptions without falling back to plaintext.
- **SG-0639** — Document what data a disclosed value could actually unlock.
- **SG-0640** — Never validate a suspected credential against an unrelated live service.

## Errors, logging, and monitoring

Suggested contexts: web, api, source, cloud. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0641** — Return generic client errors without internal stack traces.
- **SG-0642** — Keep database credentials out of exception messages.
- **SG-0643** — Keep session tokens out of access logs.
- **SG-0644** — Keep personal data out of unnecessary debug logs.
- **SG-0645** — Restrict access to application log viewers.
- **SG-0646** — Separate tenant-visible logs by organization.
- **SG-0647** — Encode untrusted text before displaying it in an administrative log viewer.
- **SG-0648** — Prevent line breaks in untrusted log fields from forging records.
- **SG-0649** — Record the actor for sensitive administrative actions.
- **SG-0650** — Record failed authorization attempts without retaining secrets.
- **SG-0651** — Preserve event timestamps with a consistent time basis.
- **SG-0652** — Protect audit-log integrity from ordinary application users.
- **SG-0653** — Bound log volume using controlled local tests.
- **SG-0654** — Handle log-delivery failures without disabling authorization.
- **SG-0655** — Keep correlation identifiers from becoming authorization credentials.
- **SG-0656** — Redact secrets in crash reports sent to third parties.
- **SG-0657** — Restrict debug endpoints in production configuration.
- **SG-0658** — Ensure alert destinations do not expose private tenant details.
- **SG-0659** — Apply documented retention limits to security logs.
- **SG-0660** — Separate an informational error disclosure from demonstrated material impact.

## Privacy and data lifecycle

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0661** — Minimize personal fields returned by public profile endpoints.
- **SG-0662** — Honor privacy settings in search and discovery features.
- **SG-0663** — Enforce audience restrictions on shared personal content.
- **SG-0664** — Protect bulk personal-data export with fresh authentication.
- **SG-0665** — Bind export downloads to the requesting identity.
- **SG-0666** — Delete or revoke exports after their intended lifetime.
- **SG-0667** — Keep deleted personal records out of normal search results.
- **SG-0668** — Apply deletion rules to derived indexes and caches.
- **SG-0669** — Restrict access to historical versions containing removed private data.
- **SG-0670** — Preserve privacy settings during account migration.
- **SG-0671** — Avoid sending private input to third-party analytics unnecessarily.
- **SG-0672** — Keep sensitive query parameters out of referrer destinations.
- **SG-0673** — Review browser storage for unnecessary sensitive data retention.
- **SG-0674** — Protect consent changes from unauthorized modification.
- **SG-0675** — Keep private data out of notification previews where settings require it.
- **SG-0676** — Validate data masking for low-privilege support roles.
- **SG-0677** — Apply retention rules to abandoned drafts and temporary uploads.
- **SG-0678** — Document cross-border processing constraints relevant to the program.
- **SG-0679** — Use synthetic personal data in research evidence.
- **SG-0680** — Stop and minimize collection if unrelated private data appears.

## Cloud object storage

Suggested contexts: cloud. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0681** — Restrict bucket listing to intended identities.
- **SG-0682** — Restrict object reading according to the data classification.
- **SG-0683** — Restrict object writing to authorized principals.
- **SG-0684** — Prevent public overwrite of published application assets.
- **SG-0685** — Scope signed upload URLs to intended object names.
- **SG-0686** — Scope signed download URLs to intended objects.
- **SG-0687** — Expire signed storage URLs as documented.
- **SG-0688** — Bind upload constraints such as size and content type where supported.
- **SG-0689** — Keep storage service credentials out of frontend code.
- **SG-0690** — Separate tenant data by enforced authorization rather than prefix convention alone.
- **SG-0691** — Review access to prior object versions.
- **SG-0692** — Apply retention rules to object replicas and backups.
- **SG-0693** — Protect storage audit logs from modification by upload users.
- **SG-0694** — Require encryption settings appropriate to stored data.
- **SG-0695** — Keep custom storage-domain ownership under program control.
- **SG-0696** — Prevent lifecycle rules from exposing expired temporary artifacts.
- **SG-0697** — Protect object metadata that contains private information.
- **SG-0698** — Review cross-origin rules for private storage content.
- **SG-0699** — Validate storage policy changes using local policy evaluation where possible.
- **SG-0700** — Avoid uploading, deleting, or claiming resources without explicit permission.

## Cloud identity and service boundaries

Suggested contexts: cloud. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0701** — Limit workload roles to the operations they require.
- **SG-0702** — Scope role-assumption trust to intended principals.
- **SG-0703** — Validate external identifiers used in delegated cloud access.
- **SG-0704** — Avoid granting wildcard resource access where narrower scope is possible.
- **SG-0705** — Restrict identity-policy modification to authorized administrators.
- **SG-0706** — Separate deployment privileges from runtime privileges.
- **SG-0707** — Keep cloud metadata access outside untrusted request paths.
- **SG-0708** — Use temporary workload credentials where appropriate.
- **SG-0709** — Rotate and revoke long-lived cloud access keys.
- **SG-0710** — Restrict secret-store access by workload identity.
- **SG-0711** — Prevent lower-trust services from invoking privileged internal functions.
- **SG-0712** — Apply authorization to serverless function invocation.
- **SG-0713** — Validate event sources before processing cloud-triggered jobs.
- **SG-0714** — Keep network placement from substituting for service authentication.
- **SG-0715** — Restrict public management interfaces according to deployment intent.
- **SG-0716** — Record ownership before treating a dangling service reference as a lead.
- **SG-0717** — Review infrastructure templates for unintended public exposure.
- **SG-0718** — Protect cloud audit configuration from ordinary runtime roles.
- **SG-0719** — Use supplied policy documents rather than enumerating another account.
- **SG-0720** — Treat resource takeover hypotheses as unverified until explicitly permitted validation.

## Containers and orchestration

Suggested contexts: cloud. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0721** — Run application containers with only required privileges.
- **SG-0722** — Avoid unnecessary host filesystem mounts.
- **SG-0723** — Restrict access to container runtime sockets.
- **SG-0724** — Use an appropriate non-root runtime identity.
- **SG-0725** — Constrain Linux capabilities to those the workload needs.
- **SG-0726** — Keep container images free of production secrets.
- **SG-0727** — Pin deployed image identities where reproducibility requires it.
- **SG-0728** — Verify image provenance before deployment.
- **SG-0729** — Apply resource limits in controlled configuration review.
- **SG-0730** — Keep orchestration dashboards behind intended authentication.
- **SG-0731** — Scope service-account permissions to the workload's namespace and purpose.
- **SG-0732** — Prevent pods from reading unrelated workload secrets.
- **SG-0733** — Review network policies between trust zones.
- **SG-0734** — Disable automatic service-account token mounting where unnecessary.
- **SG-0735** — Protect admission policy from unprivileged modification.
- **SG-0736** — Keep debug containers subject to administrative authorization.
- **SG-0737** — Avoid exposing development ports in production manifests.
- **SG-0738** — Check secret-file permissions inside the container image.
- **SG-0739** — Review backup and snapshot handling for container volumes.
- **SG-0740** — Perform container escape research only in an explicitly authorized isolated lab.

## Build and deployment pipelines

Suggested contexts: source, cloud. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0741** — Keep untrusted pull-request code from receiving production secrets.
- **SG-0742** — Avoid executing untrusted metadata as shell syntax in CI.
- **SG-0743** — Pin third-party build actions according to project policy.
- **SG-0744** — Restrict workflow token permissions to required operations.
- **SG-0745** — Separate read-only tests from deployment credentials.
- **SG-0746** — Require appropriate approval for production deployment changes.
- **SG-0747** — Bind workload identity claims to the intended repository.
- **SG-0748** — Bind workload identity claims to the intended branch or environment.
- **SG-0749** — Validate artifact provenance before release promotion.
- **SG-0750** — Keep build caches separated across incompatible trust contexts.
- **SG-0751** — Protect release signing keys from ordinary test jobs.
- **SG-0752** — Prevent downloaded artifacts from overwriting sensitive runner paths.
- **SG-0753** — Keep secrets out of archived build logs.
- **SG-0754** — Restrict who can alter deployment environment variables.
- **SG-0755** — Expire temporary runner credentials after the job.
- **SG-0756** — Preserve verification steps when retrying a failed deployment.
- **SG-0757** — Keep preview deployments from receiving production customer data.
- **SG-0758** — Restrict deployment hooks to intended authorized callers.
- **SG-0759** — Audit dependency-install scripts before running untrusted builds.
- **SG-0760** — Investigate pipeline hypotheses using local fixtures or owned repositories.

## Dependencies and software supply chain

Suggested contexts: source. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0761** — Record exact installed dependency versions from a lockfile.
- **SG-0762** — Distinguish direct dependencies from transitive dependencies.
- **SG-0763** — Match advisories to the correct package ecosystem.
- **SG-0764** — Check whether the installed version is in the affected range.
- **SG-0765** — Verify whether vulnerable functionality is reachable in the application.
- **SG-0766** — Record mitigations that alter advisory applicability.
- **SG-0767** — Avoid treating a package-name match as a confirmed vulnerability.
- **SG-0768** — Check for unsupported dependencies with no maintained security path.
- **SG-0769** — Keep private package namespaces from resolving to unintended public packages.
- **SG-0770** — Verify package integrity against trusted lockfile hashes.
- **SG-0771** — Review installation hooks that run during dependency setup.
- **SG-0772** — Preserve lockfile changes in code review.
- **SG-0773** — Keep development-only dependencies separate from runtime exposure.
- **SG-0774** — Check whether bundled copies remain after an apparent upgrade.
- **SG-0775** — Track container base-image components in the software inventory.
- **SG-0776** — Validate the origin of downloaded binaries.
- **SG-0777** — Avoid loading plugins from user-writable search paths.
- **SG-0778** — Review trust in remotely hosted scripts used by the application.
- **SG-0779** — Record advisory publication and last-check dates.
- **SG-0780** — Validate suspected dependency impact without exploiting unrelated deployments.

## Python source and data-flow review

Suggested contexts: source. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Authorized Python file digest, analyzer version, line and input path where available, safe control, and unsupported-language/runtime limits.

- **SG-0781** — Trace untrusted input reaching Python eval or exec.
- **SG-0782** — Trace untrusted input reaching a Python shell command.
- **SG-0783** — Trace untrusted input reaching Python pickle deserialization.
- **SG-0784** — Trace untrusted input reaching an unsafe Python YAML loader.
- **SG-0785** — Review Python HTTP calls that disable TLS certificate verification.
- **SG-0786** — Trace untrusted input reaching dynamically constructed Python SQL.
- **SG-0787** — Review Python pseudorandom generators used for security tokens.
- **SG-0788** — Check whether Python route decorators enforce intended authentication.
- **SG-0789** — Check whether exceptions bypass an authorization return path.
- **SG-0790** — Follow tainted values through helper function aliases.
- **SG-0791** — Follow tainted values across supported source modules.
- **SG-0792** — Recheck validation after a variable is reassigned.
- **SG-0793** — Distinguish fixed SQL constants from externally influenced SQL fragments.
- **SG-0794** — Check whether numeric conversion genuinely constrains the later query value.
- **SG-0795** — Review sensitive Python default arguments with shared mutable state.
- **SG-0796** — Keep dynamic import targets separate from untrusted request fields.
- **SG-0797** — Review temporary-file creation for unsafe name reuse.
- **SG-0798** — Check filesystem permissions assigned by Python application code.
- **SG-0799** — Record analyzer limits for unsupported decorators and dynamic dispatch.
- **SG-0800** — Verify a source hypothesis with a safe negative control before reporting it.

## Android application research

Suggested contexts: android. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Permitted Android package/build, owned device context, relevant platform configuration, and redacted local observations.

- **SG-0801** — Match the installed package to the explicitly listed Android asset.
- **SG-0802** — Record the build version and signing identity under review.
- **SG-0803** — Restrict exported activities to intended callers.
- **SG-0804** — Restrict exported services to intended callers.
- **SG-0805** — Restrict broadcast receivers handling sensitive actions.
- **SG-0806** — Protect content providers exposing private records.
- **SG-0807** — Validate deep-link parameters before privileged navigation.
- **SG-0808** — Verify ownership of Android App Links where used.
- **SG-0809** — Keep authentication secrets out of world-readable storage.
- **SG-0810** — Protect sensitive preferences with appropriate platform storage.
- **SG-0811** — Review backup inclusion of private application data.
- **SG-0812** — Avoid logging tokens through Android diagnostic output.
- **SG-0813** — Restrict JavaScript interfaces exposed to untrusted WebView content.
- **SG-0814** — Keep WebView navigation within intended trust boundaries.
- **SG-0815** — Validate TLS connections using the expected trust policy.
- **SG-0816** — Keep release builds from enabling unnecessary debugging.
- **SG-0817** — Protect clipboard use for sensitive values.
- **SG-0818** — Handle biometric fallback according to the intended authentication policy.
- **SG-0819** — Require server-side authorization despite client-side interface restrictions.
- **SG-0820** — Use an owned test device and expressly permitted application build.

## iOS application research

Suggested contexts: ios. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Permitted iOS bundle/build, owned device context, relevant platform configuration, and redacted local observations.

- **SG-0821** — Match the installed bundle identifier to the listed iOS asset.
- **SG-0822** — Record the application version and distribution channel.
- **SG-0823** — Store sensitive credentials using appropriate Keychain access controls.
- **SG-0824** — Keep private data out of unnecessarily shared app groups.
- **SG-0825** — Review iCloud and device backup exposure of sensitive files.
- **SG-0826** — Apply appropriate file data-protection classes.
- **SG-0827** — Validate custom URL scheme inputs before privileged actions.
- **SG-0828** — Verify Universal Link association ownership where used.
- **SG-0829** — Keep WKWebView message handlers away from untrusted origins.
- **SG-0830** — Restrict WebView navigation carrying authenticated context.
- **SG-0831** — Review App Transport Security exceptions for necessity.
- **SG-0832** — Validate server trust without blanket certificate acceptance.
- **SG-0833** — Keep sensitive values out of system logs.
- **SG-0834** — Avoid exposing private information in app-switcher snapshots.
- **SG-0835** — Protect sensitive pasteboard data according to the product's needs.
- **SG-0836** — Handle biometric enrollment changes according to authentication policy.
- **SG-0837** — Keep local authentication success separate from server authorization.
- **SG-0838** — Restrict extensions to the minimum shared data they need.
- **SG-0839** — Review release entitlements for unnecessary privileged capabilities.
- **SG-0840** — Use an owned device and a build allowed by the program.

## Desktop apps and browser extensions

Suggested contexts: desktop. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Permitted desktop/extension build, owned local environment, relevant privilege boundary, and redacted configuration or test evidence.

- **SG-0841** — Verify the desktop application identifier is explicitly in scope.
- **SG-0842** — Validate desktop update signatures before installation.
- **SG-0843** — Keep updater metadata within a trusted source policy.
- **SG-0844** — Restrict local IPC methods to intended callers.
- **SG-0845** — Authenticate privileged IPC operations independently of window visibility.
- **SG-0846** — Keep untrusted renderer content away from native execution APIs.
- **SG-0847** — Apply appropriate Electron context isolation where relevant.
- **SG-0848** — Disable unnecessary Node integration in untrusted renderer contexts.
- **SG-0849** — Validate custom protocol handler parameters.
- **SG-0850** — Protect local credential stores using appropriate OS facilities.
- **SG-0851** — Restrict browser-extension host permissions to required sites.
- **SG-0852** — Validate the sender of extension messages.
- **SG-0853** — Keep content-script input from invoking privileged extension actions.
- **SG-0854** — Protect extension storage containing authentication state.
- **SG-0855** — Avoid injecting remote executable code into an extension.
- **SG-0856** — Restrict web-accessible extension resources according to their sensitivity.
- **SG-0857** — Validate native-messaging requests against a strict schema.
- **SG-0858** — Keep desktop diagnostic bundles free of unnecessary secrets.
- **SG-0859** — Review local service binding and authentication in an owned lab.
- **SG-0860** — Separate client hardening observations from a proven server-side vulnerability.

## Webhooks, queues, and asynchronous jobs

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0861** — Verify webhook signatures before processing events.
- **SG-0862** — Bind signature verification to the raw bytes actually received.
- **SG-0863** — Enforce webhook timestamp freshness where supported.
- **SG-0864** — Reject duplicate webhook delivery identifiers after successful processing.
- **SG-0865** — Bind webhook events to the intended customer integration.
- **SG-0866** — Keep webhook destinations within approved outbound restrictions.
- **SG-0867** — Avoid forwarding internal credentials in webhook requests.
- **SG-0868** — Protect webhook secret rotation with administrative authorization.
- **SG-0869** — Authenticate producers before accepting queue messages.
- **SG-0870** — Validate message schemas before starting background work.
- **SG-0871** — Recheck object authorization at job execution time.
- **SG-0872** — Bind job-result retrieval to the requesting identity.
- **SG-0873** — Isolate queue consumers across tenant boundaries.
- **SG-0874** — Handle dead-letter messages without exposing secrets.
- **SG-0875** — Keep retries from repeating non-idempotent side effects.
- **SG-0876** — Bound retry schedules to avoid unbounded job accumulation.
- **SG-0877** — Honor cancellation before a queued job performs a side effect.
- **SG-0878** — Prevent low-trust messages from selecting arbitrary job handlers.
- **SG-0879** — Avoid logging sensitive message bodies by default.
- **SG-0880** — Use synthetic events in an owned queue when validating behavior.

## Email, notifications, and shared links

Suggested contexts: web, api, source. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Relevant authorized source/configuration or an expressly permitted owned-account observation; exact version and context, expected behavior, a safe baseline, and minimal redacted evidence.

- **SG-0881** — Prevent user-controlled email fields from injecting message headers.
- **SG-0882** — Construct action links from trusted application origins.
- **SG-0883** — Keep private data out of email subjects where unnecessary.
- **SG-0884** — Protect notification preferences from unauthorized changes.
- **SG-0885** — Recheck recipient authorization before sending private notifications.
- **SG-0886** — Avoid sending one tenant's notification to another tenant's address list.
- **SG-0887** — Escape untrusted content in HTML email templates.
- **SG-0888** — Keep mail preview pages behind appropriate access checks.
- **SG-0889** — Expire sensitive shared links according to their purpose.
- **SG-0890** — Revoke shared links when the owner disables sharing.
- **SG-0891** — Bind invitation links to their original organization and role.
- **SG-0892** — Keep shared-link permissions narrower than owner privileges.
- **SG-0893** — Avoid exposing passwords or reusable secrets through notifications.
- **SG-0894** — Limit security-notification detail visible on a locked device.
- **SG-0895** — Prevent unsubscribe tokens from authorizing unrelated account operations.
- **SG-0896** — Protect group recipient expansion from untrusted membership input.
- **SG-0897** — Check that removed collaborators stop receiving private updates.
- **SG-0898** — Handle bounced or reassigned contact addresses without identity confusion.
- **SG-0899** — Use researcher-owned destinations for permitted delivery tests.
- **SG-0900** — Do not send real users messages as part of an unapproved experiment.

## AI instructions and untrusted content

Suggested contexts: ai. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Synthetic instructions and canary data, model/configuration identity, observed tool behavior, and a benign baseline.

- **SG-0901** — Keep retrieved text separate from higher-trust application instructions.
- **SG-0902** — Treat uploaded documents as data rather than operational commands.
- **SG-0903** — Keep tool-returned text from changing the agent's authorization scope.
- **SG-0904** — Preserve user intent when a web page requests an unrelated action.
- **SG-0905** — Prevent quoted instructions from silently becoming executable directives.
- **SG-0906** — Keep hidden document text from overriding the requested task.
- **SG-0907** — Handle conflicting tool output with an explicit trust policy.
- **SG-0908** — Restrict model-selected destinations to independently validated resources.
- **SG-0909** — Prevent generated text from being executed as application code implicitly.
- **SG-0910** — Validate structured model outputs before consuming their fields.
- **SG-0911** — Apply output encoding when rendering generated HTML-like content.
- **SG-0912** — Keep prompts from being the sole enforcement of access controls.
- **SG-0913** — Separate public prompt disclosure from disclosure of actual secrets.
- **SG-0914** — Avoid placing secrets in model context when the task does not require them.
- **SG-0915** — Preserve approval requirements when the model proposes a tool call.
- **SG-0916** — Treat model-generated claims of permission as unverified.
- **SG-0917** — Test injection resistance with harmless synthetic instructions and canary data.
- **SG-0918** — Record the model and application configuration for a reproducible evaluation.
- **SG-0919** — Measure whether a harmful action occurred rather than relying on suggestive wording.
- **SG-0920** — Distinguish a model safety refusal from application-level authorization enforcement.

## Retrieval, embeddings, and AI memory

Suggested contexts: ai. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Synthetic source documents, two authorized identities where needed, provenance, access policy, and observed retrieval behavior.

- **SG-0921** — Apply user authorization before retrieving private documents.
- **SG-0922** — Partition vector searches by the authorized tenant.
- **SG-0923** — Preserve source permissions when creating an embedding index.
- **SG-0924** — Remove deleted documents from retrievable indexes as required.
- **SG-0925** — Recheck permissions after a source document's audience changes.
- **SG-0926** — Keep retrieval caches separated by identity and tenant.
- **SG-0927** — Store provenance for retrieved passages.
- **SG-0928** — Prevent untrusted source text from changing retrieval filters.
- **SG-0929** — Validate document ingestion destinations and file types.
- **SG-0930** — Protect ingestion jobs from unauthorized source replacement.
- **SG-0931** — Keep private snippets out of public search previews.
- **SG-0932** — Restrict access to raw embeddings according to their data sensitivity.
- **SG-0933** — Avoid treating semantic similarity as proof that two identities are equivalent.
- **SG-0934** — Keep long-term agent memory within the user's intended scope.
- **SG-0935** — Require authorization before sharing memory across workspaces.
- **SG-0936** — Apply retention rules to conversation summaries and derived memories.
- **SG-0937** — Label stale retrieved information instead of presenting it as current evidence.
- **SG-0938** — Validate citations against actually retrieved sources.
- **SG-0939** — Use synthetic documents to test cross-user retrieval isolation.
- **SG-0940** — Record whether an apparent leak came from retrieval, cache, or generated guesswork.

## AI agents and tool permissions

Suggested contexts: ai. Method: controlled manual review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Mock tool calls, allowed user intent, tool authorization decision, side effects if any, and a safe baseline.

- **SG-0941** — Grant each agent only the tools required for its task.
- **SG-0942** — Validate tool arguments independently of model-generated explanations.
- **SG-0943** — Bind tool credentials to the correct user identity.
- **SG-0944** — Keep tool output from requesting broader credentials.
- **SG-0945** — Require explicit approval for actions outside existing authorization.
- **SG-0946** — Preserve approval checks across tool retries.
- **SG-0947** — Separate read permissions from write permissions.
- **SG-0948** — Constrain filesystem tools to the permitted workspace.
- **SG-0949** — Constrain network tools to permitted destinations and methods.
- **SG-0950** — Keep scheduling tools from creating unauthorized recurring actions.
- **SG-0951** — Prevent child agents from receiving broader authority than their parent.
- **SG-0952** — Track delegated actions to the initiating user's request.
- **SG-0953** — Validate recipient identity before external message delivery.
- **SG-0954** — Keep secret-bearing tool output out of public artifacts.
- **SG-0955** — Apply spending limits before invoking paid resources.
- **SG-0956** — Stop dependent actions after a permission or access denial.
- **SG-0957** — Ensure cancellation reaches queued agent actions.
- **SG-0958** — Require evidence for a tool action's reported completion.
- **SG-0959** — Use mock tools to test destructive-action boundaries safely.
- **SG-0960** — Record unresolved tool errors without claiming task success.

## AI model and data pipelines

Suggested contexts: ai. Method: source or configuration review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Model/artifact identity, authorized configuration or synthetic dataset, repeatable evaluation, and documented uncertainty.

- **SG-0961** — Document which model version produced a research result.
- **SG-0962** — Validate the provenance of downloaded model artifacts.
- **SG-0963** — Avoid unsafe object loading when opening model files.
- **SG-0964** — Separate model configuration from untrusted evaluation inputs.
- **SG-0965** — Protect training and fine-tuning datasets according to their sensitivity.
- **SG-0966** — Require consent before using private user data for training.
- **SG-0967** — Keep evaluation data separate from the training set.
- **SG-0968** — Record contamination risks in benchmark results.
- **SG-0969** — Review access to model-serving administration endpoints.
- **SG-0970** — Apply request budgets to expensive inference operations.
- **SG-0971** — Bound context size before allocating model resources.
- **SG-0972** — Keep inference caches isolated when requests contain private data.
- **SG-0973** — Redact sensitive inputs from model telemetry.
- **SG-0974** — Validate generated dependency names before installing packages.
- **SG-0975** — Review generated code before granting it execution privileges.
- **SG-0976** — Protect model deployment credentials from inference requests.
- **SG-0977** — Track human-reviewed false positives in research evaluations.
- **SG-0978** — Use deterministic local fixtures where they adequately test the boundary.
- **SG-0979** — Avoid claiming benchmark performance as proof of real-world vulnerability discovery.
- **SG-0980** — Record uncertainty and unsupported capabilities in every AI-assisted finding.

## Evidence, validation, and reporting

Suggested contexts: all. Method: document review.

**Before review:** Current permission for the exact asset and method; owned test identities where needed. Use local synthetic fixtures when an operation could change data, spend money, or affect availability.

**Evidence to keep:** Minimal reproducible evidence, permission record, negative control, impact reasoning, redaction, and the remaining validation questions.

- **SG-0981** — Record the exact permitted asset associated with a hypothesis.
- **SG-0982** — Record the time and environment of each observation.
- **SG-0983** — Separate raw observation from interpretation.
- **SG-0984** — Document the prerequisites needed to reproduce a result.
- **SG-0985** — Use a benign baseline that demonstrates expected behavior.
- **SG-0986** — Use a negative control that rules out an obvious alternate explanation.
- **SG-0987** — Repeat a result only within the permitted request budget.
- **SG-0988** — Record the affected user's role using synthetic identifiers.
- **SG-0989** — Minimize sensitive data in screenshots and saved responses.
- **SG-0990** — Redact authentication material before storing a report draft.
- **SG-0991** — Describe the security boundary that was crossed.
- **SG-0992** — Explain practical impact without overstating the evidence.
- **SG-0993** — Check program exclusions before classifying a lead as reportable.
- **SG-0994** — Check whether the same root cause already has a saved investigation.
- **SG-0995** — Record unsuccessful and inconclusive attempts honestly.
- **SG-0996** — Keep laboratory reproduction separate from proof on a live asset.
- **SG-0997** — Link a code hypothesis to the actual deployed version where known.
- **SG-0998** — Include an appropriate remediation direction in a validated draft.
- **SG-0999** — Require separate authorization before submitting or contacting a program.
- **SG-1000** — Keep accepted reports, confirmed bugs, and paid bounties as separate outcomes.
