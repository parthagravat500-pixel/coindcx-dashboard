# ScopeGuard testing methods and current coverage

Updated 25 September 2026. These notes describe implemented coverage, not expert
certification or a guarantee of accepted reports or earnings.

## Sequential work

Configured private-data profiles run one at a time and rotate between due
programs. Saved exact URLs, current scope, permission expiry and the pause state
still control every request. Discovery and shortlisting never create a target.
Programs without the required access or a supported test environment remain
visible with a reason; they are not recorded as scanned or clean.

The seven Intigriti programs at the top of the previous reward list now have
dated readiness notes linked to their official policies. Hardware, firmware and
automotive programs need specialist environments. Web/API programs still need
the actual eligible resources, permitted method and suitable test accounts.

## Two-account authorization comparison

This implements a bounded form of OWASP WSTG-v42-ATHZ-02 and PortSwigger's
horizontal access-control method. Both accounts and records must belong to the
operator, with no intended sharing between them.

1. Account A reads its own synthetic marker at an exact approved JSON URL.
2. Account B reads a different marker at its own approved JSON URL.
3. Account B reads account A's exact URL.
4. If A's marker appears, repeat that comparison once.
5. Repeat both own-account controls before drawing a conclusion.

The maximum is six GETs, at least one second apart, every fifteen minutes.
URLs must have the same HTTPS origin and program policy. Both authorizations
must remain valid. The scanner neither guesses record IDs nor modifies data.
Raw response bodies, markers and credentials are not included in evidence.
Exposure, failed controls, uncertain outcomes, rate limits, server failures,
pause or revoked permissions stop the profile. Bounty eligibility and identity
separation still require review; an observed marker exposure is not submitted.

Production transport accepts only approved public HTTPS destinations, pins DNS
resolution, validates TLS, does not follow redirects, and caps JSON bodies at
64 KB. Local network fixtures are test-only transports, not production options.

Existing anonymous comparisons remain a separate mode with four-request limits.
Existing configured tests are never silently upgraded to two-account testing.

## Validation

Regression cases cover positive and negative controls, expired sessions,
inconsistent responses, HTML/redirect responses, rate limits, credential
privacy, permission changes and request limits. A real loopback HTTP fixture
has secure and deliberately vulnerable variants; these are synthetic tests,
not findings against external bounty programs.

## Remaining limitations

- No universal crawler, firmware harness or general business-logic tester.
- No automatic purchase, account signup, identity verification or consent.
- No automatic expansion of program scope, test methods or saved credentials.
- No evidence of expert performance from this small fixture suite.
- No claims that a passed check makes an entire site secure.

Business-logic work starts with a program-specific role/resource matrix and
workflow invariants. A reusable checklist cannot substitute for understanding
the actual application, reproducing impact and checking known issues.

## Primary references

- https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/
- https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/horizontal-access-controls
- https://portswigger.net/web-security/logic-flaws
- https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic/

Official program links and concise readiness notes are recorded in readiness.py.
Policies may change; these dated notes never replace current authorization.
