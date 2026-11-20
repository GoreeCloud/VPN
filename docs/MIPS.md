# MIPS integration plan and source evidence

The required systems have distinct responsibility. This table records only **verified implementation vs. future requirements**.

| Owner | GoreeCloud VPN contract | Current state |
| --- | --- | --- |
| GoreeCloud UI | One design language from gc-ui; Compose/Material 3 Expressive Android; native Qt Quick Linux; Next.js web | Current UI uses canonical gc-ui Lagoon alpha semantic tokens by reference. Published shared UI package/adapter integration remains pending |
| GoreeCloud Mesh | Explicitly authorized, minimal health and enrollment/event contracts | The local GET /healthz JSON is management liveness only; Mesh source pin is historical and unavailable; no production contract |
| GoreeCloud Identity | Authentication, RBAC and device approval | A temporary local admin token and web session exist. Identity not yet integrated |
| GoreeShield | Consent, privacy, tracking prevention, retention, data transparency | No default analytics; consent/retention governance not yet enforced |
| Wardveil | Cybersecurity policy, threat assessment, packet/host controls, incident response | Threat model drafted; no operational policy acceptance |

Do not weaken source-pinned Mesh CI or treat endpoint-name similarity as source parity. Independently review and update a replacement VPN owner contract against an immutable GitHub commit when actual tests and privileges exist. Canonical brand values: https://github.com/GoreeCloud/gc-ui/blob/main/tokens/gc.tokens.json.
