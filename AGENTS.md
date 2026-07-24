# AGENTS.md — Cloud Honeypot Client

Before changing API / agent behavior, follow **honeypot-contract** (SoT):

1. `../honeypot-contract/VERSION` + `INDEX.md` + `FLEET.md`
2. Relevant `api/*`, `agent/*`, or `cloud/*`
3. Contract first on behavior changes; then code
4. Local `docs/api/*` are stubs — edit the contract only

Cursor rule: `.cursor/rules/honeypot-contract.mdc`  
Pointer: [`contract/README.md`](contract/README.md)  
Remote: https://github.com/cevdetaksac/honeypot-contract (pin = `VERSION` file, currently **1.4.25**)
