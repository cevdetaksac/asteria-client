# Contract pointer

**CONTRACT_ROOT** (this workspace):

```text
../asteria-contract
```

Remote: https://github.com/cevdetaksac/asteria-contract · **VERSION ≥ 1.4.31** · production floor client ≥ **4.9.0** ([`FLEET.md`](https://github.com/cevdetaksac/asteria-contract/blob/main/FLEET.md))

Legacy clone URL redirects: `honeypot-contract` → `asteria-contract`.

Local `docs/api/*` are stubs — source of truth is **only** asteria-contract.

## Agent / Cursor — read order

1. `CONTRACT_ROOT/VERSION` + `INDEX.md` + `FLEET.md`
2. Relevant `api/*`, `agent/*`, or `cloud/*`
3. Do not write code that contradicts the contract; note Open questions when unsure
4. API change → contract MD + CHANGELOG + VERSION → then client/cloud code
5. Cloud operators: `git pull` + `publish_contract.sh`

Cursor rule: `.cursor/rules/honeypot-contract.mdc`
