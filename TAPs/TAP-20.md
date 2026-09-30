---
tap: TBD
title: TapeUP Native Assets on TapeOut(TAP-20)
description: A container-native asset and settlement standard that enables TapeOut circuits to issue and transfer fungible digital assets.
author: TBD (@tapup)
discussions-to: https://github.com/TapeOutProtocol/TAPs/issues/TBD
status: Draft
type: Standards
created: 2026-09-30
updated: 2026-09-30
version: 0.1.0
requires: TAP-01, TAP-10
license: CC0-1.0
---

# TAP-draft: TapeUP Native Assets on TapeOut(TAP-20)

> **Status: Draft / pre-Draft.** Not an editor-assigned TAP. This proposal **requests** core number **TAP-20** under TAP-01 §6.1 if the community treats inscription-style assets as a core standard. Until assignment, normative protocol id is **`tape-20/v1`**.

## Summary

Tape-20 defines fungible tokens whose **authority is a sequence of protocol operations** written through TapeOut (circuit-bound deploy, then mint/transfer logs). Balances are **not** stored in a classic ERC-20 mapping by default; any full node or indexer that replays the rules on the same chain data MUST obtain the same balances.

## Abstract

TapeOut already has stronger write primitives: circuit identity, containers, SiteRegistry files, and (via TAP-10) the DeWEB Hub. TAP-20 uses those primitives as the **inscription layer**:

1. **deploy** — circuit holder publishes an immutable deploy record bound to `(circuits, circuitId)`;
2. **mint** / **transfer** — append-only operations in a **TokenLog** (preferred) and/or constrained SiteRegistry artifacts;
3. **discover** — TAP-10 name resolution + deploy manifest + replay from genesis of that ticker.

Optional **wrap** to ERC-20 is an Application profile, not required for the token to exist under this TAP.

Goal: extend TapeOut into a base network that can **issue and transfer digital assets** under protocol rules,keeping verification aligned with TAP-10’s multi-node agreement model.

## Motivation

- Path A (container-bound ERC-20) optimises DEX/wallets; it does not create a **metaprotocol** state machine shared by all indexers.
- Ecosystem narratives and “native asset issuance” benefit from a **single replay rule** over TapeOut writes.
- SiteRegistry + events give content-addressed, hash-verified payloads (closer to inscriptions than bare `eth_call` storage of third-party ERC-20s).
- Circuit identity gives a clearer **issuer** than a bare EOA deploy on Ethereum.

## Specification

Key words MUST / MUST NOT / SHOULD / MAY per RFC 2119 / 8174 when capitalised.

### 1. Terms

| Term | Meaning |
|------|---------|
| Ticker | Case-sensitive ASCII string `tick` identifying a token within one deploy scope |
| Deploy scope | `(chainId, circuits, circuitId)` — one circuit is one issuer realm |
| Deploy record | The unique successful `deploy` for a `(scope, tick)` |
| Operation | A signed protocol action: `deploy` \| `mint` \| `transfer` \| `burn` (optional) |
| TokenLog | Canonical append-only contract emitting operations (normative for v1 balances) |
| Balance | Result of deterministic replay of all valid ops for a tick after a block |
| Holder | `ownerOf(circuitId)` on `circuits` at the block of the op |
| Actor | Address authorized to submit an op (holder, or rules in deploy) |
| Recipient | Container address or EOA allowed by §6 |
| Indexer | Any implementation that replays §8; not a privileged oracle |

### 2. Design principles (TAP-20)

Creation commits: `name`, `symbol`, `decimals`, `supplyCap`, `initialSupply`, `initialRecipient`, `mintPolicy`, `burnPolicy`, `adminPolicy` and `policyCommitment`. The combination of container and asset index MUST be used at most once. Creation MUST atomically initialize total supply and the initial recipient's balance. `initialSupply` MUST NOT exceed `supplyCap`.

Two initial policies are proposed:

- **Fixed supply:** the initial supply is final; no actor, including a subsequent circuit NFT owner, may mint additional units.
- **Rule-based supply:** future issuance is permitted only through the committed mint rule, with a fixed cap and a discoverable authorization path.

The runtime MUST expose which policy applies and whether any part of it can be upgraded or paused. An issuer's description cannot substitute for enforceable rules.

For each asset the runtime maintains `totalSupply`, `balance[holder]` and `nonce[holder]`. Units are non-negative integers in the asset's smallest denomination. Every committed transition MUST preserve the following invariants:

```text
0 <= totalSupply <= supplyCap
sum(balance[all holders]) == totalSupply
transfer: totalSupply_after == totalSupply_before
mint:     supply and recipient balance increase by the same amount
burn:     supply and holder balance decrease by the same amount
```

The runtime MUST provide a public method to determine canonical supply, balance and nonce at a specified settled block, either by direct state read or by a fully specified state commitment and proof. Events and indexer records MAY accelerate discovery but MUST NOT replace verifiable canonical state.
An accepted operation MUST commit every related state change atomically. A transfer cannot debit one account without crediting the other, and failed execution cannot consume a nonce or change a balance. The home chain's transaction order determines conflicting transfers.

 User-directed transfer

A holder authorizes a transfer by signing a typed operation bound to the home chain, runtime, asset ID, sender, recipient, amount, nonce and expiry. A relayer MAY submit the signed operation and pay gas but gains no authority to change its terms. The runtime MUST verify authorization, reject an expired or replayed operation, check sufficient balance, then debit, credit and increment the nonce in one committed transition.
The final signing schema, selectors, event fields and error codes require an implementation and exact test vectors. No implementation should claim interoperability from the semantic description alone.


### 3. Writing surfaces

#### 3.1 TokenLog (normative for balance replay in v1)

A per-chain **TokenLog** contract (UUPS allowed only until sealed; Deployments list addresses).

```text
function submit(
  address circuits,
  uint256 circuitId,
  bytes32 payloadHash,
  bytes calldata payload
) external returns (uint256 index);
```

Rules:

1. `payload` MUST be non-empty and MUST NOT exceed **4_096** bytes;
2. `payloadHash` MUST equal `keccak256(payload)`;
3. Authorization MUST pass §7 for the decoded `op`;
4. TokenLog MUST NOT parse economics beyond authorization checks it documents; full validation is in the replay rules (§8);
5. Storage MUST keep an append-only sequence per chain: index `0..n-1` with `(circuits, circuitId, from, block, timestamp, payloadHash)` and emit the full payload in the event (or store payload on-chain if gas policy allows—**v1 MUST emit payload in the event** so one receipt carries the inscription).

#### 3.2 Event: OpSubmitted

```text
event OpSubmitted(
  uint256 indexed index,
  address indexed circuits,
  uint256 indexed circuitId,
  address from,
  bytes32 payloadHash,
  bytes payload
);
```

Canonical signature for topic0:

```text
OpSubmitted(uint256,address,uint256,address,bytes32,bytes)
```

(topic0 hex MUST be published in Test Cases when ABI is frozen.)

Indexed fields: `index`, `circuits`, `circuitId`.  
`from` = `msg.sender`.  
Clients verify `keccak256(payload) == payloadHash`.

#### 3.3 SiteRegistry deploy manifest (normative discovery; optional mirror of deploy)

After a successful deploy op is accepted in replay, the issuer SHOULD publish:

```text
SiteRegistry path: .well-known/tape-20.json
```

This file is for **discovery and UX**, not a second source of truth for balances. If it disagrees with the deploy op in TokenLog, **TokenLog wins**.

### 4. Payload encoding

#### 4.1 Envelope

All ops are a single JSON object, UTF-8, no BOM, max 4096 bytes as submitted:

```json
{
  "p": "tape-20/v1",
  "op": "deploy",
  "...": "..."
}
```

| Field | Required | Rules |
|-------|----------|--------|
| `p` | yes | Exactly `tape-20/v1` |
| `op` | yes | One of §5 |

Unknown fields MUST be ignored in replay (forward compatible). Unknown `op` values MUST make the op **invalid** (skipped, not fatal to the log).

#### 4.2 Op codes

| op | Code (ASCII) | Role |
|----|--------------|------|
| Deploy | `deploy` | Create ticker in a scope |
| Mint | `mint` | Increase supply to an account under rules |
| Transfer | `transfer` | Move balance between accounts |
| Burn | `burn` | Optional destroy balance |

No other ops in v1.

### 5. Operation schemas

Amounts are **decimal integer strings** in **display units** scaled by `10^dec` is NOT used: amounts are in **base units** (integer string of indivisible units), same spirit as many ordinal protocols. `dec` only affects display wallets.

#### 5.1 deploy

```json
{
  "p": "tape-20/v1",
  "op": "deploy",
  "tick": "EX",
  "max": "21000000000000000000000000",
  "lim": "1000000000000000000000",
  "dec": "18",
  "to": "container"
}
```

| Field | Required | Constraint |
|-------|----------|------------|
| `tick` | yes | `^[A-Z0-9]{2,8}$` (uppercase); unique per `(chainId, circuits, circuitId)` |
| `max` | yes | Positive decimal integer string; total mintable base units |
| `lim` | yes | Positive decimal integer string; max base units per successful `mint` op |
| `dec` | yes | Integer 0–18 inclusive (JSON number) |
| `to` | yes | `"container"` \| `"eoa"` \| `"either"` — who may hold balances |

Rules:

1. Only the **Holder** of `(circuits, circuitId)` at submit time may submit `deploy` (msg.sender MUST be Holder);
2. Second `deploy` for same `(scope, tick)` is **invalid**;
3. `lim` MUST be ≤ `max`.

#### 5.2 mint

```json
{
  "p": "tape-20/v1",
  "op": "mint",
  "tick": "EX",
  "amt": "1000000000000000000",
  "rcv": "0xRecipient…"
}
```

| Field | Required | Constraint |
|-------|----------|------------|
| `tick` | yes | Existing deploy in this scope |
| `amt` | yes | Positive integer string; ≤ deploy.`lim`; remaining supply MUST allow it |
| `rcv` | yes | Recipient per §6 |

Authorization (v1): **Holder only** (same circuit that deployed).  
(Future profiles MAY add open mint; not in v1.)

#### 5.3 transfer

```json
{
  "p": "tape-20/v1",
  "op": "transfer",
  "tick": "EX",
  "amt": "1000",
  "rcv": "0x…"
}
```

Authorization: `msg.sender` MUST control the **source balance** under §6 (EOA = sender; container = Holder of that container’s circuit, or the container account itself if it submits via ERC-6551 execute—see §7).

#### 5.4 burn (optional)

```json
{
  "p": "tape-20/v1",
  "op": "burn",
  "tick": "EX",
  "amt": "1000"
}
```

Burns from sender’s balance; decreases circulating supply; does not restore mint budget unless deploy profile says so (**v1: burn does NOT restore mint budget**).

### 6. Accounts and recipients

1. If deploy.`to` is `container`, `rcv` MUST be a TapeOut container on the same chain (derive via registry/opener; MUST verify `accountOf` round-trip as in TAP-10).
2. If `eoa`, `rcv` MUST be an address with no code **or** EIP-7702 designation as in TAP-10 “plain account”.
3. If `either`, both forms allowed.
4. Self-transfers are valid but NO-OP for balances if `amt` > 0 still consumes the op as valid (balance unchanged net).
5. Circuit NFT addresses as `rcv` MUST be rejected (prevent lock of identity NFTs into ambiguous custody).

### 7. Authorization at submit time (TokenLog)

Before accepting `submit` (chain-level, cheap checks):

1. Decode JSON; require `p` and `op`;
2. Resolve Holder = `ownerOf(circuitId)` on `circuits`;
3. For `deploy` / `mint`: `msg.sender == Holder`;
4. For `transfer` / `burn`:
   - if balance key is EOA: `msg.sender == from_account`;
   - if balance key is container: `msg.sender == Holder` of that container’s circuit **or** `msg.sender == container` (6551 execution);
5. TokenLog MAY skip full numeric replay (gas); **invalid ops may still be logged**. Replay (§8) MUST mark them invalid and ignore their economic effect.

### 8. Deterministic replay (balance truth)

State per `(chainId, circuits, circuitId, tick)`:

```text
deployed: bool
max, lim, dec, to_mode
minted: integer
bal: map(account => integer)
```

Process all `OpSubmitted` for that `circuits` in increasing `index` global order (TokenLog is total-ordered on each chain). For each entry:

1. Verify `keccak256(payload) == payloadHash`; else skip;
2. Parse JSON; if fail or `p != tape-20/v1`, skip;
3. Apply op-specific validation; on failure, **skip** (do not halt the chain of later ops);
4. On success, update `minted` / `bal`.

**mint validity:** deploy exists; sender was Holder at that block (use `ownerOf` at `block` if archive available; otherwise v1 MAY use `from` field only as submitter identity—**normative v1: use event `from` and require it equalled Holder rule at submit**, already enforced by TokenLog for mint); `amt ≤ lim`; `minted + amt ≤ max`; `rcv` legal; then `bal[rcv] += amt`, `minted += amt`.

**transfer validity:** `bal[from] >= amt`; `rcv` legal; then subtract/add.

Checkpoint: balance of `A` at block `B` is the map after applying all ops with `blockNumber ≤ B` (or finalised tag per TAP-10).

Clients verifying a claimed balance MUST either:

- replay from genesis with multi-node agreement on the log pages, or  
- accept a proof format defined in a future TAP (not v1).

### 9. Discovery

#### 9.1 Flow

```text
User: 4246.0.tape + tick EX
  → TAP-10 resolve → (circuits, circuitId, container)
  → Read TokenLog ops for circuits (filter circuitId)
  → Find valid deploy for tick EX
  → Optional read SiteRegistry `.well-known/tape-20.json`
  → If manifest present: MUST match deploy fields or show warning
  → Replay → balances
```

#### 9.2 Manifest schema (discovery only)

Path: `.well-known/tape-20.json`

| Field | Required | Notes |
|-------|----------|--------|
| `tape20` | yes | `"1.0"` |
| `p` | yes | `tape-20/v1` |
| `tick` | yes | Uppercase ticker |
| `chainId` | yes | |
| `circuits` | yes | |
| `circuitId` | yes | string decimal |
| `container` | yes | Issuer container |
| `max` / `lim` / `dec` / `to` | yes | MUST match deploy op |
| `tokenLog` | yes | TokenLog address |
| `deployIndex` | yes | TokenLog index of deploy op |
| `deployTx` | no | Hint |
| `logoPath` | no | |
| `wrap` | no | ERC-20 wrap address if Application profile used |

### 10. Lifecycle diagram (TAP-20)

```text
┌──────────────────────┐
│ Holder of circuit    │
│ (circuits, circuitId)│
└──────────┬───────────┘
           │ op: deploy
           │ TokenLog.submit(payload deploy)
           │ event OpSubmitted(index=i0, …)
           ▼
┌──────────────────────┐
│ Deploy record fixed  │
│ tick, max, lim, dec  │
│ scope = this circuit │
└──────────┬───────────┘
           │
           │ op: publish_manifest (optional)
           │ SiteRegistry putFile tape-20.json
           ▼
┌──────────────────────┐
│ Discoverable ticker  │
└──────────┬───────────┘
           │
     ┌─────┴─────┐
     │ op: mint  │  Holder submit; rcv gets bal
     └─────┬─────┘
           │
           ▼
┌──────────────────────┐
│ Replay state: bal[]  │
└──────────┬───────────┘
           │
     ┌─────┴─────┐
     │ op: xfer  │  Owner of bal submits; rcv updated
     └─────┬─────┘
           │
           ▼
┌──────────────────────┐
│ Client discover:     │
│ TAP-10 resolve +     │
│ log replay + optional│
│ manifest cross-check │
└──────────────────────┘
```

### 11. Optional wrap profile (non-normative for balances)

An Application MAY deploy an ERC-20 that **custodies** claims only after verifying replay proofs or trusted indexer sets. Under this TAP, **unwrapped Tape-20 balance is the replay result**. Wallets MUST NOT present wrap balance as the sole Tape-20 truth.

### 12. Relation to protocol assets

Does not replace transistors, circuits, or BEM. Tape-20 assets are **application-layer fungible units** under circuit scopes. Mint of Tape-20 MUST NOT burn transistors unless a future op profile defines it.

### 13. Security considerations

1. **Indexer disagreement** — mitigate with open replay + multi-node log reads (TAP-10 style).
2. **Invalid ops in log** — MUST be skippable; economic validity is replay-side.
3. **Holder capture** — deploy and mint are holder-gated in v1.
4. **Payload size** — 4_096 limit reduces gas/DoS.
5. **Reorgs** — use TAP-10 finality tags when displaying balances.
6. **Fake manifests** — TokenLog deploy is authority.
7. **Unsealed TokenLog** — same Candidate/Final sealing policy as TAP-01 / TAP-10.

### 14. Rationale

- Path B maximises “TapeOut as issuance base network” in the **metaprotocol** sense.
- TokenLog total order avoids ambiguous multi-file inscription races.
- Discovery reuses TAP-10 rather than DNS.

### 15. Test cases (outline)

1. Two deploys same tick → second invalid.
2. Mint above lim / max → invalid.
3. Transfer without balance → invalid.
4. Manifest tick mismatch → warn / non-verified discovery.
5. payloadHash mismatch → skip.
6. Multi-node log page disagreement → refuse balance display.

### 16. Reference implementation

TBD: TokenLog.sol, replay library in JS/Rust, vectors under `assets/tap-draft-tape20/`.

### 17. Deployments

TBD per chain: TokenLog proxy, sealed status, opener, SiteRegistry.

### Copyright

Copyright and related rights waived via CC0-1.0.
```

---

## TAP-20 at a glance

| Item | Choice |
|------|--------|
| Balance truth | **Deterministic replay** of `OpSubmitted` |
| Write path | **TokenLog.submit** + event payload (inscription analogue) |
| Issuer | **Circuit holder** for `deploy` / `mint` (v1) |
| Discovery | TAP-10 resolve + optional `.well-known/tape-20.json` |
| ERC-20 | **Not required**; optional wrap only |
| Op set | `deploy` · `mint` · `transfer` · `burn` |

---

## Next steps

1. Open a TAP-01 **Idea** issue; attach this file as `TAP-draft-tape-inscription-token.md`.  
2. Implement minimal `TokenLog` + JS replay + vectors.  
3. Ask editors for number **20** vs another id (and keep `tape-20/v1` until Final).  
4. Decide later whether Path A CBT is a **separate** TAP or a “wrap profile” of this one.
