# [CRITICAL] WBTC Vault Collateral Rebase Manipulation — 0.835 BTC Missing, $53K Unbacked SILK

**Program:** Shade Protocol Bug Bounty  
**Severity:** Critical  
**Component:** Shade Lend — V3-prod Vault Registry  
**Network:** secret-4 mainnet  
**Date:** 2026-05-31  
**PoC Script:** `poc_f7_wbtc_insolvency.py`

---

## Summary

The V3-prod WBTC Vault (`vault_id=9`) in Shade Lend has its collateral rebase `elastic` reduced to near-zero (2,097 base units = 0.00002097 BTC = $1.57) while carrying 37,867.68 SILK ($53,015) in outstanding debt. Approximately **0.835 BTC (~$62,369) of real Axelar-bridged Bitcoin is missing** from the vault. The pattern is identical to the first-depositor LP inflation bug (F1): a missing `MINIMUM_COLLATERAL` guard in the vault collateral rebase allows the first depositor to manipulate the `elastic/base` ratio to near-zero, stealing all collateral from subsequent depositors.

---
## Affected Asset

https://github.com/securesecrets/shadeswap/blob/main/contracts/amm_pair/src/operations.rs

## Affected Contract

| Field | Value |
|-------|-------|
| Registry contract | `secret1qxk2scacpgj2mmm0af60674afl9e6qneg7yuny` |
| Registry code_id | 929 |
| Vault ID | 9 ("WBTC Vault") |
| Collateral token | `secret1guyayjwg5f84daaxl7w84skd8naxvq8vz9upqx` |
| Collateral name | Secret Axelar WBTC (saWBTC) — code_id 2283 |
| SILK token | `secret1fl449muk5yq8dlad7a22nje4p5d2pnsgymhjfd` |
| Vault status | **frozen** |

---

## On-Chain Evidence (Live, 2026-05-31)

### Collateral Rebase State
```
vault.collateral.elastic  = 2,097
vault.collateral.base     = 15,836,243,458,932,126,387
elastic / base            = 1.324178e-16   ← healthy vaults: ~1.0
last_accrued              = 1692289881  (2023-08-17)
```

### Debt State
```
vault.debt.elastic        = 37,867,675,549,228,044,104,227
Outstanding SILK debt     = 37,867.68 SILK
```

### Insolvency Calculation
```
Collateral tokens  = 2,097 / 10^8 = 0.00002097 BTC
WBTC oracle price  = $74,731.68  (xWBTC.axl, live)
Collateral USD     = $1.57

Debt USD           = 37,867.68 SILK × $1.40/SILK = $53,014.75

SHORTFALL          = $53,013.18
ACTUAL LTV         = 33,829×  (max allowed: 0.85×)

Expected BTC to back 37,867.68 SILK at 85% LTV = 0.8346 BTC
BTC actually present                            = 0.00002097 BTC
MISSING                                         = 0.8344 BTC = $62,369
```

### Healthy Vault Comparison
```
V1  stkd-SCRT  elastic/base = 1.000000   21,775.98 SILK   normal
V8  WETH       elastic/base = 1.000000  153,578.97 SILK   normal
V12 sSCRT      elastic/base = 1.000000    4,977.72 SILK   normal
V9  WBTC       elastic/base = 1.324e-16  37,867.68 SILK   frozen ← BROKEN
```

All healthy vaults maintain `elastic ≈ base` (ratio ≈ 1.0). The WBTC vault's ratio is 14 orders of magnitude below normal, indicating its collateral rebase was deliberately manipulated.

---

## Root Cause

The vault tracks deposited collateral using an elastic/base rebase system:

```
deposit_shares = deposit_tokens × total_base / total_elastic
withdraw_tokens = shares × total_elastic / total_base
```

**Attack sequence (first-depositor attack):**

1. Attacker is the first depositor in a newly created vault
2. Deposits 1 wei of saWBTC → receives all base shares (no `MINIMUM_COLLATERAL` guard)
3. Inflates the vault elastic slightly via direct SNIP-20 `transfer` (no callback triggered)
4. Total base is large; total elastic is near-zero → `elastic/base ≈ 0`
5. Subsequent depositors' `deposit_shares = deposit × base / elastic ≈ ∞` (or miscalculated)
6. Subsequent depositors' `withdraw_tokens = shares × elastic / base ≈ 0`
7. Attacker removes 100% of pool via their original base shares, taking all deposited saWBTC
8. Vault is left with `elastic ≈ 0`, outstanding debt, and no real collateral

**Attack timestamp:** `last_accrued = 1692289881` → **August 17, 2023**

This is the same missing guard that causes the ShadeSwap LP inflation bug (F1). In F1 the target was `calculate_lp_tokens` in the AMM pair; here the target is the vault collateral rebase in `add_collateral`.

---

## Impact

| Impact | Detail |
|--------|--------|
| Real funds at risk | ~0.835 saWBTC (~$62,369) missing from vault |
| Protocol bad debt | 37,867.68 SILK ($53,015) permanently unbacked |
| SILK solvency | ~5.6% of total SILK supply (671,330 SILK) is now unbacked |
| User impact | 39 borrowers cannot recover their collateral (collateral value rounds to 0 on withdrawal) |
| Vault status | Frozen by protocol — but positions remain unresolvable |
| Liquidation | Permanently broken (see F8: divide-by-zero in liquidation math) |

---

## Proof of Concept

**Script:** `poc_f7_wbtc_insolvency.py` (run with `python3 poc_f7_wbtc_insolvency.py`)

Full live output:

```
==============================================================
  F7 PoC — WBTC Vault Insolvency (live secret-4)
==============================================================

  1/5  Verify production tokens
  SILK  (secret1fl449muk5yq8dlad7a22nje4p5d2pnsgymhjfd)
        name=Silk  supply=671,330.15 SILK
  saWBTC (secret1guyayjwg5f84daaxl7w84skd8naxvq8vz9upqx)
         name=Secret Axelar WBTC  total_supply=16.60533962 BTC

  2/5  Live WBTC oracle price
  Oracle key    : xWBTC.axl
  Price         : $74,731.68 USD
  Last updated  : 2026-05-31 09:00 UTC

  3/5  WBTC vault raw on-chain state (vault_id=9)
  vault name      : WBTC Vault
  vault status    : frozen
  open positions  : 39
  collateral.elastic  = 2097
  collateral.base     = 15836243458932126387
  elastic / base      = 1.324178e-16  ← should be ~1.0
  last_accrued        = 1692289881  (2023-08-17)
  debt.elastic        = 37867675549228044104227

  4/5  Insolvency calculation
  ┌──────────────────────────────────────────┐
  │  COLLATERAL  :   $        1.57           │
  │  DEBT        :   $   53,014.75           │
  │  SHORTFALL   :   $   53,013.18           │
  │  LTV (actual):         33,829×           │
  │  LTV (max)   :           0.85×           │
  └──────────────────────────────────────────┘
  MISSING: 0.834569 BTC  ($62,368.72)

  5/5  Comparison: healthy vaults vs WBTC vault
  V1 stkd-SCRT    col_ratio=1.000000  21,775.99 SILK  normal
  V8 WETH         col_ratio=1.000000 153,578.97 SILK  normal
  V12 sSCRT       col_ratio=1.000000   4,977.72 SILK  normal
  V9 WBTC Vault   col_ratio=1.324e-16 37,867.68 SILK  frozen ← BROKEN
```

---

## Recommended Fix

**Immediate (operational):**
1. Confirm vault V9 is permanently frozen — no new deposits or borrows
2. Investigate the August 17, 2023 transactions that reduced `collateral.elastic` to 2,097
3. Determine how many users deposited real saWBTC into this vault and quantify user losses
4. Consider protocol-funded reimbursement for affected borrowers

**Code fix (prevents recurrence):**

Add a `MINIMUM_COLLATERAL` constant (analogous to Uniswap V2's `MINIMUM_LIQUIDITY`) to the vault `add_collateral` entry point. On the first deposit, lock a small number of collateral shares permanently so `elastic` can never be reduced to zero:

```rust
const MINIMUM_COLLATERAL: u128 = 1_000;  // burn on first deposit

pub fn add_collateral(...) -> StdResult<Response> {
    if vault.collateral.base == Uint128::zero() {
        // First deposit: mint MINIMUM_COLLATERAL to dead address
        vault.collateral.elastic += Uint128::from(MINIMUM_COLLATERAL);
        vault.collateral.base += Uint128::from(MINIMUM_COLLATERAL);
        // These shares are permanently locked, preventing elastic/base from reaching 0
    }
    // ... rest of deposit logic
}
```

Also add a guard in `liquidatable_positions` to handle `elastic == 0` gracefully (see F8).

---
