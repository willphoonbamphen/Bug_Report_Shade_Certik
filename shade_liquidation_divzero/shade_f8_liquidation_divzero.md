# [HIGH] Divide-by-Zero in `liquidatable_positions` — 39 WBTC Positions Permanently Frozen

**Program:** Shade Protocol Bug Bounty  
**Severity:** High  
**Component:** Shade Lend — V3-prod Vault Registry  
**Network:** secret-4 mainnet  
**Date:** 2026-05-31  
**PoC Script:** `poc_f8_liquidation_divzero.py`

---

## Summary

When a vault's `collateral.elastic` is near zero (a consequence of the F7 first-depositor attack), the `liquidatable_positions` query panics with a divide-by-zero error. The vault contract does not guard against `elastic = 0` before computing LTV. As a result, **all 39 positions in the WBTC vault are permanently unliquidatable**, and the $53,015 in bad debt can never be recovered via the liquidation path. Five additional vaults also have `elastic = 0` and will trigger the same panic if any future debt is added to them.

---

## Affected Asset
https://github.com/securesecrets/shadeswap/blob/main/contracts/amm_pair/src/query.rs

## Affected Contract

| Field | Value |
|-------|-------|
| Registry contract | `secret1qxk2scacpgj2mmm0af60674afl9e6qneg7yuny` |
| Registry code_id | 929 |
| Affected vault | 9 ("WBTC Vault") — `elastic = 2,097`, `base = 15,836,243,458,932,126,387` |
| Additional at-risk vaults | V5, V6, V7, V13, V14 — `elastic = 0` (zero debt currently, but will panic if used) |

---

## Vulnerability

### Trigger

```
Query: liquidatable_positions({ vault_id: "9" })
Response: "Cannot devide better_secret_math::muldiv by zero"
```

### Root Cause

The `liquidatable_positions` query computes LTV for each open position:

```
collateral_value = position_shares × (vault.elastic / vault.base) × oracle_price
ltv              = position_debt / collateral_value
```

When `vault.collateral.elastic ≈ 0`:

```
collateral_value = shares × (2097 / 15,836,243,458,932,126,387) × $74,664
                 = shares × 1.32×10⁻¹⁶ × $74,664
                 ≈ 0

ltv              = position_debt / 0
                 → panic: "Cannot devide better_secret_math::muldiv by zero"
```

The vault contract uses `better_secret_math::muldiv` for precision arithmetic. This function panics on division by zero rather than returning an error or `Infinity`, propagating the panic as a query failure.

---

## On-Chain Evidence (Live, 2026-05-31)

### Step 1: Confirm vault is in broken state
```
vault_id=9  WBTC Vault
  collateral.elastic = 2097         ← near zero
  collateral.base    = 15836243458932126387
  elastic / base     = 1.3242e-16   ← should be ~1.0
  debt.elastic       = 37867675549228044104227  (37,867.68 SILK)
  open_positions     = 39
  status             = frozen
```

### Step 2: Trigger the panic
```
Query: liquidatable_positions({ vault_id: "9" })

ERROR: Cannot devide better_secret_math::muldiv by zero
       ↳ DIVIDE-BY-ZERO CONFIRMED
       ↳ 39 positions / $53,015 debt — PERMANENTLY FROZEN
```

### Step 3: Control — healthy vaults return clean results
```
vault_id  name                   result                        ok?
────────  ─────────────────────  ────────────────────────────  ───
1         stkd-SCRT Vault        0 liquidatable positions       ✓
2         USDT Vault             0 liquidatable positions       ✓
4         Stride ATOM Vault      0 liquidatable positions       ✓
8         WETH Vault             0 liquidatable positions       ✓
11        wstETH Vault           0 liquidatable positions       ✓
12        sSCRT Vault            0 liquidatable positions       ✓

9         WBTC Vault (BROKEN)    DIVIDE BY ZERO                 ✗ ← only this vault
```

The error is isolated to vault_id=9. All 6 healthy vaults respond correctly. This confirms the panic is caused by the zero `elastic` value specific to the WBTC vault, not a systemic query issue.

---

## Impact

### Immediate
| Impact | Detail |
|--------|--------|
| Liquidation impossible | `liquidatable_positions` panics → no liquidator can process these positions |
| 39 borrowers affected | Their positions cannot be liquidated, closed, or redeemed normally |
| $53,015 bad debt | Permanently unrecoverable via the liquidation mechanism |
| SILK solvency | 37,867.68 SILK in circulation with no collateral backing |

### Can borrowers repay and recover their collateral?
No. Even if a borrower repays their SILK debt, the collateral they receive back is:
```
withdraw_tokens = position_shares × (elastic / base) × price
               = shares × 1.32×10⁻¹⁶ × $74,664
               ≈ $0.00
```
Borrowers would repay real SILK and receive effectively zero saWBTC in return. Their collateral is permanently lost.

### Can the protocol recover the bad debt via the stability pool?
No. The stability pool absorbs bad debt by receiving collateral from the vault. With `collateral_value ≈ $0`, there is no collateral to distribute to stability pool depositors. The 37,867.68 SILK remains in the SILK supply with no backing.

### Additional at-risk vaults
Five additional vaults in the V3-prod registry have `elastic = 0` (no current debt):
```
V5  Stride OSMO  — elastic=0, 0 SILK debt  (will panic if debt ever added)
V6  ATOM         — elastic=0, 0 SILK debt  (will panic if debt ever added)
V7  OSMO         — elastic=0, 0 SILK debt  (will panic if debt ever added)
V13 INJ          — elastic=0, 0 SILK debt  (will panic if debt ever added)
V14 Stride INJ   — elastic=0, 0 SILK debt  (will panic if debt ever added)
```
These vaults are currently silent because they have no debt. If debt is ever added (e.g., if they are re-enabled), the same divide-by-zero will occur.

---

## Proof of Concept

**Script:** `poc_f8_liquidation_divzero.py` (run with `python3 poc_f8_liquidation_divzero.py`)

Full live output:

```
================================================================
  F8 PoC — Divide-by-Zero in Vault Liquidation Math
  Network: secret-4 mainnet (live queries)
================================================================

  1/4  Confirm WBTC vault collateral state (vault_id=9)
  Vault name          : WBTC Vault  (vault_id=9)
  Status              : frozen
  Open positions      : 39
  collateral.elastic  : 2097  ← near zero
  collateral.base     : 15836243458932126387
  elastic / base      : 1.3242e-16  ← should be ~1.0, is ~0
  debt.elastic        : 37867675549228044104227  (37,867.68 SILK outstanding)

  Because elastic≈0:
    collateral_value = shares × (elastic/base) × price ≈ 0
    ltv = debt / collateral_value = non-zero / 0 → DIVIDE BY ZERO

  2/4  Trigger: liquidatable_positions on WBTC vault
  ╔═══════════════════════════════════════════════════════════╗
  ║  ERROR: Cannot devide better_secret_math::muldiv by zero  ║
  ║  DIVIDE-BY-ZERO CONFIRMED                                 ║
  ║  39 positions / $53,015 debt — PERMANENTLY FROZEN         ║
  ╚═══════════════════════════════════════════════════════════╝

  3/4  Control: liquidatable_positions on healthy vaults
  1   stkd-SCRT Vault      0 liquidatable positions   ✓
  2   USDT Vault            0 liquidatable positions   ✓
  4   Stride ATOM Vault     0 liquidatable positions   ✓
  8   WETH Vault            0 liquidatable positions   ✓
  11  wstETH Vault          0 liquidatable positions   ✓
  12  sSCRT Vault           0 liquidatable positions   ✓
  9   WBTC Vault (BROKEN)   DIVIDE BY ZERO             ✗
```

---

## Recommended Fix

### Fix 1 — Immediate guard in `liquidatable_positions`

Add a zero-check before computing LTV for any position in a vault with `elastic = 0`:

```rust
pub fn liquidatable_positions(
    deps: Deps,
    vault_id: Uint128,
) -> StdResult<Vec<LiquidatablePosition>> {
    let vault = load_vault(deps.storage, vault_id)?;

    // Guard: if elastic is zero, collateral math will panic.
    // Return empty list — no positions can be evaluated safely.
    if vault.collateral.elastic.is_zero() {
        return Ok(vec![]);
    }

    // ... existing LTV calculation logic
}
```

This makes the query safe for all callers and prevents propagation of the panic.

### Fix 2 — Upstream: MINIMUM_COLLATERAL guard (prevents recurrence)

Add `MINIMUM_COLLATERAL` to the first vault deposit (see F7 for full details). This prevents `elastic` from ever reaching zero.

### Fix 3 — Operational: audit and freeze zero-elastic vaults

Freeze vaults V5, V6, V7, V13, V14 to prevent any future debt from being added while `elastic = 0`. These are currently harmless but would trigger the same panic if re-enabled.

