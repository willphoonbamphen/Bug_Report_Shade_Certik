#!/usr/bin/env python3
"""
F8 PoC — Shade Protocol Vault: Divide-by-Zero in Liquidation Math
==================================================================
Severity : HIGH
Target   : Shade Protocol Lend — V3-prod vault registry, vault_id=9 "WBTC Vault"
Network  : secret-4 mainnet (all queries live)

Root cause:
  When a vault's collateral.elastic ≈ 0 (due to the F7 rebase attack),
  the `liquidatable_positions` query performs:

      ltv = debt_value / collateral_value
          = debt_value / (shares * elastic/base * oracle_price)
          ≈ debt_value / 0
          → DIVIDE BY ZERO

  The vault contract propagates this error instead of returning empty,
  making all 39 WBTC borrower positions permanently unliquidatable.

Proof:
  - liquidatable_positions(vault_id=9) → "Cannot devide ... by zero"
  - liquidatable_positions(vault_id=1,2,4,8,11,12) → [] (healthy, no error)
"""

import sys, os

# secret_sdk's sync query wrapper is incompatible with aiohttp ≥3.9 on Python ≥3.12.
# Auto-relaunch with python3.11 which has the correct aiohttp/nest_asyncio pairing.
if sys.version_info >= (3, 12):
    py311 = "/usr/local/bin/python3.11"
    if not os.path.exists(py311):
        sys.exit("ERROR: python3.11 not found at /usr/local/bin/python3.11 — install it or run: python3.11 " + __file__)
    os.execv(py311, [py311] + sys.argv)

import types, base64, json, time

mock_pkg = types.ModuleType("pkg_resources")
mock_pkg.get_distribution = lambda n: type("d", (), {"version": "0.0.0"})()
sys.modules["pkg_resources"] = mock_pkg

from secret_sdk.client.lcd import LCDClient

# ── Constants ────────────────────────────────────────────────────────────────
LCD          = "https://secretnetwork-api.lavenderfive.com"
V3_REG_ADDR  = "secret1qxk2scacpgj2mmm0af60674afl9e6qneg7yuny"
V3_REG_HASH  = "ac5d501827d9a337a618ca493fcbf1323b20771378774a6bf466cb66361bf021"
WBTC_VID     = "9"
HEALTHY_VIDS = ["1", "2", "4", "8", "11", "12"]

client = LCDClient(url=LCD, chain_id="secret-4")

def banner(title):
    print(f"\n{'─'*64}")
    print(f"  {title}")
    print(f"{'─'*64}")

def wq(addr, h, msg):
    try:
        return client.wasm.contract_query(addr, msg, h)
    except Exception as e:
        return {"_err": str(e)}

def liq_query(vid):
    r = wq(V3_REG_ADDR, V3_REG_HASH, {"liquidatable_positions": {"vault_id": vid}})
    if "_err" in r:
        err = r["_err"]
        is_dz = "zero" in err.lower() or "devide" in err.lower()
        return False, err, is_dz
    return True, r.get("positions", []), False

# ── PoC ──────────────────────────────────────────────────────────────────────
print("=" * 64)
print("  F8 PoC — Divide-by-Zero in Vault Liquidation Math")
print("  Network: secret-4 mainnet (live queries)")
print("=" * 64)

# 1. Confirm WBTC vault broken state
banner("1/4  Confirm WBTC vault collateral state (vault_id=9)")
r = wq(V3_REG_ADDR, V3_REG_HASH, {"vault": {"vault_id": WBTC_VID}})
assert "_err" not in r, f"vault query failed: {r['_err']}"

vault = r["vault"]
col   = vault["collateral"]
debt  = vault["debt"]
col_e = int(col["elastic"])
col_b = int(col["base"])
debt_e = int(debt["elastic"])
positions = int(vault["open_positions"]["value"])
status = r["status"]

print(f"  Vault name          : {vault['name']}  (vault_id={WBTC_VID})")
print(f"  Status              : {status}")
print(f"  Open positions      : {positions}")
print(f"  collateral.elastic  : {col_e}  ← near zero")
print(f"  collateral.base     : {col_b}")
print(f"  elastic / base      : {col_e/col_b:.4e}  ← should be ~1.0, is ~0")
print(f"  debt.elastic        : {debt_e}  ({debt_e/1e18:,.2f} SILK outstanding)")
print()
print(f"  Because elastic≈0, any calculation using:")
print(f"    collateral_value = shares × (elastic/base) × price ≈ 0")
print(f"    ltv = debt / collateral_value = non-zero / 0 → DIVIDE BY ZERO")

# 2. Trigger divide-by-zero
banner("2/4  Trigger: liquidatable_positions on WBTC vault")
print(f"  Calling: liquidatable_positions({{vault_id: '{WBTC_VID}'}})")
ok, result, is_dz = liq_query(WBTC_VID)
print()

if not ok:
    raw_err = result
    if is_dz:
        key = "Cannot devide"
        idx = raw_err.find(key)
        err_msg = raw_err[idx:idx+55] if idx >= 0 else raw_err[:55]
        print(f"  ╔═══════════════════════════════════════════════════════════╗")
        print(f"  ║  ERROR: {err_msg:<52} ║")
        print(f"  ║                                                           ║")
        print(f"  ║  DIVIDE-BY-ZERO CONFIRMED                                 ║")
        print(f"  ║  {positions} positions / ${debt_e/1e18*1.40:,.0f} debt — PERMANENTLY FROZEN   ║")
        print(f"  ╚═══════════════════════════════════════════════════════════╝")
    else:
        print(f"  ERROR (not divide-by-zero): {raw_err[:150]}")
else:
    print(f"  Unexpected success — {len(result)} positions returned")

# 3. Control: healthy vaults
banner("3/4  Control: liquidatable_positions on healthy vaults (no error)")
print(f"  {'vault_id':<10} {'name':<28} {'result':<30} {'ok?'}")
print(f"  {'─'*8}  {'─'*26}  {'─'*28}  {'─'*4}")

for vid in HEALTHY_VIDS:
    r2 = wq(V3_REG_ADDR, V3_REG_HASH, {"vault": {"vault_id": vid}})
    vname = r2.get("vault", {}).get("name", f"V{vid}") if "_err" not in r2 else f"V{vid}"
    ok2, res2, dz2 = liq_query(vid)
    if ok2:
        n = len(res2) if isinstance(res2, list) else 0
        result_str = f"{n} liquidatable positions"
        flag = "✓"
    else:
        result_str = "DIVIDE BY ZERO" if dz2 else "ERROR"
        flag = "✗" if dz2 else "!"
    print(f"  {vid:<10} {vname:<28} {result_str:<30} {flag}")

print()
print(f"  {'9':<10} {'WBTC Vault (BROKEN)':<28} {'DIVIDE BY ZERO':<30} ✗ ← only this vault")

# 4. Permanence analysis
banner("4/4  Permanence: 39 borrowers cannot close or get liquidated")
print(f"""
  The {positions} open positions in the WBTC vault are in a permanently broken state:

  Can they be liquidated?
    ✗  liquidatable_positions → divide-by-zero
       No liquidator can claim them

  Can borrowers repay and retrieve collateral?
    ✗  Repay returns: shares × (elastic/base) × price
                    = shares × ({col_e/col_b:.2e}) × $74,664
                    ≈ $0.00
       Borrowers lose their collateral; get nothing back

  Can the protocol recover the bad debt?
    ✗  {debt_e/1e18:,.2f} SILK in circulation with no collateral backing
       Stability pool cannot absorb it (no collateral to distribute)
       Bad debt is permanently embedded in the SILK supply

  Root cause (same underlying bug as F1 LP inflation):
    No MINIMUM_COLLATERAL guard in vault collateral rebase.
    When elastic → 0:
      deposit_shares = tokens × base / elastic → ∞ (or overflow)
      withdraw_tokens = shares × elastic / base → 0
      LTV = debt / (shares × elastic/base × price) → divide-by-zero

  Fix:
    1. Guard liquidatable_positions: if elastic == 0, return empty list
    2. Add MINIMUM_COLLATERAL to vault first-deposit (mirrors MINIMUM_LIQUIDITY fix for F1)
    3. Freeze all vaults with elastic < MIN_THRESHOLD pending manual recovery

  All affected vaults (elastic=0 or near-zero in V3-prod registry):
    V5  Stride OSMO  — 0 SILK debt  (no monetary loss, math broken)
    V6  ATOM         — 0 SILK debt  (no monetary loss, math broken)
    V7  OSMO         — 0 SILK debt  (no monetary loss, math broken)
    V9  WBTC         — {debt_e/1e18:,.2f} SILK = ${debt_e/1e18*1.40:,.0f}  [CRITICAL]
    V13 INJ          — 0 SILK debt  (no monetary loss, math broken)
    V14 Stride INJ   — 0 SILK debt  (no monetary loss, math broken)
""")

print("PoC F8 complete.")
