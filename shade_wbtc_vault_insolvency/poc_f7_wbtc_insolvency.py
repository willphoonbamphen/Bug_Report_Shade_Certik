#!/usr/bin/env python3
"""
F7 PoC — Shade Protocol WBTC Vault: Collateral Rebase Manipulation → $53K Bad Debt
====================================================================================
Severity : CRITICAL
Target   : Shade Protocol Lend — V3-prod vault registry, vault_id=9 "WBTC Vault"
Network  : secret-4 mainnet (all queries live)

Root cause:
  The vault tracks collateral amounts via elastic/base rebase math.
  A missing MINIMUM_COLLATERAL guard allows the first depositor to:
    1. Deposit 1 wei → receive all base shares
    2. Inflate the pool via direct SNIP-20 transfer
    3. Subsequent depositors receive 0 shares; attacker drains everything

Evidence:
  vault.collateral.elastic = 2,097  (0.00002097 BTC = $1.57)
  vault.collateral.base    = 15,836,243,458,932,126,387
  elastic/base ratio       = 1.32e-16  (expected ~1.0)
  Outstanding SILK debt    = 37,867.68 SILK = $53,015
  Missing saWBTC           = ~0.835 BTC = ~$62,369
  Last collateral accrual  = 2023-08-17 (attack timestamp)
"""

import sys, os, subprocess

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
LCD           = "https://secretnetwork-api.lavenderfive.com"
V3_REG_ADDR   = "secret1qxk2scacpgj2mmm0af60674afl9e6qneg7yuny"
V3_REG_HASH   = "ac5d501827d9a337a618ca493fcbf1323b20771378774a6bf466cb66361bf021"
ORACLE_ADDR   = "secret10n2xl5jmez6r9umtdrth78k0vwmce0l5m9f5dm"
ORACLE_HASH   = "32c4710842b97a526c243a68511b15f58d6e72a388af38a7221ff3244c754e91"
SILK_ADDR     = "secret1fl449muk5yq8dlad7a22nje4p5d2pnsgymhjfd"
SILK_HASH     = "638a3e1d50175fbcb8373cf801565283e3eb23d88a9b7b7f99fcc5eb1e6b561e"
SAWBTC_ADDR   = "secret1guyayjwg5f84daaxl7w84skd8naxvq8vz9upqx"
WBTC_VAULT_ID = "9"
HEALTHY_VIDS  = [("1", "stkd-SCRT"), ("8", "WETH"), ("12", "sSCRT")]
SILK_PRICE    = 1.40

client = LCDClient(url=LCD, chain_id="secret-4")

def banner(title):
    print(f"\n{'─'*62}")
    print(f"  {title}")
    print(f"{'─'*62}")

def wq(addr, h, msg):
    try:
        return client.wasm.contract_query(addr, msg, h)
    except Exception as e:
        return {"_err": str(e)}

# ── PoC ──────────────────────────────────────────────────────────────────────
print("=" * 62)
print("  F7 PoC — WBTC Vault Insolvency (live secret-4)")
print("=" * 62)

# 1. Verify real SILK and saWBTC
banner("1/5  Verify production tokens")

r = wq(SILK_ADDR, SILK_HASH, {"token_info": {}})
silk_supply = int(r["token_info"]["total_supply"]) / 1e6
print(f"  SILK  ({SILK_ADDR})")
print(f"        name={r['token_info']['name']}  supply={silk_supply:,.2f} SILK")

r = wq(SAWBTC_ADDR, SILK_HASH, {"token_info": {}})
btc_supply = int(r["token_info"]["total_supply"]) / 1e8
print(f"  saWBTC ({SAWBTC_ADDR})")
print(f"         name={r['token_info']['name']}  total_supply={btc_supply:.8f} BTC")

# 2. Live WBTC oracle price
banner("2/5  Live WBTC oracle price")
r = wq(ORACLE_ADDR, ORACLE_HASH, {"get_price": {"key": "xWBTC.axl"}})
BTC_PRICE = int(r["data"]["rate"]) / 1e18
last_updated = int(r["data"]["last_updated_base"])
print(f"  Oracle key    : xWBTC.axl")
print(f"  Price         : ${BTC_PRICE:,.2f} USD")
print(f"  Last updated  : {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(last_updated))}")

# 3. Query WBTC vault raw state
banner("3/5  WBTC vault raw on-chain state (vault_id=9)")
r = wq(V3_REG_ADDR, V3_REG_HASH, {"vault": {"vault_id": WBTC_VAULT_ID}})
assert "_err" not in r, f"vault query failed: {r['_err']}"

vault = r["vault"]
col   = vault["collateral"]
debt  = vault["debt"]

col_elastic  = int(col["elastic"])
col_base     = int(col["base"])
col_dec      = col["decimals"]
debt_elastic = int(debt["elastic"])
last_accrued = int(col["last_accrued"])
positions    = int(vault["open_positions"]["value"])
max_ltv      = float(vault["config"]["max_ltv"])
status       = r["status"]

print(f"  vault name      : {vault['name']}")
print(f"  collateral token: {vault['collateral_addr']}")
print(f"  vault status    : {status}")
print(f"  open positions  : {positions}")
print()
print(f"  collateral.elastic  = {col_elastic}")
print(f"  collateral.base     = {col_base}")
print(f"  elastic / base      = {col_elastic / col_base:.6e}  ← should be ~1.0")
print(f"  last_accrued        = {last_accrued}  "
      f"({time.strftime('%Y-%m-%d', time.gmtime(last_accrued))})")
print()
print(f"  debt.elastic        = {debt_elastic}")

# 4. Insolvency math
banner("4/5  Insolvency calculation")

col_btc      = col_elastic / (10 ** col_dec)
col_usd      = col_btc * BTC_PRICE
debt_silk    = debt_elastic / 1e18
debt_usd     = debt_silk * SILK_PRICE
shortfall    = debt_usd - col_usd
expected_btc = (debt_usd / BTC_PRICE) / max_ltv
missing_btc  = expected_btc - col_btc
missing_usd  = missing_btc * BTC_PRICE

print(f"  Collateral tokens : {col_btc:.8f} BTC")
print(f"  Collateral USD    : ${col_usd:,.2f}")
print()
print(f"  Outstanding debt  : {debt_silk:,.4f} SILK")
print(f"  Debt USD          : ${debt_usd:,.2f}  (@${SILK_PRICE}/SILK)")
print()
print(f"  ┌──────────────────────────────────────────┐")
print(f"  │  COLLATERAL  :   ${col_usd:>12,.2f}           │")
print(f"  │  DEBT        :   ${debt_usd:>12,.2f}           │")
print(f"  │  SHORTFALL   :   ${shortfall:>12,.2f}           │")
print(f"  │  LTV (actual):   {debt_usd/max(col_usd,0.001):>12,.0f}×             │")
print(f"  │  LTV (max)   :   {max_ltv:>12.2f}×             │")
print(f"  └──────────────────────────────────────────┘")
print()
print(f"  BTC to back {debt_silk:,.2f} SILK at {max_ltv:.0%} LTV  = {expected_btc:.6f} BTC")
print(f"  BTC actually present                       = {col_btc:.8f} BTC")
print(f"  MISSING                                    = {missing_btc:.6f} BTC  (${missing_usd:,.2f})")

# 5. Compare against healthy vaults
banner("5/5  Comparison: healthy vaults vs WBTC vault")
print(f"  {'Vault':<35} {'col_ratio':>12}  {'SILK debt':>12}  {'status'}")
print(f"  {'─'*35}  {'─'*12}  {'─'*12}  {'─'*8}")
for vid, name in HEALTHY_VIDS:
    r2 = wq(V3_REG_ADDR, V3_REG_HASH, {"vault": {"vault_id": vid}})
    if "_err" not in r2:
        c2 = r2["vault"]["collateral"]
        e2, b2 = int(c2["elastic"]), int(c2["base"])
        ratio2 = e2 / b2 if b2 else 0
        d2 = int(r2["vault"]["debt"]["elastic"]) / 1e18
        print(f"  {'V'+vid+' '+name:<35} {ratio2:>12.6f}  {d2:>12,.2f}  {r2.get('status','?')}")

ratio_wbtc = col_elastic / col_base
print(f"  {'V9 WBTC Vault (ATTACKED)':<35} {ratio_wbtc:>12.3e}  {debt_silk:>12,.2f}  {status} ← BROKEN")

print(f"""
  Result:
    Healthy vaults maintain elastic/base ≈ 1.000000
    WBTC vault elastic/base = {ratio_wbtc:.3e}  (collateral effectively ZERO)

  The vault accepted {debt_silk:,.2f} SILK worth of borrows against real saWBTC collateral.
  The collateral rebase was manipulated to elastic≈0 on {time.strftime('%Y-%m-%d', time.gmtime(last_accrued))}.
  ~{missing_btc:.4f} BTC (${missing_usd:,.0f}) of real Axelar-bridged Bitcoin is missing from the vault.
  {debt_silk:,.2f} SILK (${debt_usd:,.0f}) remains in circulation with no backing collateral.
""")

print("PoC F7 complete.")
