"""Minimal EVM client for the TrustLens report registry.

Uses raw JSON-RPC (no web3 dependency). Only a digest and report reference go
on-chain; the report payload stays in the TrustLens database.
"""

from __future__ import annotations

import time

import httpx
from eth_account import Account
from eth_utils import keccak

from ..config import Settings
from ..security.redaction import safe_error

REGISTER_SELECTOR = keccak(text="register(bytes32,bytes32)")[:4]
GET_DIGEST_SELECTOR = keccak(text="getDigest(bytes32)")[:4]


class ChainError(RuntimeError):
    pass


def _rpc(settings: Settings, method: str, params: list) -> dict:
    try:
        with httpx.Client(timeout=settings.chain_rpc_timeout_seconds, trust_env=False) as client:
            response = client.post(
                settings.chain_rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ChainError(f"RPC unavailable: {safe_error(exc, 120)}") from exc
    if "error" in data:
        raise ChainError(f"{data['error'].get('message', 'RPC error')}"[:200])
    return data.get("result", {})


def _hex32(value: str) -> str:
    value = value.lower().replace("0x", "")
    if len(value) != 64:
        raise ChainError("report reference must be 32 bytes")
    return value


def read_digest(report_ref: str, settings: Settings) -> str | None:
    if not settings.chain_configured:
        return None
    call_data = "0x" + (GET_DIGEST_SELECTOR + bytes.fromhex(_hex32(report_ref))).hex()
    result = _rpc(
        settings,
        "eth_call",
        [{"to": settings.chain_contract_address, "data": call_data}, "latest"],
    )
    if not result or result == "0x":
        return None
    raw = result.replace("0x", "")
    return raw[:64].rjust(64, "0")


def commit_digest(report_ref: str, digest: str, settings: Settings) -> dict:
    if not settings.chain_configured:
        raise ChainError("Blockchain registry is not configured.")
    if not settings.chain_private_key:
        raise ChainError(
            "No signing key is configured. Use the documented Hardhat script to register reports."
        )
    account = Account.from_key(settings.chain_private_key)
    calldata = "0x" + (
        REGISTER_SELECTOR + bytes.fromhex(_hex32(report_ref)) + bytes.fromhex(_hex32(digest))
    ).hex()

    nonce_hex = _rpc(settings, "eth_getTransactionCount", [account.address, "pending"])
    gas_price_hex = _rpc(settings, "eth_gasPrice", [])
    chain_id_hex = _rpc(settings, "eth_chainId", [])
    transaction = {
        "nonce": int(nonce_hex, 16),
        "gasPrice": int(gas_price_hex, 16),
        "gas": 200_000,
        "to": settings.chain_contract_address,
        "value": 0,
        "data": calldata,
        "chainId": int(chain_id_hex, 16),
    }
    signed = Account.sign_transaction(transaction, settings.chain_private_key)
    raw_tx = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    tx_hash = _rpc(settings, "eth_sendRawTransaction", ["0x" + raw_tx.hex()])

    receipt = None
    for _ in range(30):
        receipt = _rpc(settings, "eth_getTransactionReceipt", [tx_hash])
        if receipt:
            break
        time.sleep(0.5)
    if not receipt:
        raise ChainError("Transaction was submitted but no receipt arrived in time.")
    if str(receipt.get("status", "")) not in {"0x1", "1"}:
        raise ChainError("Transaction reverted on-chain.")
    return {
        "tx_hash": tx_hash,
        "block_number": int(receipt.get("blockNumber", "0x0"), 16),
        "chain_id": int(chain_id_hex, 16),
        "contract_address": settings.chain_contract_address,
    }


def verify_digest(report_ref: str, digest: str, settings: Settings) -> dict:
    if not settings.chain_configured:
        return {
            "status": "unavailable",
            "match": None,
            "reason": "Blockchain registry is not configured (CHAIN_CONTRACT_ADDRESS is empty).",
            "chain_id": None,
            "contract_address": None,
        }
    try:
        on_chain = read_digest(report_ref, settings)
    except ChainError as exc:
        return {
            "status": "unavailable",
            "match": None,
            "reason": safe_error(exc, 180),
            "chain_id": settings.chain_id,
            "contract_address": settings.chain_contract_address,
        }
    if not on_chain or set(on_chain) == {"0"}:
        return {
            "status": "not_found",
            "match": False,
            "reason": "No digest is registered on-chain for this report reference.",
            "chain_id": settings.chain_id,
            "contract_address": settings.chain_contract_address,
            "on_chain_digest": None,
        }
    return {
        "status": "verified" if on_chain == digest.lower() else "mismatch",
        "match": on_chain == digest.lower(),
        "on_chain_digest": on_chain,
        "off_chain_digest": digest.lower(),
        "chain_id": settings.chain_id,
        "contract_address": settings.chain_contract_address,
        "reason": (
            "The on-chain digest matches the stored report."
            if on_chain == digest.lower()
            else "The stored report no longer matches its on-chain commitment."
        ),
    }
