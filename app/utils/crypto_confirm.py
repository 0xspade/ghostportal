# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Read-only blockchain transaction confirmation checkers.

GhostPortal DOES NOT custody crypto or send transactions.
These utilities only check confirmation status via public read-only APIs.

ALL API calls use safe_fetch() for SSRF protection.

Supported networks:
- BTC (Bitcoin) via Blockstream API
- ETH (Ethereum) via public RPC
- TRON (TRC-20 USDT) via Trongrid API
- DOGE (Dogecoin) via Dogechain API
- XMR (Monero) — privacy coin, no on-chain verification possible
"""

import logging
from typing import Optional

from flask import current_app
from app.utils.safe_fetch import safe_fetch

logger = logging.getLogger(__name__)


def check_btc_confirmation(tx_hash: str) -> Optional[int]:
    """
    Check Bitcoin transaction confirmation count via Blockstream API.

    Args:
        tx_hash: Bitcoin transaction hash (64 hex characters).

    Returns:
        Number of confirmations, or None if check failed.
    """
    base_url = current_app.config.get("BTC_RPC_URL", "https://blockstream.info/api")

    try:
        response = safe_fetch(f"{base_url}/tx/{tx_hash}/status")
        response.raise_for_status()
        data = response.json()

        confirmed = data.get("confirmed", False)
        if not confirmed:
            return 0

        block_height = data.get("block_height")
        if block_height is None:
            return 0

        # Get current block height
        tip_response = safe_fetch(f"{base_url}/blocks/tip/height")
        tip_response.raise_for_status()
        current_height = int(tip_response.text.strip())

        confirmations = current_height - block_height + 1
        return max(0, confirmations)

    except Exception as exc:
        logger.warning(f"BTC confirmation check failed for {tx_hash[:12]}...: {exc}")
        return None


def check_eth_confirmation(tx_hash: str) -> Optional[int]:
    """
    Check Ethereum transaction confirmation count via public RPC.

    Args:
        tx_hash: Ethereum transaction hash (0x + 64 hex characters).

    Returns:
        Number of confirmations, or None if check failed.
    """
    rpc_url = current_app.config.get("ETH_RPC_URL", "https://eth.llamarpc.com")

    try:
        # Get transaction receipt
        response = safe_fetch(
            rpc_url,
            method="POST",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
            },
        )
        response.raise_for_status()
        data = response.json()

        receipt = data.get("result")
        if not receipt:
            return 0

        tx_block_number = int(receipt.get("blockNumber", "0x0"), 16)
        if tx_block_number == 0:
            return 0

        # Get current block number
        block_response = safe_fetch(
            rpc_url,
            method="POST",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "eth_blockNumber",
                "params": [],
            },
        )
        block_response.raise_for_status()
        current_block = int(block_response.json()["result"], 16)

        confirmations = current_block - tx_block_number + 1
        return max(0, confirmations)

    except Exception as exc:
        logger.warning(f"ETH confirmation check failed for {tx_hash[:12]}...: {exc}")
        return None


def check_tron_confirmation(tx_hash: str) -> Optional[int]:
    """
    Check Tron network transaction confirmation count via Trongrid API.

    Args:
        tx_hash: Tron transaction hash.

    Returns:
        Number of confirmations, or None if check failed.
    """
    api_url = current_app.config.get("TRON_API_URL", "https://api.trongrid.io")

    try:
        response = safe_fetch(f"{api_url}/v1/transactions/{tx_hash}")
        response.raise_for_status()
        data = response.json()

        ret = data.get("ret", [{}])
        if not ret or ret[0].get("contractRet") != "SUCCESS":
            return 0

        # Tron doesn't provide confirmation count directly
        # A confirmed transaction is one with contractRet=SUCCESS
        return 1

    except Exception as exc:
        logger.warning(f"TRON confirmation check failed for {tx_hash[:12]}...: {exc}")
        return None


def check_doge_confirmation(tx_hash: str) -> Optional[int]:
    """
    Check Dogecoin transaction confirmation count via Dogechain API.

    Args:
        tx_hash: Dogecoin transaction hash.

    Returns:
        Number of confirmations, or None if check failed.
    """
    api_url = current_app.config.get("DOGE_API_URL", "https://dogechain.info/api/v1")

    try:
        response = safe_fetch(f"{api_url}/transaction/{tx_hash}")
        response.raise_for_status()
        data = response.json()

        if data.get("success") != 1:
            return 0

        confirmations = data.get("transaction", {}).get("confirmations", 0)
        return int(confirmations)

    except Exception as exc:
        logger.warning(f"DOGE confirmation check failed for {tx_hash[:12]}...: {exc}")
        return None


def check_confirmations(network: str, tx_hash: str) -> Optional[int]:
    """
    Check transaction confirmations for any supported network.

    Args:
        network: Network identifier (BTC, ETH, TRC20, DOGE).
        tx_hash: Transaction hash.

    Returns:
        Number of confirmations, or None if unsupported/failed.
    """
    if not current_app.config.get("CRYPTO_CONFIRM_ENABLED", False):
        return None

    network_upper = network.upper()

    if network_upper == "BTC":
        return check_btc_confirmation(tx_hash)
    elif network_upper in ("ETH", "ERC20", "ERC-20"):
        return check_eth_confirmation(tx_hash)
    elif network_upper in ("TRC20", "TRC-20", "TRON"):
        return check_tron_confirmation(tx_hash)
    elif network_upper == "DOGE":
        return check_doge_confirmation(tx_hash)
    elif network_upper == "XMR":
        # Monero: privacy coin — no on-chain verification possible
        logger.info("XMR transaction verification not available (privacy coin)")
        return None
    else:
        logger.warning(f"Unsupported network for confirmation check: {network}")
        return None


def get_min_confirmations(network: str) -> int:
    """
    Get the minimum required confirmations for a network.

    Args:
        network: Network identifier.

    Returns:
        Minimum confirmation count.
    """
    network_upper = network.upper()
    defaults = {
        "BTC": current_app.config.get("CRYPTO_MIN_CONFIRMATIONS_BTC", 3),
        "ETH": current_app.config.get("CRYPTO_MIN_CONFIRMATIONS_ETH", 12),
        "ERC20": current_app.config.get("CRYPTO_MIN_CONFIRMATIONS_ETH", 12),
        "DOGE": current_app.config.get("CRYPTO_MIN_CONFIRMATIONS_DOGE", 6),
        "TRC20": 1,
    }
    return defaults.get(network_upper, 6)


def is_confirmed(network: str, tx_hash: str) -> bool:
    """
    Check if a transaction has reached the minimum confirmation threshold.

    Args:
        network: Network identifier.
        tx_hash: Transaction hash.

    Returns:
        True if confirmed, False otherwise.
    """
    confirmations = check_confirmations(network, tx_hash)
    if confirmations is None:
        return False
    return confirmations >= get_min_confirmations(network)
