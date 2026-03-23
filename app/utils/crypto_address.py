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
Crypto address format validation and checksum verification.

Supported address formats:
- BTC: Base58Check (P2PKH, P2SH) + Bech32 (P2WPKH, P2WSH)
- ETH: EIP-55 checksummed hex (0x + 40 chars)
- USDT/USDC on ETH: Same as ETH
- USDT on TRON (TRC-20): Base58Check, starts with T
- DOGE: Base58Check, starts with D
- XMR: 95-char base58 or 106-char integrated address
- LTC: Base58Check or Bech32 (starts with ltc1)

SECURITY:
- Always validate before display to prevent clipboard hijacking
- Character-by-character highlighting CSS classes added for visual verification
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def validate_address(network: str, address: str) -> tuple[bool, str, bool]:
    """
    Validate a cryptocurrency address.

    Args:
        network: Network identifier (BTC, ETH, USDT-ERC20, USDT-TRC20, USDC, DOGE, XMR, LTC).
        address: Address string to validate.

    Returns:
        Tuple of (is_valid, error_message, has_checksum).
        has_checksum indicates if checksum was verified.
    """
    if not address or not address.strip():
        return False, "Address is empty", False

    address = address.strip()
    network_upper = network.upper()

    if network_upper == "BTC":
        return _validate_btc(address)
    elif network_upper in ("ETH", "ERC20", "ERC-20", "USDC", "USDT-ERC20"):
        return _validate_eth(address)
    elif network_upper in ("TRC20", "TRC-20", "USDT-TRC20"):
        return _validate_tron(address)
    elif network_upper == "DOGE":
        return _validate_doge(address)
    elif network_upper == "XMR":
        return _validate_xmr(address)
    elif network_upper == "LTC":
        return _validate_ltc(address)
    else:
        # Unknown network: basic length check only
        if len(address) < 20 or len(address) > 200:
            return False, f"Address length seems invalid for {network}", False
        return True, "", False


def _validate_btc(address: str) -> tuple[bool, str, bool]:
    """Validate Bitcoin address (P2PKH, P2SH, or Bech32)."""
    # Bech32 (native SegWit)
    if address.startswith("bc1"):
        try:
            import bech32
            hrp, data = bech32.bech32_decode(address)
            if hrp == "bc" and data is not None:
                return True, "", True
            return False, "Invalid Bech32 address", False
        except ImportError:
            # Fallback: regex check
            if re.match(r"^bc1[ac-hj-np-z02-9]{6,87}$", address):
                return True, "", False
            return False, "Invalid Bech32 Bitcoin address", False
        except Exception:
            return False, "Invalid Bech32 Bitcoin address", False

    # P2PKH (starts with 1) or P2SH (starts with 3)
    if address.startswith(("1", "3")):
        try:
            import base58
            decoded = base58.b58decode_check(address)
            if decoded and len(decoded) == 21:
                return True, "", True
            return False, "Invalid Base58Check checksum", False
        except ImportError:
            # Fallback regex
            if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
                return True, "", False
            return False, "Invalid Bitcoin address format", False
        except Exception:
            return False, "Invalid Bitcoin address (checksum failed)", False

    return False, "Bitcoin address must start with 1, 3, or bc1", False


def _validate_eth(address: str) -> tuple[bool, str, bool]:
    """Validate Ethereum address with EIP-55 checksum."""
    if not re.match(r"^0x[0-9a-fA-F]{40}$", address):
        return False, "Ethereum address must be 0x + 40 hex characters", False

    # Check EIP-55 checksum
    try:
        checksum_addr = _eth_checksum(address)
        has_checksum = address == checksum_addr
        if not has_checksum and address != address.lower() and address != address.upper():
            # Mixed case but doesn't match checksum
            return False, "Ethereum address has invalid EIP-55 checksum", False
        return True, "", has_checksum
    except Exception:
        # Accept any valid hex address even without checksum verification
        return True, "", False


def _validate_tron(address: str) -> tuple[bool, str, bool]:
    """Validate Tron (TRC-20) address."""
    if not address.startswith("T"):
        return False, "Tron address must start with T", False

    try:
        import base58
        decoded = base58.b58decode_check(address)
        if decoded and len(decoded) == 21 and decoded[0] == 0x41:
            return True, "", True
        return False, "Invalid Tron address checksum", False
    except ImportError:
        if re.match(r"^T[a-km-zA-HJ-NP-Z1-9]{33}$", address):
            return True, "", False
        return False, "Invalid Tron address format", False
    except Exception:
        return False, "Invalid Tron address (checksum failed)", False


def _validate_doge(address: str) -> tuple[bool, str, bool]:
    """Validate Dogecoin address."""
    if not address.startswith("D"):
        return False, "Dogecoin address must start with D", False

    try:
        import base58
        decoded = base58.b58decode_check(address)
        if decoded and len(decoded) == 21:
            return True, "", True
        return False, "Invalid Dogecoin address checksum", False
    except ImportError:
        if re.match(r"^D[a-km-zA-HJ-NP-Z1-9]{33}$", address):
            return True, "", False
        return False, "Invalid Dogecoin address format", False
    except Exception:
        return False, "Invalid Dogecoin address (checksum failed)", False


def _validate_xmr(address: str) -> tuple[bool, str, bool]:
    """Validate Monero address (standard or integrated)."""
    length = len(address)
    if length == 95:
        # Standard Monero address
        if re.match(r"^4[0-9A-Za-z]{94}$", address):
            return True, "", False
        return False, "Invalid Monero address format (expected 95 chars starting with 4)", False
    elif length == 106:
        # Integrated address
        if re.match(r"^4[0-9A-Za-z]{105}$", address):
            return True, "", False
        return False, "Invalid Monero integrated address format", False
    else:
        return False, f"Monero address must be 95 or 106 characters (got {length})", False


def _validate_ltc(address: str) -> tuple[bool, str, bool]:
    """Validate Litecoin address."""
    # Bech32 (native SegWit)
    if address.startswith("ltc1"):
        try:
            import bech32
            hrp, data = bech32.bech32_decode(address)
            if hrp == "ltc" and data is not None:
                return True, "", True
        except ImportError:
            pass
        if re.match(r"^ltc1[ac-hj-np-z02-9]{6,87}$", address):
            return True, "", False
        return False, "Invalid Litecoin Bech32 address", False

    # Legacy (L or M prefix)
    if address.startswith(("L", "M")):
        try:
            import base58
            decoded = base58.b58decode_check(address)
            if decoded and len(decoded) == 21:
                return True, "", True
        except ImportError:
            if re.match(r"^[LM][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
                return True, "", False
        except Exception:
            pass
        return False, "Invalid Litecoin address (checksum failed)", False

    return False, "Litecoin address must start with L, M, or ltc1", False


def _eth_checksum(address: str) -> str:
    """Compute EIP-55 checksummed Ethereum address."""
    import hashlib
    addr = address.lower().replace("0x", "")
    checksum = hashlib.sha3_256(addr.encode()).hexdigest()
    result = "0x"
    for i, char in enumerate(addr):
        if char.isdigit():
            result += char
        elif int(checksum[i], 16) >= 8:
            result += char.upper()
        else:
            result += char.lower()
    return result


def validate_tx_hash(network: str, tx_hash: str) -> tuple[bool, str]:
    """
    Validate a transaction hash format.

    Args:
        network: Network identifier.
        tx_hash: Transaction hash string.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not tx_hash or not tx_hash.strip():
        return False, "Transaction hash is empty"

    tx_hash = tx_hash.strip()
    network_upper = network.upper()

    if network_upper == "BTC":
        # BTC: 64 lowercase hex characters
        if re.match(r"^[0-9a-fA-F]{64}$", tx_hash):
            return True, ""
        return False, "BTC transaction hash must be 64 hex characters"

    elif network_upper in ("ETH", "ERC20", "ERC-20", "USDC", "USDT-ERC20", "TRC20"):
        # ETH/ERC20: 0x + 64 hex characters
        if re.match(r"^0x[0-9a-fA-F]{64}$", tx_hash):
            return True, ""
        return False, "ETH transaction hash must be 0x + 64 hex characters"

    elif network_upper == "DOGE":
        if re.match(r"^[0-9a-fA-F]{64}$", tx_hash):
            return True, ""
        return False, "DOGE transaction hash must be 64 hex characters"

    else:
        # Unknown network: basic length check
        if 20 <= len(tx_hash) <= 200:
            return True, ""
        return False, "Transaction hash length seems invalid"
