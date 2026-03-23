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
Approved generic auth error message constants.

Anti-enumeration policy: ONLY these strings may be used in auth endpoint
flash messages and API responses. Never use messages that reveal:
- Whether an email exists in the system
- Whether a token was expired vs. used vs. not found
- Which part of two-factor verification failed (url_token vs OTP)
- Internal system state or error details

USAGE:
    from app.utils.auth_messages import MSG_LOGIN_SENT, MSG_INVALID_LINK
    flash(MSG_INVALID_LINK, "error")
"""

# Shown after POST /login — regardless of whether email is known/unknown
MSG_LOGIN_SENT = (
    "If this email is associated with an account, a login link has been sent. "
    "Check your inbox (and spam folder). The link expires in 15 minutes."
)

# Shown for any magic link failure: expired, used, not found, wrong OTP
# Never reveal which specific failure occurred
MSG_INVALID_LINK = (
    "This link is invalid or has expired. Please request a new one."
)

# Shown when account has issues (locked, no active invites, etc.)
# Never reveal the specific issue
MSG_ACCOUNT_ISSUE = (
    "There is an issue with your account. Please contact the researcher."
)

# Shown when rate limit is hit on auth endpoints
MSG_RATE_LIMITED = (
    "Too many attempts. Please wait before trying again."
)

# Shown on portal setup when invite link is invalid/expired
MSG_INVITE_INVALID = (
    "This invite link is invalid or has expired. "
    "Please contact the researcher for a new invite."
)

# Shown after portal setup complete — do not reveal account was created
MSG_PORTAL_SETUP_COMPLETE = (
    "Portal access established. You can now view the report."
)

# Shown when session expires due to idle timeout
MSG_SESSION_EXPIRED_IDLE = (
    "Your session expired due to inactivity. Please sign in again."
)

# Shown when session is displaced by a new login from another location
MSG_SESSION_DISPLACED = (
    "Your session was ended because you signed in from another location."
)

# Shown on successful logout
MSG_LOGGED_OUT = "You have been signed out."

# Generic form validation error — never expose field-specific issues on auth forms
MSG_FORM_INVALID = "Please check your input and try again."
