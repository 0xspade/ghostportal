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
WSGI entry point for GhostPortal.

Used by Gunicorn in production:
    gunicorn wsgi:app --bind 0.0.0.0:8000 --workers 4

Used by Flask development server:
    flask --app wsgi:app run
"""

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Development only — use Gunicorn in production
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_ENV") == "development",
    )
