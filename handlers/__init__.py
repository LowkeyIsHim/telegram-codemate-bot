"""
handlers package — importing this package registers every command
handler on the shared `bot` instance from core.py.

ORDER MATTERS: `fallback` is imported LAST, on purpose. Its handler
matches every message (func=lambda m: True). If it were registered
before the specific command handlers, it would catch commands like
/run before they got a chance to run at all.

To add a new feature: add a new file in this folder (or add to an
existing one, e.g. security.py for another security tool) and import
it below, above the fallback import.
"""

from . import menu
from . import coding
from . import osint
from . import security
from . import recon
from . import bugbounty
from . import exif
from . import webtools
from . import fallback  # noqa: F401 — must stay last, see docstring above
