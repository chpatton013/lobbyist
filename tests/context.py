import os
import sys

# Add the parent directory to the path so we can import the lobbyist module
# directly instead of relying on it to be installed in site-packages.
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")),
)

import lobbyist

__all__ = ("lobbyist", )
