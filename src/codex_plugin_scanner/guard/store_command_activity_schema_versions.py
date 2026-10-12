"""Version markers for the command-activity schema families.

The native store creates and validates these tables (see the guard-store
`initialize_schema_prefix` method); Python keeps only the values it reads back.
"""

from __future__ import annotations

from typing import Final

COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION: Final = 10
COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION: Final = 11
COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION: Final = 12
COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION: Final = 27
COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION: Final = "1.0.0"
COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION: Final = "guard.command-activity-maintenance.v1"
COMMAND_ACTIVITY_INVALIDATION_LIMIT: Final = 10_000
