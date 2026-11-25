"""Local-cloud skeleton: SQLite-backed stand-in for the vendor device service.

The package holds the implementation that ``docs/LOCAL_CLOUD_DESIGN.md``
describes but does not contain: :mod:`tools.local_cloud.contract` records which
fields are evidenced, :mod:`tools.local_cloud.store` persists them, and
:mod:`tools.local_cloud.service` serves the ten recorded routes and refuses the
rest with a 501 that names the D-id.
"""
