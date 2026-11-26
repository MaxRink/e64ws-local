"""End-to-end runs against the local simulator.

Each module here drives something that speaks to ``tools/e64ws_simulator.py``
over a real socket, rather than to a stubbed transport.  ``run_apps_e2e.py``
runs the apps; ``unlock_tier_e2e.py`` runs tier discovery.
"""
