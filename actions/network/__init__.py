"""Network attack actions — reserved namespace, no actions registered yet.

Port scanning and service probing currently live in modules/ (stage 1-3)
where they are passive-first and rate-limited; no agent or chain leg can
arm them yet. Keep the import so the namespace keeps its intended shape.
"""
