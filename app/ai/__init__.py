"""Bounded internal assistant (T7).

A consumer of the shared deterministic analytics layer, never a
prerequisite for external REST queries. All model input passes the
fail-closed provider/model/tier gate (:mod:`app.ai.gate`) and the
minimized egress boundary (:mod:`app.ai.egress`) before every
attempted provider request. Budgets are reserved and charged against
a durable database ledger (:mod:`app.ai.budget`), so restarts and
concurrent workers cannot reset or double-spend them.

Routine operation uses fake providers only
(:mod:`app.ai.providers.fake`); no real product provider transport
exists in this slice. A real paid call additionally requires verified
account access and explicit capped user authorization (T8).
"""
