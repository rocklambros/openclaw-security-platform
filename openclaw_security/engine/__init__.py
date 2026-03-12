from openclaw_security.engine.context import EvalContext
from openclaw_security.engine.result import EvalResult, Action

# Lazy import to avoid circular dependency (chain → evaluators.base → engine)
def __getattr__(name: str):
    if name == "EvaluatorChain":
        from openclaw_security.engine.chain import EvaluatorChain
        return EvaluatorChain
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["EvalContext", "EvalResult", "Action", "EvaluatorChain"]
