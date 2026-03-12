from openclaw_security.evaluators.base import Evaluator
from openclaw_security.evaluators.regex_eval import RegexEvaluator
from openclaw_security.evaluators.sigma_eval import SigmaEvaluator
from openclaw_security.evaluators.cel_eval import CELEvaluator
from openclaw_security.evaluators.sql_eval import SQLEvaluator
from openclaw_security.evaluators.ml_eval import MLEvaluator
from openclaw_security.evaluators.llm_eval import LLMEvaluator

EVALUATOR_REGISTRY: dict[str, type[Evaluator]] = {
    "regex": RegexEvaluator,
    "sigma": SigmaEvaluator,
    "cel": CELEvaluator,
    "sql": SQLEvaluator,
    "ml": MLEvaluator,
    "llm": LLMEvaluator,
}

__all__ = [
    "Evaluator",
    "RegexEvaluator",
    "SigmaEvaluator",
    "CELEvaluator",
    "SQLEvaluator",
    "MLEvaluator",
    "LLMEvaluator",
    "EVALUATOR_REGISTRY",
]
