"""Rule DSL schema validation — no evidence evaluation in Flow 1."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Union

from pydantic import BaseModel, Field, model_validator


class Operator(str, Enum):
    EQ = "EQ"
    NE = "NE"
    IN = "IN"
    NOT_IN = "NOT_IN"
    EXISTS = "EXISTS"
    NOT_EXISTS = "NOT_EXISTS"
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    GTE = "GTE"
    LTE = "LTE"
    MATCHES = "MATCHES"


UNARY_OPERATORS = {Operator.EXISTS, Operator.NOT_EXISTS}
BINARY_OPERATORS = set(Operator) - UNARY_OPERATORS


class RuleCondition(BaseModel):
    path: str
    operator: Operator
    value: Any | None = None

    @model_validator(mode="after")
    def validate_value_for_operator(self) -> "RuleCondition":
        if self.operator in UNARY_OPERATORS and self.value is not None:
            raise ValueError(f"operator {self.operator} must not have a value")
        if self.operator in BINARY_OPERATORS and self.value is None:
            raise ValueError(f"operator {self.operator} requires a value")
        return self


class AllRule(BaseModel):
    all: list[Union["AllRule", "AnyRule", RuleCondition]]


class AnyRule(BaseModel):
    any: list[Union["AllRule", "AnyRule", RuleCondition]]


RuleExpression = Union[AllRule, AnyRule, RuleCondition]


AllRule.model_rebuild()
AnyRule.model_rebuild()


def validate_rule(rule: dict[str, Any]) -> RuleExpression:
    """Validate a rule dict against the DSL schema."""
    if "all" in rule:
        return AllRule.model_validate(rule)
    if "any" in rule:
        return AnyRule.model_validate(rule)
    return RuleCondition.model_validate(rule)


def validate_rules(rules: list[dict[str, Any]]) -> list[RuleExpression]:
    return [validate_rule(r) for r in rules]
