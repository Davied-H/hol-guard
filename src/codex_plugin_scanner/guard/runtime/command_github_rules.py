"""Compatibility rules for distinct GitHub remote capability classes."""

from __future__ import annotations

from typing import Final, cast

from .command_extension_specs import CommandExtensionSpec
from .command_permission_catalog import COMMAND_PERMISSION_SCHEMA_VERSION, CommandPermissionSpec
from .command_rules import CommandSafetyRule
from .github_capability_contract import github_capability_contracts


def github_permission_specs(implementation_version: str) -> tuple[CommandPermissionSpec, ...]:
    return tuple(
        CommandPermissionSpec(
            permission_id=contract.permission_id,
            schema_version=COMMAND_PERMISSION_SCHEMA_VERSION,
            extension_id="command.github",
            implementation_version=implementation_version,
            label=contract.title,
            description=contract.description,
            risk_tier=contract.risk_tier,
            baseline_floor=contract.action_floor,
            default_enabled=True,
            configurable=True,
            fixed_reason=None,
            typed_capabilities=(contract.capability,),
            action_classes=() if contract.action_class is None else (contract.action_class,),
            rule_ids=() if contract.rule_id is None else (contract.rule_id,),
            dependencies=(),
            conflicts=(),
            implied_permissions=(),
            introduced_version="2.2.0",
            deprecated=False,
            replacement_permission_id=None,
            safer_guidance=contract.safer_alternatives,
            example_command=contract.example_command,
            family=contract.family,
        )
        for contract in github_capability_contracts()
    )


_GITHUB_CONTRACTS: Final = tuple(contract for contract in github_capability_contracts() if contract.rule_id is not None)
GITHUB_ACTION_RISK_CLASSES: Final[dict[str, tuple[str, ...]]] = {
    cast(str, contract.action_class).lower(): contract.risk_classes for contract in _GITHUB_CONTRACTS
}
GITHUB_COMMAND_RULES: Final[tuple[CommandSafetyRule, ...]] = tuple(
    CommandSafetyRule(
        rule_id=cast(str, contract.rule_id),
        title=contract.title,
        description=contract.description,
        severity=contract.risk_tier,
        risk_classes=contract.risk_classes,
        action_classes=(cast(str, contract.action_class),),
        safer_alternatives=contract.safer_alternatives,
        default_mode="disabled" if contract.action_floor == "allow" else "review",
        compatibility_fallback=True,
    )
    for contract in _GITHUB_CONTRACTS
)
GITHUB_COMMAND_EXTENSION_SPECS: Final[tuple[CommandExtensionSpec, ...]] = (
    CommandExtensionSpec(
        extension_id="command.github",
        name="GitHub capability protection",
        description="Reviews distinct GitHub maintenance, content, merge, publication, workflow, and control effects.",
        action_classes=tuple(cast(str, contract.action_class) for contract in _GITHUB_CONTRACTS),
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternatives=("Inspect the exact repository, resource, and operation before confirming it.",),
        reference_urls=("https://cli.github.com/manual/",),
        permissions=github_permission_specs("1.0.0"),
    ),
)
