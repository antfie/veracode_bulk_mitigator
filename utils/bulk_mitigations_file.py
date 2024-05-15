from json import load
from sys import exit
from typing import IO
from collections import OrderedDict

from rich.console import Console


class BulkMitigation:
    def __init__(self, console: Console, data):
        if "friendly_name" not in data:
            console.log('A bulk mitigation was missing a value for "friendly_name".')
            exit(1)

        self.friendly_name = data["friendly_name"]
        self.process_policy = bool(data["process_policy"])
        self.process_sandboxes = bool(data["process_sandboxes"])

        if not self.process_policy and not self.process_sandboxes:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" must have "process_policy" or "process_sandboxes" set to true.'
            )
            exit(1)

        self.sandboxes = []

        if "sandboxes" in data:
            for sandbox in data["sandboxes"]:
                self.sandboxes.append(sandbox.strip())

        self.cwe = int(data["cwe"])
        self.module = data["module"]

        if self.module.count("*") > 1:
            console.log(
                "There can only be one wildcard character used for module resolution"
            )
            exit(1)

        self.file_path = data["file_path"]
        self.attack_vector = data["attack_vector"]
        self.line_number = int(data["line_number"])
        self.mitigate_by_design = (
            None if "mitigate_by_design" not in data else data["mitigate_by_design"]
        )
        self.false_positive = (
            None if "false_positive" not in data else data["false_positive"]
        )
        self.accept_risk = None if "accept_risk" not in data else data["accept_risk"]
        self.approve = None if "approve" not in data else data["approve"]
        self.reject = None if "reject" not in data else data["reject"]

        if (
            self.mitigate_by_design is None
            and self.false_positive is None
            and self.accept_risk is None
            and self.approve is None
            and self.reject is None
        ):
            console.log(
                f'Bulk mitigation "{self.friendly_name}" does not specify at least one action of "mitigate_by_design", "false_positive", "accept_risk" or "approve".'
            )
            exit(1)

        if self.mitigate_by_design is not None and self.false_positive is not None:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" cannot specify both "mitigate_by_design" and "false_positive".'
            )
            exit(1)

        if self.approve is not None and self.reject is not None:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" cannot specify both "approve" and "reject".'
            )
            exit(1)

        if self.false_positive is not None and self.reject is not None:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" cannot specify both "false_positive" and "reject".'
            )
            exit(1)

        if self.accept_risk is not None and self.reject is not None:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" cannot specify both "accept_risk" and "reject".'
            )
            exit(1)

        if self.mitigate_by_design is not None and self.reject is not None:
            console.log(
                f'Bulk mitigation "{self.friendly_name}" cannot specify both "mitigate_by_design" and "reject".'
            )
            exit(1)

    # There is a specific order in which to apply multiple mitigations
    def get_actions(self) -> OrderedDict[str, str]:
        actions = OrderedDict()

        if self.mitigate_by_design is not None:
            actions["APPDESIGN"] = self.mitigate_by_design

        if self.false_positive is not None:
            actions["FP"] = self.false_positive

        if self.accept_risk is not None:
            actions["ACCEPTRISK"] = self.accept_risk

        if self.approve is not None:
            actions["ACCEPTED"] = self.approve

        if self.reject is not None:
            actions["REJECTED"] = self.reject

        return actions


class BulkMitigations:
    def __init__(self, console: Console, bulk_mitigations_file: IO[str]):
        self.items: list[BulkMitigation] = []

        for entry in load(bulk_mitigations_file):
            self.items.append(BulkMitigation(console, entry))

        if len(self.items) < 1:
            console.log(
                f'There were no bulk mitigations in "{bulk_mitigations_file.name}".'
            )
            exit(0)

    def get_all_sandbox_names(self):
        sandbox_names = []

        for item in self.items:
            if item.process_sandboxes and len(item.sandboxes) == 0:
                return "ALL"

            for sandbox_name in item.sandboxes:
                if sandbox_name not in sandbox_names:
                    sandbox_names.append(sandbox_name)

        return sandbox_names

    def is_policy_in_scope(self) -> bool:
        for item in self.items:
            if item.process_policy:
                return True

        return False

    def contains_approve_action(self) -> bool:
        for item in self.items:
            if item.approve is not None:
                return True

        return False
