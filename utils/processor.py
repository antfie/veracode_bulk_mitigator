from datetime import datetime

from utils.api import API
from utils.bulk_mitigations_file import BulkMitigations, BulkMitigation
from utils.list_of_applications import AppSandboxInfo
from utils.parallel import parallel_execute_tasks_with_progress
from rich.console import Console

from utils.time import parse_from_veracode_date_time


class MitigationToAdd:
    def __init__(
        self,
        app_info: AppSandboxInfo,
        bulk_mitigation: BulkMitigation,
        flaw_number: int,
        last_seen: datetime,
        annotations,
    ):
        self.app_info: AppSandboxInfo = app_info
        self.bulk_mitigation: BulkMitigation = bulk_mitigation
        self.flaw_number = flaw_number
        self.last_seen: datetime = last_seen
        self.annotations = annotations


def is_candidate_for_bulk_mitigation(
    finding: dict, bulk_mitigation: BulkMitigation, annotations
) -> bool:
    status = finding["finding_status"]

    if status["status"] != "OPEN":
        return False

    if status["resolution_status"] == "APPROVED":
        return False

    if status["resolution"] == "MITIGATED":
        return False

    details = finding["finding_details"]

    if bulk_mitigation.cwe != int(details["cwe"]["id"]):
        return False

    if bulk_mitigation.module != details["module"]:
        return False

    if bulk_mitigation.file_path != details["file_path"]:
        return False

    if bulk_mitigation.attack_vector != details["attack_vector"]:
        return False

    if bulk_mitigation.line_number != int(details["file_line_number"]):
        return False

    # All done, no annotations
    if len(annotations) < 1:
        return True

    # Nothing further to do if we are approving
    if bulk_mitigation.approve is not None:
        return True

    last_annotation = annotations[0]

    # If we are only proposing a mitigation by design and that mitigation is already the latest then there is nothing to do
    if (
        bulk_mitigation.mitigate_by_design is not None
        and bulk_mitigation.false_positive is None
        and bulk_mitigation.accept_risk is None
    ):
        if (
            last_annotation["action"] == "APPDESIGN"
            and bulk_mitigation.mitigate_by_design.strip()
            == last_annotation["comment"].strip()
        ):
            return False

    # If we are only proposing a false positive and that mitigation is already the latest then there is nothing to do
    if (
        bulk_mitigation.false_positive is not None
        and bulk_mitigation.mitigate_by_design is None
        and bulk_mitigation.accept_risk is None
    ):
        if (
            last_annotation["action"] == "APPDESIGN"
            and bulk_mitigation.mitigate_by_design.strip()
            == last_annotation["comment"].strip()
        ):
            return False

    # If we are only proposing "accept the risk" and that mitigation is already the latest then there is nothing to do
    if (
        bulk_mitigation.accept_risk is not None
        and bulk_mitigation.mitigate_by_design is None
        and bulk_mitigation.false_positive is None
    ):
        if (
            last_annotation["action"] == "ACCEPTRISK"
            and bulk_mitigation.accept_risk.strip()
            == last_annotation["comment"].strip()
        ):
            return False

    return True


def process(
    console: Console,
    api: API,
    bulk_mitigations: BulkMitigations,
    applications_to_process,
    mitigations_to_add: list[MitigationToAdd],
    number_of_threads: int,
):
    def process_application(app_info: AppSandboxInfo):
        findings = api.get_findings(
            app_info.application_guid,
            app_info.sandbox_guid,
        )

        if findings is None:
            console.log(
                f'No SAST findings in app profile: "{app_info.application_name}"'
            )
            return

        for finding in findings:
            if "annotations" in finding:
                sorted_annotations = sorted(
                    finding["annotations"],
                    key=lambda x: parse_from_veracode_date_time(x["created"]),
                    reverse=True,
                )
            else:
                sorted_annotations = []

            for bulk_mitigation in bulk_mitigations.items:
                if is_candidate_for_bulk_mitigation(
                    finding, bulk_mitigation, sorted_annotations
                ):
                    last_seen = parse_from_veracode_date_time(
                        finding["finding_status"]["last_seen_date"]
                    )

                    mitigations_to_add.append(
                        MitigationToAdd(
                            app_info,
                            bulk_mitigation,
                            finding["issue_id"],
                            last_seen,
                            sorted_annotations,
                        )
                    )

    application_count_pluralised = "" if len(applications_to_process) == 1 else "s"

    parallel_execute_tasks_with_progress(
        console,
        f"Processing {len(applications_to_process)} scan{application_count_pluralised}...",
        process_application,
        applications_to_process,
        number_of_threads,
    )
