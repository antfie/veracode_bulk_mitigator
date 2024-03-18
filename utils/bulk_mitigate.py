from utils.api import API
from utils.processor import MitigationToAdd
from utils.parallel import parallel_execute_tasks_with_progress
from rich.console import Console


def bulk_mitigate(
    console: Console,
    api: API,
    mitigations_to_add: list[MitigationToAdd],
    number_of_threads: int,
):
    def perform_mitigation(mitigation: MitigationToAdd):
        console.log(
            f"Mitigating flaw #{mitigation.flaw_number} in application profile '{mitigation.app_info.application_name}'..."
        )
        for action, comment in mitigation.bulk_mitigation.get_actions().items():
            if len(mitigation.annotations) > 0:
                last_annotation = mitigation.annotations[0]

                # Ignore if the annotation is already present
                if (
                    action == last_annotation["action"]
                    and comment.strip() == last_annotation["comment"].strip()
                ):
                    continue

            api.add_mitigation(
                mitigation.app_info.application_guid,
                mitigation.flaw_number,
                action,
                comment,
                mitigation.app_info.sandbox_guid,
            )

    mitigation_count_pluralised = "" if len(mitigations_to_add) == 1 else "s"

    parallel_execute_tasks_with_progress(
        console,
        f"Mitigating {len(mitigations_to_add)} flaw{mitigation_count_pluralised}...",
        perform_mitigation,
        mitigations_to_add,
        number_of_threads,
    )
