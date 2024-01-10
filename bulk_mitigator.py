from typing import IO

import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from utils.api import API
from utils.bulk_mitigate import bulk_mitigate
from utils.list_of_applications import acquire_applications
from utils.bulk_mitigations_file import BulkMitigations
from utils.processor import process, MitigationToAdd

console = Console(log_path=False)


def print_summary(mitigations_to_add: list[MitigationToAdd]):
    console.log(
        (
            "There is 1 mitigation"
            if len(mitigations_to_add) == 1
            else f"There are {len(mitigations_to_add)} mitigations"
        )
        + " to apply:"
    )

    table = Table()
    table.add_column("Application")
    table.add_column("Sandbox")
    table.add_column("Mitigation Name")
    table.add_column("Flaw ID")

    for mitigation in mitigations_to_add:
        table.add_row(
            mitigation.app_info.application_name,
            mitigation.app_info.sandbox_name,
            mitigation.bulk_mitigation.friendly_name,
            str(mitigation.flaw_number),
        )

    console.print(table)


def sort_and_filter_mitigations(
    mitigations_to_add: list[MitigationToAdd],
) -> list[MitigationToAdd]:
    filtered_mitigations_to_add: list[MitigationToAdd] = []
    sorted_mitigations = sorted(
        mitigations_to_add, key=lambda x: x.last_seen, reverse=True
    )

    for mitigation in sorted_mitigations:
        mitigation_has_been_processed = False

        # We only need to mitigate the latest unique flaw id
        for processed in filtered_mitigations_to_add:
            if (
                mitigation.app_info.application_guid
                == processed.app_info.application_guid
                and mitigation.flaw_number == processed.flaw_number
            ):
                mitigation_has_been_processed = True

        if not mitigation_has_been_processed:
            filtered_mitigations_to_add.append(mitigation)

    return filtered_mitigations_to_add


@click.command()
@click.option(
    "--application_names_file",
    default="data/application_names.txt",
    type=click.File("r", encoding="utf-8"),
    help="A text file containing application names, one per line.",
)
@click.option(
    "--mitigations_file",
    default="data/approved_bulk_mitigations.json",
    type=click.File("r", encoding="utf-8"),
    help="A JSON file containing bulk mitigation details.",
)
@click.option(
    "--number_of_threads",
    default=10,
    type=click.INT,
    help="Number of threads to use.",
)
@click.option(
    "--application_cache_file_path",
    default=None,
    type=click.STRING,
    help="A text file containing application name to guid mappings, one per line.",
)
def main(
    application_names_file: IO[str],
    mitigations_file: IO[str],
    number_of_threads: int,
    application_cache_file_path: str,
):
    thread_count_pluralised = "" if number_of_threads == 1 else "s"
    console.log(f"Using {number_of_threads} thread{thread_count_pluralised}")

    mitigations_to_add: list[MitigationToAdd] = []
    bulk_mitigations = BulkMitigations(console, mitigations_file)
    api = API(console)

    applications_to_process = acquire_applications(
        console,
        api,
        bulk_mitigations,
        application_names_file,
        application_cache_file_path,
        number_of_threads,
    )

    if len(applications_to_process) > 0:
        process(
            console,
            api,
            bulk_mitigations,
            applications_to_process,
            mitigations_to_add,
            number_of_threads,
        )

    if len(mitigations_to_add) < 1:
        console.log(f"There are no mitigations to apply.")
        return

    mitigations_to_add = sort_and_filter_mitigations(mitigations_to_add)

    print_summary(mitigations_to_add)

    if not Confirm.ask("Apply mitigations?"):
        return

    bulk_mitigate(console, api, mitigations_to_add, number_of_threads)


if __name__ == "__main__":
    main()
