from csv import reader as csv_reader, writer as csv_writer
from pathlib import Path
from rich.console import Console
from utils.api import API
from utils.bulk_mitigations_file import BulkMitigations
from utils.parallel import parallel_execute_tasks_with_progress
from threading import Lock
from typing import IO


class AppSandboxInfo:
    def __init__(
        self,
        application_name: str,
        application_guid: str,
        sandbox_name: str = None,
        sandbox_guid: str = None,
    ):
        self.application_name: str = application_name
        self.application_guid: str = application_guid
        self.sandbox_name: str = sandbox_name
        self.sandbox_guid: str = sandbox_guid


class ApplicationCache:
    def __init__(self, file_path: str):
        self._path = None if file_path is None else Path(file_path)
        self._entries: list[AppSandboxInfo] = []
        self._lock = Lock()
        self.load()

    def load(self):
        if self._path is None:
            return

        if not self._path.exists():
            return

        with self._path.open("r") as cache_file:
            rows = csv_reader(cache_file)
            for row in rows:
                self._entries.append(
                    AppSandboxInfo(
                        row[0],
                        row[1],
                        None if len(row[2]) < 1 else row[2],
                        None if len(row[3]) < 1 else row[3],
                    )
                )

    def add(self, info: AppSandboxInfo) -> None:
        if self._path is None:
            return

        with self._lock:
            with self._path.open("a") as cache_file:
                writer = csv_writer(cache_file)
                writer.writerow(
                    [
                        info.application_name,
                        info.application_guid,
                        info.sandbox_name,
                        info.sandbox_guid,
                    ]
                )
                self._entries.append(info)

    def get_by_application_name(self, application_name: str) -> AppSandboxInfo:
        for entry in self._entries:
            if entry.application_name == application_name:
                return entry

        return None

    def get_by_sandbox_name(
        self, application_name: str, sandbox_name: str
    ) -> AppSandboxInfo:
        for entry in self._entries:
            if (
                entry.application_name == application_name
                and entry.sandbox_name == sandbox_name
            ):
                return entry

        return None


def load_applications_from_file(applications_file_path: str) -> list[str]:
    application_names = []

    with open(applications_file_path, "r") as applications_file:
        for line in applications_file.readlines():
            # Trim
            application_name = line.strip()

            # Ignore empty lines
            if len(application_name) < 1:
                continue

            application_names.append(application_name)

    return application_names


def acquire_applications(
    console: Console,
    api: API,
    bulk_mitigations: BulkMitigations,
    application_names: list[str],
    application_cache_file_path: str,
    number_of_threads: int,
) -> list[AppSandboxInfo]:
    cache = ApplicationCache(application_cache_file_path)
    items: list[AppSandboxInfo] = []
    mappings = {}
    applications_to_resolve = []

    for application_name in application_names:
        # Ignore any duplicate names which may have crept in via the file or API
        if application_name in applications_to_resolve:
            continue

        cached = cache.get_by_application_name(application_name)

        if cached is not None:
            items.append(cached)
            continue

        if application_name in applications_to_resolve:
            continue

        applications_to_resolve.append(application_name)

    if len(applications_to_resolve) > 0:

        def resolve_application_guid(application_name):
            applications = []

            # The API can return results for similar named applications
            applications_to_consider = api.get_applications_by_name(application_name)

            for application in applications_to_consider:
                if application["profile"]["name"].lower() == application_name.lower():
                    applications.append(application)

            if len(applications) < 1:
                console.log(
                    f'Skipping not found app profile named: "{application_name}"'
                )
                return

            if len(applications) > 1:
                console.log(
                    f'Skipping ambiguous app profile named: "{application_name}". Make sure this application name has been entered fully and correctly'
                )
                return

            # Use the name from the API rather than the file
            application_name = applications[0]["profile"]["name"]

            app_info = AppSandboxInfo(
                application_name, applications[0]["guid"], None, None
            )
            items.append(app_info)
            cache.add(app_info)

        application_count_pluralised = "" if len(applications_to_resolve) == 1 else "s"

        parallel_execute_tasks_with_progress(
            console,
            f"Identifying {len(applications_to_resolve)} application{application_count_pluralised}...",
            resolve_application_guid,
            applications_to_resolve,
            number_of_threads,
        )

    application_sandboxes_to_resolve: list[AppSandboxInfo] = []

    all_sandbox_names = bulk_mitigations.get_all_sandbox_names()

    if len(all_sandbox_names) < 1:
        return mappings

    # we need to enquire about sandboxes because there could be new sandboxes that were not cached
    if all_sandbox_names == "ALL":
        application_sandboxes_to_resolve = items
    else:
        # Filter out anything that has been cached
        for app_info in items.copy():
            for sandbox_name in all_sandbox_names:
                cached = cache.get_by_sandbox_name(
                    app_info.application_name, sandbox_name
                )

                if cached is not None:
                    items.append(cached)
                else:
                    found = False
                    for processed_sandbox in application_sandboxes_to_resolve:
                        if (
                            processed_sandbox.application_name
                            == app_info.application_name
                        ):
                            found = True

                    if not found:
                        application_sandboxes_to_resolve.append(app_info)

    if len(application_sandboxes_to_resolve) > 0:

        def resolve_sandboxes(app_info: AppSandboxInfo):
            for sandbox in api.get_sandboxes(app_info.application_guid):
                # Skip if sandbox is not in scope
                if (
                    all_sandbox_names != "ALL"
                    and sandbox["name"] not in all_sandbox_names
                ):
                    continue

                app_info = AppSandboxInfo(
                    app_info.application_name,
                    app_info.application_guid,
                    sandbox["name"],
                    sandbox["guid"],
                )
                items.append(app_info)

                # Don't bother caching if all sandboxes are in scope
                if all_sandbox_names != "ALL":
                    cache.add(app_info)

        application_sandboxes_to_resolve_count_pluralised = (
            "" if len(application_sandboxes_to_resolve) == 1 else "es"
        )

        parallel_execute_tasks_with_progress(
            console,
            f"Identifying {len(application_sandboxes_to_resolve)} sandbox{application_sandboxes_to_resolve_count_pluralised}...",
            resolve_sandboxes,
            application_sandboxes_to_resolve,
            number_of_threads,
        )

    # Filter out policy level if out of scope for all mitigations
    if not bulk_mitigations.is_policy_in_scope():
        items = list(filter(lambda item: item.sandbox_name is not None, items))

    return items
