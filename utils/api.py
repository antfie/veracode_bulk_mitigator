from requests import RequestException
from veracode_api_py.api import VeracodeAPI, Applications, Sandboxes, Findings
from rich.console import Console
from time import sleep
import logging
from threading import Lock
from secrets import randbelow

# Disable some warnings and traceback logging from the underlying API to prevent clutter in the log
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("veracode_api_py.apihelper").setLevel(logging.CRITICAL)


class API:
    def __init__(self, console: Console):
        self.console = console
        self.request_counters: dict[str, int] = {}
        self.lock = Lock()

        console.log("Testing API connectivity...")
        if not self.test_connection():
            console.log(
                "Error: Could not connect to the Veracode API. Check your Veracode API account credentials."
            )
            exit(1)

    def back_off(self, e: Exception):
        seconds_to_wait = randbelow(111) + 10
        self.console.log(
            f'Backing off for {seconds_to_wait}s due to an API error. Request will be retried. If this occurs often consider reducing the number of threads with the "--number_of_threads" argument'
        )
        sleep(seconds_to_wait)

    def test_connection(self) -> bool:
        try:
            VeracodeAPI().healthcheck()
            return True
        except RequestException:
            return False

    def update_counter(self, request_signature):
        with self.lock:
            if request_signature in self.request_counters:
                self.request_counters[request_signature] = (
                    self.request_counters[request_signature] + 1
                )
            else:
                self.request_counters[request_signature] = 1

            # Max attempts = 5
            if self.request_counters[request_signature] > 5:
                self.console.log("Error: Giving up, too many request errors.")
                exit(1)

    def get_all_applications(self):
        self.update_counter("get_all_applications")

        try:
            return Applications().get_all()
        except Exception as err:
            self.back_off(err)
            return self.get_all_applications()

    def get_applications_by_name(self, application_name: str):
        self.update_counter(f"get_applications_by_name:{application_name}")

        try:
            return Applications().get_by_name(application_name)
        except Exception as err:
            self.back_off(err)
            return self.get_applications_by_name(application_name)

    def get_sandboxes(self, application_guid: str):
        self.update_counter(f"get_sandboxes:{application_guid}")

        try:
            return Sandboxes().get_all(application_guid)
        except Exception as err:
            self.back_off(err)
            return self.get_sandboxes(application_guid)

    def get_findings(self, application_guid: str, sandbox_guid: str = None):
        self.update_counter(f"get_findings:{application_guid},{sandbox_guid}")

        try:
            findings = Findings().get_findings(
                app=application_guid,
                scantype="STATIC",
                annot="TRUE",
                sandbox=sandbox_guid,
            )
            if findings is not None:
                return findings
        except Exception as err:
            self.back_off(err)
            return self.get_findings(application_guid, sandbox_guid)

    def add_mitigation(
        self,
        application_guid: str,
        flaw_id: int,
        action: str,
        comment: str,
        sandbox_guid: str = None,
    ):
        self.update_counter(
            f"add_mitigation{application_guid},{flaw_id},{action},{comment},{sandbox_guid}"
        )

        try:
            Findings().add_annotation(
                application_guid,
                [flaw_id],
                comment,
                action,
                sandbox_guid,
            )
        except Exception as err:
            self.back_off(err)
            self.add_mitigation(
                application_guid, flaw_id, action, comment, sandbox_guid
            )
