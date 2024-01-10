from datetime import datetime


def parse_from_veracode_date_time(input: str):
    return datetime.strptime(
        input,
        "%Y-%m-%dT%H:%M:%S.%fZ",
    )
