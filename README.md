# Veracode SAST Bulk Mitigator

**Note this tool is not an official Veracode product. It comes with no support or warranty.**

This tool takes a list of application names (from `data/application_names.txt`) and it attempts to bulk mitigate any
un-mitigated flaws found within those applications as per the approved mitigation signatures as defined
in `data/approved_bulk_mitigations.json`.

For targeted mitigation the tool will check for all 5 matching signatures when considering every open flaw for each application specified:

1. CWE
2. Module name
3. File name
4. Attack vector
5. Line Number

Example output:

![example.png](docs%2Fexample.png)

## Requirements

The following components are required to run this tool:

* [Python 3](https://www.python.org/downloads/)
* [Pipenv](https://pipenv.pypa.io/) which can be installed using `pip install --user --upgrade pipenv`
* [Veracode API credentials file](https://docs.veracode.com/r/c_api_credentials3)

## Running

1. Ensure you have configured and reviewed appropriate mitigation signatures in `data/approved_bulk_mitigations.json` (see below for the structure of this file).
2. Make sure you have added a list of applications to `data/application_names.txt`. It may be appropriate to use a single application to test the process before adding all candidate applications. This is simply a text file of application profile names, one per line.
3. Run the below command to run the tool. Note that the tool will not make any changes unless you enter "y" at the prompt following the summary of mitigations to add.

    ```bash
    pipenv run bulk_mitigator
    ```

## mitigations.json File Format

mitigations.json can contain a number of bulk mitigation definitions.

| Property           | Notes                                                                                               |
|--------------------|-----------------------------------------------------------------------------------------------------|
| friendly_name      | A friendly name only used by this tool when producing the report                                    |
| process_policy     | Set to `true` to process policy-level scans                                                         |
| process_sandboxes  | Set to `true` to process sandbox scans                                                              |
| sandboxes          | This is an array of sandbox names to process. If the array is empty all sandboxes will be processed |
| cwe                | The CWE id to match                                                                                 |
| module             | The module name* to match                                                                           |
| file_path          | The file path* to match                                                                             |
| attack_vector      | The attack vector* to match                                                                         |
| line_number        | The line number to match                                                                            |
| mitigate_by_design | If this is present propose a Mitigate By Design mitigation                                          |
| false_positive     | If this is present propose a False Positive mitigation                                              |
| accept_risk        | If this is present propose an Accept The Risk mitigation                                            |
| approve            | If this is present the mitigation will be approved                                                  |

* You can find this information from the Flaw Details section of the Triage Flaws page. 

### Example

In the example below you can see how to use the [TSRV](https://docs.veracode.com/r/c_review_TSRV) format.

```json
[
  {
    "friendly_name": "CWE-117 identified in app.dll",
    "process_policy": true,
    "process_sandboxes": true,
    "sandboxes": [
      "Release"
    ],
    "cwe": 117,
    "module": "app.dll",
    "file_path": "app/controllers/portalcontroller.cs",
    "attack_vector": "microsoft_extensions_logging_abstractions_dll.Microsoft.Extensions.Logging.LoggerExtensions.LogInformation",
    "line_number": 75,
    "mitigate_by_design": "Technique : M1 :  Establish and maintain control over all of your inputs\nSpecifics : TODO\nRemaining Risk : TODO\nVerification : TODO",
    "false_positive": "TODO",
    "accept_risk": "Specifics : TODO\nRemaining Risk : TODO\nVerification : TODO",
    "approve": "TODO"
  }
]
```

## Future Features

* The ability to work across all applications.

## Troubleshooting

If you experience issues running pipenv see this [guide](https://pipenv.pypa.io/en/latest/installation.html). On Windows you may need to update your path environment variable. Alternatively try running pipenv via python like so:

```bash
python3 -m pipenv run bulk_mitigator
```

Finally, consider using pip to install the dependencies:

```bash
python3 -m pip install --user -r requirements.txt
python3 bulk_mitigator.py
```

## Development

When running locally it helps to cache some of the requests. Use this flag to do that:

```bash
pipenv run bulk_mitigator --application_cache_file_path=data/application_cache.csv
```

There is a script to lint the code, keep dependencies up to date and run some tests:

```bash
pipenv run test
```
