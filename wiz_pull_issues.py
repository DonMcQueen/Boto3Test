# © 2023 Wiz, Inc.
# By using this software and associated documentation files (the “Software”) you hereby agree and understand that:
# 1. The use of the Software is free of charge and may only be used by Wiz customers for its internal purposes.
# 2. The Software should not be distributed to third parties.
# 3. The Software is not part of Wiz’s Services and is not subject to your company’s services agreement with Wiz.
# 4. THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL WIZ BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OF THIS SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Python 3.8+
# pip install -r requirements.txt
import json
import os
import pandas as pd
import random
import re
import requests
import socket
import sys
import time
import traceback

from datetime import datetime, timedelta, timezone
from operator import itemgetter
from typing import Any
from yaspin import yaspin


# Start a timer to time the script execution
start_time = datetime.now()

############### Start Script settings ###############

# Using a config file to store credential information
# We default to checking for a config file FIRST
# and then fall back to checking for environment vars
# wiz_config_file = "~/fake_dir/wiz/wiz_config.json"  # Default will be skipped, update with real path to config file
wiz_config_file = "/Users/don/VSCode/Boto3Test/wizcreds.json"

# File names - change these if you would like
# We will automatically append extensions to file names
csv_fname = "wiz_issues"
############### End script settings ###############


############### Start Helpers ###############
class Timer:
    """
    A class to generate generic timer objects that we use to time function execution
    """

    def __init__(self, text: str):
        self.text = text
        self._start = datetime.now()

    def __str__(self) -> str:
        now = datetime.now()
        delta = now - self._start
        # split the time into minutes:seconds
        total_time = (
            f"{round(delta.total_seconds(),1)}"
            if delta.total_seconds() < 60
            # round rounds down by default, so we include a remainder in the calculation to force
            # a round up in the minutes calculation withouth having to include an additional library
            else f"{round((delta.total_seconds() // 60 + (delta.total_seconds() % 60 > 0)))}:{round((delta.total_seconds()% 60),1)}"
        )
        return f"{self.text} - Total elapsed time: {total_time}s"


def print_logo() -> None:
    """
    Print out the Wiz logo and script information

    Parameters:
        - none

    Returns:
        - none
    """

    print(
        f"""
                    __      _(_)____   ✦  ✦                                 
                    \ \ /\ / / |_  /     ✦                                  
                     \ V  V /| |/ /                                           
                      \_/\_/ |_/___|  © 2023 Wiz, Inc. 
+----------------------------------------------------------------------+
  WIZ DATACENTER: {BLUE}{WIZ_DATACENTER}{END}
  API URL: {BLUE}{API_URL}{END}
  AUTH URL: {BLUE}{WIZ_AUTH_URL}{END} 
+----------------------------------------------------------------------+
  SCRIPT NAME: {BLUE}{SCRIPT_NAME}{END}
+----------------------------------------------------------------------+
  {SCRIPT_DESCRIPTION}
+----------------------------------------------------------------------+
  OUTPUT FILE: {BLUE}{csv_fname}-<timestamp>.csv{END}
+----------------------------------------------------------------------+"""
    )


def _generic_exception_handler(function: Any) -> Any:
    """
    Private decorator function for error handling

    Parameters:
        - function: the function to pass in

    Returns:
        - _inner_function: the decorated function
    """

    def _inner_function(*args: Any, **kwargs: Any) -> Any:
        try:
            function_result = function(*args, **kwargs)
            return function_result
        except ValueError as v_err:
            print(traceback.format_exc(), f"{v_err}")
            sys.exit(1)
        except Exception as err:
            if (
                "502: Bad Gateway" not in str(err)
                and "503: Service Unavailable" not in str(err)
                and "504: Gateway Timeout" not in str(err)
            ):
                print(traceback.format_exc(), f"[ERROR]: {err}")
                return err

            else:
                print(traceback.format_exc(), "[ERROR] - Retry")

            sys.exit(1)

    return _inner_function


@_generic_exception_handler
def validate_config(
    client_id: str, client_secret: str, auth_url: str, api_url: str
) -> str:
    """
    Validate the the inputs from the config parser are valid
    And exit if any are not

    Parameters:
        - client_id: the wiz client id to check
        - client_secrete: the wiz client secret to check
        - auth_url: the wiz auth url to check
        - api_url: the wiz api url to check

    Returns:
        - wiz_dc: the datacenter extracted from the api url

    Returns:
        - wiz_dc: the wiz datacenter pulled from the config file or the local environment variables
    """
    # A current list of datacenters can be found at
    # https://docs.wiz.io/wiz-docs/docs/req-urls-ip-addr#datacenter-ip-addresses

    # Regex to match us1 - us28, and us28 - 36 (note the ranges we skip)
    US_DC_MATCHER = "(us+([1-9]|[1][0-9]|2[0-8]|3[2-6]))"
    # Regex to match eu1 - eu7
    EU_DC_MATCHER = "(eu+[1-7])"
    # Regex to match gov-us1 ONLY - can extend this later if we add more DCs
    GOV_DC_MATCHER = "(gov-us+[1])"
    # 32 char alphanumeric match for auth0 client ids
    AUTH0_CLIENT_ID_MATCHER = "([a-zA-Z0-9]{32})"
    # 52 or 53 char alphanumeric match for cognito client ids
    COGNITO_CLIENT_ID_MATCHER = "([a-zA-Z0-9]{52,53})"
    # 64 char alphanumeric match for secret
    SECRET_MATCHER = "([A-Za-z0-9-]{64})"

    WIZ_AUTH_ENDPOINTS = [
        "https://auth.app.wiz.io/oauth/token",  # Cognito
        "https://auth.demo.wiz.io/oauth/token",  # Cognito Demo
        "https://auth.wiz.io/oauth/token",  # Auth0 [legacy auth provider]
    ]

    # check to make sure the api url is valid
    if "https://api." not in api_url or not ".wiz.io/graphql" in api_url:
        sys.exit(
            f"[ERROR] {api_url} is not a valid Wiz API URL endpoint. Please check your config file and try again."
        )
    if auth_url not in WIZ_AUTH_ENDPOINTS:
        sys.exit(
            f"[ERROR] {auth_url} is not a valid Wiz Auth Endpoint. Please check your config file and try again. Exiting..."
        )
    # If we don't find a valid client ID, exit
    if not (
        re.fullmatch(AUTH0_CLIENT_ID_MATCHER, client_id)
        or re.fullmatch(COGNITO_CLIENT_ID_MATCHER, client_id)
    ):
        sys.exit(
            f"[ERROR] Did not find a valid Wiz Client ID. Please check your config file and try again. Exiting..."
        )

    # If we dont' find a valid secret, exit
    if not re.fullmatch(SECRET_MATCHER, client_secret):
        sys.exit(
            f"[ERROR] Did not find a valid Wiz Secret. Please check your config file and try again. Exiting..."
        )

    # Pull out only the Wiz DC to validate it is valid
    # Extracts <this-text> from  'api.<this-text>.'
    wiz_dc = api_url.partition("/api.")[2].partition(".")[0]

    # Check to make sure the datacenter is one of of our valid DCs
    if not (
        re.fullmatch(US_DC_MATCHER, wiz_dc)
        or re.fullmatch(EU_DC_MATCHER, wiz_dc)
        or re.fullmatch(GOV_DC_MATCHER, wiz_dc)
    ):
        sys.exit(
            f"[ERROR] {wiz_dc} is not a valid Wiz Datacenter. Please check and try again. Exiting..."
        )

    return wiz_dc


@_generic_exception_handler
def config_parser() -> tuple:
    """
    Parse the system for a config file OR environment variables for the script to use
    The default behavior is to try a config file first, and then defer to environment variables

    Parameters:
        - none

    Returns:
        - WIZ_DATACENTER: the wiz datacenter pulled from the config file or the local environment variables
        - WIZ_CLIENT_ID: the wiz client id pulled from the config file or the local environment variables
        - WIZ_CLIENT_SECRET: the wiz client secret pulled from the config file or the local environment variables
        - WIZ_AUTH_URL: the wiz client id pulled from the config file or the local environment variables
        - API_URL: the wiz API URL
    """

    wiz_client_id, wiz_client_secret, wiz_auth_url, api_url = "", "", "", ""

    try:
        with open(f"{wiz_config_file}", mode="r") as config_file:
            config = json.load(config_file)

            # Extract the values from our dict and assign to vars
            api_url, wiz_auth_url, wiz_client_id, wiz_client_secret = itemgetter(
                "wiz_api_url", "wiz_auth_url", "wiz_client_id", "wiz_client_secret"
            )(config)

            # Validate the inputs and get the current Wiz DC back
            wiz_dc = validate_config(
                client_id=wiz_client_id,
                client_secret=wiz_client_secret,
                auth_url=wiz_auth_url,
                api_url=api_url,
            )

    except FileNotFoundError:
        pass

        try:
            wiz_client_id = str(os.getenv("wiz_client_id"))
            wiz_client_secret = str(os.getenv("wiz_client_secret"))
            wiz_auth_url = str(os.getenv("wiz_auth_url"))
            api_url = str(os.getenv("wiz_api_url"))

            # Validate the inputs and get the current Wiz DC back
            wiz_dc = validate_config(
                client_id=wiz_client_id,
                client_secret=wiz_client_secret,
                auth_url=wiz_auth_url,
                api_url=api_url,
            )

        except Exception:
            sys.exit(
                f"[ERROR] Unable to find one or more Wiz environment variables. Please check them and try again."
            )

    return (
        wiz_dc,
        wiz_client_id,
        wiz_client_secret,
        wiz_auth_url,
        api_url,
    )


@_generic_exception_handler
def set_socket_blocking() -> Any:
    """
    Sets blocking for http sockets so that no other internal libs
    can overwrite the defalt socket timeout

    Parameters:
        - none

    Returns:
        - none
    """
    setblocking_func = socket.socket.setblocking

    def wrapper(self: Any, flag: Any) -> Any:
        if flag:
            # prohibit timeout reset
            timeout = socket.getdefaulttimeout()
            if timeout:
                self.settimeout(timeout)
            else:
                setblocking_func(self, flag)
        else:
            setblocking_func(self, flag)

    wrapper.__doc__ = setblocking_func.__doc__
    wrapper.__name__ = setblocking_func.__name__
    return wrapper


############### End Helpers ###############

############### Start Script Config CONSTS ###############
# Colors
BLUE = "\033[94m"
GREEN = "\033[92m"
END = "\033[0m"
SPINNER_COLORS = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]
# Script info
SCRIPT_NAME = "Get Wiz Issues"
SCRIPT_DESCRIPTION = f"""{BLUE}DESCRIPTION:{END}
 - This script will parse the Wiz issues table
 - and write out to a CSV file"""
# Please do not adjust any of the settings below
(
    WIZ_DATACENTER,
    WIZ_CLIENT_ID,
    WIZ_CLIENT_SECRET,
    WIZ_AUTH_URL,
    API_URL,
) = config_parser()
# Blank strings will be populated when parsing config files or env vars
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
HEADERS = {"Content-Type": "application/json"}
MAX_QUERY_RETRIES = 5
############### End Script Config CONSTS ###############

############### Start Queries and Vars ###############
issues_query = """
query IssuesTable(
    $filterBy: IssueFilters
    $first: Int
    $after: String
    $orderBy: IssueOrder
  ) {
    issues: issuesV2(
      filterBy: $filterBy
      first: $first
      after: $after
      orderBy: $orderBy
    ) {
      nodes {
        ...IssueDetails
      }
      pageInfo {
        hasNextPage
        endCursor
      }
      totalCount
    }
  }
  
  fragment IssueDetails on Issue {
    id
    type
    control {
      id
      name
      description
      severity
      type
      query
      enabled
      enabledForLBI
      enabledForMBI
      enabledForHBI
      enabledForUnattributed
      securitySubCategories {
        id
        category {
          id
        }
      }
      sourceCloudConfigurationRule {
        id
        name
      }
      createdBy {
        id
        name
        email
      }
      serviceTickets {
        ...ControlServiceTicket
      }
    }
    sourceRule {
      ...SourceRuleFields
    }
    createdAt
    updatedAt
    projects {
      id
      name
      slug
      isFolder
      businessUnit
      riskProfile {
        businessImpact
      }
    }
    status
    severity
    entity {
      id
      name
      type
    }
    resolutionReason
    entitySnapshot {
      id
      type
      name
      cloudPlatform
      region
      subscriptionName
      subscriptionId
      subscriptionExternalId
      subscriptionTags
      nativeType
      kubernetesClusterId
      kubernetesClusterName
      kubernetesNamespaceName
      containerServiceId
      containerServiceName
    }
    notes {
      id
      text
    }
    serviceTickets {
      id
      externalId
      name
      url
    }
  }

  
  fragment ControlServiceTicket on ServiceTicket {
    id
    externalId
    name
    url
    project {
      id
      name
    }
    integration {
      id
      type
      name
    }
  }

  
  fragment SourceRuleFields on IssueSourceRule {
    ... on CloudConfigurationRule {
      id
      name
      description
      subjectEntityType
      securitySubCategories {
        id
        title
        category {
          id
          name
          framework {
            id
            name
            description
            enabled
          }
        }
      }
      control {
        id
      }
    }
    ... on CloudEventRule {
      id
      name
      description
      severity
      builtin
      generateIssues
      generateFindings
      enabled
      sourceType
      subCategories {
        id
        title
        category {
          id
          name
          framework {
            id
            name
            description
            enabled
          }
        }
      }
    }
    ... on Control {
      id
      name
      query
      type
      enabled
      enabledForHBI
      enabledForLBI
      enabledForMBI
      enabledForUnattributed
      controlDescription: description
      securitySubCategories {
        id
        title
        category {
          id
          name
          framework {
            id
            name
            description
            enabled
          }
        }
      }
    }
  }
"""

issues_query_variables = {
    "first": 500,
    "filterBy": {
        "status": ["OPEN", "IN_PROGRESS"],
    },
    "orderBy": {"field": "SEVERITY", "direction": "DESC"},
    "quick": False,
    "fetchTotalCount": True,
}
############### End Queries and Vars ###############


############### Start functions ###############
@_generic_exception_handler
def query_wiz_api(query: str, variables: dict) -> dict:
    """
    Query the WIZ API for the given query data schema
    Parameters:
        - query: the query or mutation we want to run
        - variables: the variables to be passed with the query or mutation
    Returns:
        - result: a json representation of the request object
    """

    # Init counters for retries, backoff
    retries = 0
    backoff = 1

    response = requests.post(
        url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
    )

    code = response.status_code

    # Handle retries, and exponential backoff logic
    while code != requests.codes.ok:
        # Increment backoff counter, 5 max retries doubling the backoff timer each retry
        # Retries look like 1, 2, 4, 16, 32
        backoff = backoff * 2
        if retries >= MAX_QUERY_RETRIES:
            raise Exception(
                f"[ERROR] Exceeded the maximum number of retries [{response.status_code}] - {response.text}"
            )

        if code == requests.codes.unauthorized or code == requests.codes.forbidden:
            raise Exception(
                f"[ERROR] Authenticating to Wiz [{response.status_code}] - {response.text}"
            )
        if code == requests.codes.not_found:
            raise Exception(f"[ERROR] Unknown error [{response.status_code}]")

        if backoff != 0:
            print(f"\n└─ Backoff triggered, waiting {backoff}s and retrying.")

        time.sleep(backoff)

        response = requests.post(
            url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
        )
        code = response.status_code
        retries += 1

    # Catch edge case where we get a valid response but empty response body
    if not response:
        time.sleep(backoff)
        response = requests.post(
            url=API_URL, json={"variables": variables, "query": query}, headers=HEADERS
        )
        raise Exception(f"\n API returned no data or emtpy data set. Retrying.")

    response_json = response.json()

    if response_json.get("errors"):
        errors = response_json.get("errors")[0]
        raise Exception(
            f'\n └─ MESSAGE: {errors["message"]}, CODE: {errors["extensions"]["code"]}'
        )

    if response_json.get("code") == "DOWNSTREAM_SERVICE_ERROR":
        errors = response_json.get("errors")
        request_id = errors["message"].partition("request id: ")[2]

        raise Exception(
            f" \n └─ [ERROR] - DOWNSTREAM_SERVICE_ERROR - request id: {request_id}"
        )

    return response_json


@_generic_exception_handler
def request_wiz_api_token(auth_url: str, client_id: str, client_secret: str) -> None:
    """
    Request a token to be used to authenticate against the wiz API

    Parameters:
        - client_id: the wiz client ID
        - client_secret: the wiz secret

    Returns:
        - TOKEN: A session token
    """
    audience = (
        "wiz-api" if "auth.app" in auth_url or "auth.gov" in auth_url else "beyond-api"
    )

    auth_payload = {
        "grant_type": "client_credentials",
        "audience": audience,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    # Initliaze a timer
    func_time = Timer("+ Requesting Wiz API token")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # Request token from the Wiz API
        response = requests.post(
            url=auth_url, headers=HEADERS_AUTH, data=auth_payload, timeout=None
        )

        if response.status_code != requests.codes.ok:
            raise Exception(
                f"Error authenticating to Wiz {response.status_code} - {response.text}"
            )

        response_json = response.json()

        response.close()

        TOKEN = response_json.get("access_token")

        if not TOKEN:
            raise Exception(
                f'Could not retrieve token from Wiz: {response_json.get("message")}'
            )

        HEADERS["Authorization"] = "Bearer " + TOKEN

    print(func_time, "\n└─ DONE: Received API token from Wiz.")


@_generic_exception_handler
def get_api_result() -> list:
    """
    A wrapper around the query_wiz_api function
    That fetches the cloud controls for the tenant

    Parameters:
        - none

    Returns:
        - df: a pandas dataframe
    """

    # Initliaze a timer
    func_time = Timer("Fetching Issues from Wiz")

    query_key = "issues"

    with yaspin(text=func_time, color="white"):
        # Query the wiz API
        result = query_wiz_api(query=issues_query, variables=issues_query_variables)

        # Get the data back from each page
        # Each data item is a list of dicts, so append to the list

        df = pd.json_normalize(result["data"][query_key]["nodes"], sep="_")

        page_info = result["data"][query_key]["pageInfo"]

        # Count starting at 1 because we always sent at least 1 page
        page_count = 1

        # Continue querying until we have no pages left
        while page_info["hasNextPage"]:
            # Increment page count with each page
            page_count += 1

            # Advance the cursor
            issues_query_variables["after"] = page_info["endCursor"]

            # Query the API, now with a new after value
            result = query_wiz_api(query=issues_query, variables=issues_query_variables)

            df = pd.concat(
                [
                    df,
                    pd.json_normalize(result["data"][query_key]["nodes"], sep="_"),
                ]
            )

            page_info = result["data"][query_key]["pageInfo"]

    print(
        func_time,
        f'\n└─ DONE: Got {GREEN}{page_count}{END} pages containing {GREEN}{result["data"][query_key]["totalCount"]}{END} results',
    )

    return df


############### End functions ###############


def main() -> None:
    print_logo()

    # Set default socket timeout to 20 seconds
    socket.setdefaulttimeout(20)

    # Set blocking to prevent overrides of socket timeout
    # docs: https://docs.python.org/3/library/socket.html#socket-timeouts
    socket.socket.setblocking = set_socket_blocking()

    # Request the Wiz API token, token life is 1440 mins
    request_wiz_api_token(
        auth_url=WIZ_AUTH_URL, client_id=WIZ_CLIENT_ID, client_secret=WIZ_CLIENT_SECRET
    )

    # Get the issues from Wiz
    issues = get_api_result()

    # Get timezone information in UTC
    timestamp_now = f"{datetime.now(timezone.utc)}Z".replace(" ", "T").replace(
        "+00:00", ""
    )

    # Generate a timestamped file name
    timestamped_fname = f"{csv_fname}-{timestamp_now}.csv"

    func_time = Timer(f"+ Writing results to file")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # any columns you want to exclude from the CSV
        # df.loc[:, df.columns != ""]
        issues.to_csv(timestamped_fname, encoding="utf-8")

    print(
        func_time,
        f"\n└─ DONE: Wrote data to file:\n└── {GREEN}{timestamped_fname}{END}",
    )

    end_time = datetime.now()

    total_elapsed_time = (
        f"{round((end_time - start_time).total_seconds(),1)}"
        if (end_time - start_time).total_seconds() < 60
        # round rounds down by default, so we include a remainder in the calculation to force
        # a round up in the minutes calculation withouth having to include an additional library
        else f"{round(((end_time - start_time).total_seconds() // 60 + ((end_time - start_time).total_seconds()% 60 > 0)))}:{round(((end_time - start_time).total_seconds()% 60),1)}"
    )

    print(f"+ Script Finished\n└─ Total script elapsed time: {total_elapsed_time}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n+ Ctrl+C interrupt received. Exiting.")
        pass
