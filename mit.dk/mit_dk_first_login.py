"""
Logs in to mit.dk og saves tokens needed for further requests.
Method from https://github.com/dk/Net-MitDK/. Thank you.
"""
import base64
import gzip
import http.cookies
import json
import re
import secrets
import string
import sys
from hashlib import sha256
from time import sleep
from typing import List, Optional, Dict

try:
    import tomllib
except ImportError:
    print("This script requires at least Python 3.11 to run.")
    sys.exit(1)

import requests
from bs4 import BeautifulSoup
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from seleniumwire import webdriver


def random_string(size):
    """Generate a random string of letters, digits, punctuation and whitespace."""
    letters = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
        + string.whitespace
    )
    generated_string = "".join(secrets.choice(letters) for i in range(size))
    encoded_string = generated_string.encode(encoding="ascii")
    url_safe_string = base64.urlsafe_b64encode(encoded_string).decode()
    url_safe_string_no_padding = url_safe_string.replace("=", "")
    return url_safe_string_no_padding


# Load variables from config file
with open("mit_dk_config.toml", "rb") as f:
    try:
        config = tomllib.load(f)
        username = config["mitid"]["username"]
        token_path = config["files"]["tokens"]

        try:
            identity_patterns = config["mitid"]["identity_patterns"]
        except KeyError:
            # If no identity patterns are specified, match all identities
            identity_patterns = []

    except (tomllib.TOMLDecodeError, KeyError) as error:
        print(f"Error loading configuration file: {error}")
        sys.exit(1)


SAML_RESPONSE = ""
state = random_string(23)
nonce = random_string(93)
code_verifier = random_string(93)
code_challenge = (
    base64.urlsafe_b64encode(sha256(code_verifier.encode("ascii")).digest())
    .decode()
    .replace("=", "")
)
REDIRECT_URL = "https://post.mit.dk/main"
login_url = (
    "https://gateway.mit.dk/view/client/authorization/login"
    + "?client_id=view-client-id-mobile-prod-1-id"
    + "&response_type=code"
    + "&scope=openid"
    + f"&state={state}"
    + f"&code_challenge={code_challenge}"
    + "&code_challenge_method=S256"
    + "&response_mode=query"
    + f"&nonce={nonce}"
    + f"&redirect_uri={REDIRECT_URL}"
    + "&deviceName=digitalpost-utilities&deviceId=pc&lang=en_US"
)

# Set up Chrome driver options
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--log-level=3")
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("start-maximized")

# Disable webdriver tells
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option("useAutomationExtension", False)
chrome_options.add_argument("--disable-blink-features")
chrome_options.add_argument("--disable-blink-features=AutomationControlled")
driver = webdriver.Chrome(chrome_options=chrome_options)

# Change the property value of the `navigator` for webdriver to undefined
# This is to prevent mit.dk from detecting the use of headless Chrome
driver.execute_script(
    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
)
# Change the `userAgent` property
driver.execute_cdp_cmd(
    "Network.setUserAgentOverride",
    {
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/83.0.4103.53 Safari/537.36"
    },
)


def save_tokens(response: str) -> None:
    """Save tokens from response to file."""
    with open(token_path, "wt", encoding="utf8") as token_file:
        token_file.write(response)


def get_user_choice(options):
    """Get user choice from a list of options and return the chosen option"""
    while True:
        try:
            choice = int(input("Enter the number corresponding to your choice: "))
            if 1 <= choice <= len(options):
                return options[choice - 1]

            print("Invalid choice. Please enter a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def match_identity(identities: List[Dict[str, str]]) -> Optional[int]:
    """Find the first identity in the provided list that matches all the 'identity_patterns'
    specified in the configuration under 'mitid' section.

    Args:
        identities (list): A list of dictionaries containing 'name' and 'type' keys.

    Returns:
        int: The index of the matched identity in the list or None if no match is found.
    """

    def matches_all_patterns(string_to_search: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if not re.search(pattern, string_to_search):
                return False
        return True

    # Find the first identity that matches all patterns.
    # Searches name, organization and type. (name and organization are
    # concatenated in name field)
    matched_identity_index = None
    for index, identity in enumerate(identities):
        identity_str = f"{identity['name']} {identity['type']}".strip()
        if matches_all_patterns(identity_str, identity_patterns):
            matched_identity_index = index
            break

    return matched_identity_index


def handle_login_options() -> None:
    """Handle the login options for users with multiple MitID accounts or organizational accounts.

    This function will:
    1. Display the available identity options.
    2. If identity patterns are configured in the configuration file, try to match them.
    3. If no identity matches the configured patterns, select the first identity option.
        Otherwise, use the matched identity to log in.

    Returns:
        None
    """
    login_options = driver.find_elements(By.CLASS_NAME, "list-link")
    identities_for_matching = []
    print("\nThe following login options were found:\n")
    for i, identity in enumerate(login_options):
        # Decode and parse (base64(json)) from attribute
        identity_data_b64 = identity.get_attribute("data-loginoptions").encode("utf-8")
        identity_data = json.loads(base64.b64decode(identity_data_b64))

        # Print identity names and types
        identity_name = identity_data["signingIdentityName"]
        identity_type = identity_data["type"]
        if "organizationName" in identity_data:
            org_name = identity_data["organizationName"]
            identity_name += f"\n\t\t{org_name}"
        print(f"\t{i+1}: {identity_name}\n\t\tType: {identity_type}\n")
        identities_for_matching.append({"name": identity_name, "type": identity_type})

    if not identity_patterns:
        print("No identity patterns configured. Please choose an identity to login as.")
        identity_choice = get_user_choice(login_options)
        identity_choice.click()
        return

    # If identity patterns are configured, try to match them
    matched_identity = match_identity(identities_for_matching)
    if matched_identity is None:
        print(
            "No identity matched the configured patterns. Selecting first identity on the list."
        )
        login_options[0].click()
        return
    print(
        f"Patterns matched identity: {matched_identity+1}: "
        f"{identities_for_matching[matched_identity]['name']}"
    )
    print("Proceeding with login...")
    login_options[matched_identity].click()


def submit_username() -> None:
    """Submit the username to the MitID login form and wait for the success indicator.

    This function will:
    1. Enter the provided username into the active username field.
    2. Submit the form.
    3. Wait for a success tooltip indicating that the MitID app should be used for approval.
    4. In case of a timeout, exit the script and close the browser.

    Returns:
        None
    """
    print("Submitting username...")
    # Username field is the default active element. Type username and submit.
    username_field = driver.switch_to.active_element
    username_field.send_keys(username)
    username_field.send_keys(Keys.RETURN)
    counter = 0
    while True:
        counter += 1

        # Wait 10*4 seconds for element indicating submission success
        if counter > 10:
            print("ERROR: Timeout waiting for submission response. Exiting.")
            driver.quit()
            sys.exit()

        print("Waiting for submission response...")
        tooltip = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.CLASS_NAME, "mitid-tooltip__text "))
        )
        tooltip_success_strings = [
            "Åbn MitID app og godkend",
            "Open MitID app and approve",
        ]
        if any(tooltip.text == string for string in tooltip_success_strings):
            break
        sleep(4)


def wait_for_approval() -> None:
    """Wait for the user to approve the login request in the MitID app.

    This function will prompt the user to open the MitID app and approve the login request.
    It will wait for up to 120 seconds for the user to complete the approval process.
    In case of a timeout, exit the script and close the browser.

    Returns:
        None
    """
    print("Please open the MitID app and approve the login request.")
    try:
        # Wait 120 seconds for app interaction
        approval_wait = WebDriverWait(driver, 120)
        mitid_form_url = driver.current_url
        approval_wait.until(EC.url_changes(mitid_form_url))
    except TimeoutException as wait_error:
        print(f"ERROR: Timeout waiting for app approval: {wait_error}")
        driver.quit()
        sys.exit()


def init_login() -> None:
    """Initialize the MitID login process by navigating
    to the login page, waiting for username field to load.

    This function will:
    1. Navigate to the MitID login page using the provided WebDriver instance.
    2. Wait for up to 30 seconds for the username field to be present on the page.

    Returns:
        None
    """
    driver.get(login_url)
    print("Waiting for MitID login page to load...")
    WebDriverWait(driver, 30).until(
        EC.presence_of_element_located((By.CLASS_NAME, "mitid-core-user__user-id"))
    )


def get_saml_response(mitid_request) -> str:
    """Extract the SAMLResponse from the MitID login form.

    This function will:
    1. Check if the response body is gzip-encoded.
    2. If gzip-encoded, decompress the response body; otherwise, decode it directly.
    3. Parse the HTML using BeautifulSoup and locate the 'SAMLResponse' input element.
    4. Extract and return the value of the 'SAMLResponse' input element.

    Args:
        mitid_request (Request): A request object containing the MitID login form response.

    Returns:
        str: The extracted SAMLResponse value from the login form.
    """
    if mitid_request.response.headers["content-encoding"] == "gzip":
        response = gzip.decompress(mitid_request.response.body).decode()
    else:
        response = mitid_request.response.body.decode()
    soup = BeautifulSoup(response, "html.parser")
    input_element = soup.find_all("input", {"name": "SAMLResponse"})
    samlresponse = input_element[0]["value"]
    return samlresponse


def process_cookies(session, request) -> None:
    """Extracts and updates session cookies from the response headers of the given request.

    Args:
        session: A session object to update with the extracted cookies.
        request: The request whose response headers contain the cookies.

    Returns:
        None
    """
    if request.response:
        headers_string = str(request.response.headers)
        headers_list = headers_string.split("\n")

        for header in headers_list:
            if "set-cookie" not in header:
                continue

            cookie_string = header.replace("set-cookie: ", "")
            cookie = http.cookies.BaseCookie(cookie_string)

            for key, value in cookie.items():
                if "expires" in value:
                    expiry = value["expires"]
                    if expiry:
                        expiry_list = list(expiry)
                        expiry_list[7] = "-"
                        expiry_list[11] = "-"
                        cookie[key]["expires"] = "".join(expiry_list)
            session.cookies.update(cookie)


def find_saml_response(driver_requests) -> str:
    """Find the SAMLResponse from the driver's requests based on specific conditions.

    This function iterates through the provided driver_requests and looks for a request
    that meets the following conditions:
    1. The request method is POST.
    2. The request URL matches one of the following:
        - "https://nemlog-in.mitid.dk/LoginOption.aspx"
        - "https://nemlog-in.mitid.dk/login.aspx/mitid"
        - "https://nemlog-in.mitid.dk/login.aspx/noeglekort"
    3. The request's response status code is 200.

    If a request meeting these conditions is found, the SAMLResponse is extracted
    using the `get_saml_response` function.

    Args:
        driver_requests (list): A list of request objects from the Selenium WebDriver.

    Returns:
        str: The extracted SAMLResponse value, or None if no matching request is found.
    """
    saml_response = ""
    for request in driver_requests:
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/LoginOption.aspx"
            and request.response.status_code == 200
        ):
            saml_response = get_saml_response(request)
        elif (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/mitid"
            and request.response.status_code == 200
        ):
            saml_response = get_saml_response(request)
        elif (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/noeglekort"
            and request.response.status_code == 200
        ):
            saml_response = get_saml_response(request)
    return saml_response


def set_initial_cookies(session) -> None:
    """Set initial cookies required for the login process in the given session.

    Args:
        session (requests.Session): A requests Session object that holds cookies.
    """
    session.cookies.set("cookiecheck", "Test", domain="nemlog-in.mitid.dk")
    session.cookies.set("loginMethod", "noeglekort", domain="nemlog-in.mitid.dk")


def process_requests(session) -> str:
    """Process requests from the Selenium WebDriver to extract cookies and find the SAMLResponse.

    This function sets the initial cookies, iterates through the driver's requests,
    processes cookies from the requests, and attempts to find the SAMLResponse using
    the `find_saml_response` function.

    Args:
        session (requests.Session): A requests Session object that holds cookies.

    Returns:
        str: The extracted SAMLResponse value, or None if no matching request is found.
    """
    driver_requests = driver.requests

    set_initial_cookies(session)

    for request in driver_requests:
        process_cookies(session, request)

    saml_response = find_saml_response(driver_requests)
    return saml_response


def process_saml_response(session, saml_response: str) -> str:
    """Posts the SAML response to the Digital Post gateway and returns the redirect location.

    Args:
        session (Union[bytes, str]): A session to use for sending the POST request.
        saml_response (str): The SAMLResponse value to post to the gateway.

    Returns:
        str: (URL) The value of the Location header in the response.
    """
    request_code_part_one = session.post(
        "https://gateway.digitalpost.dk/auth/s9/mit-dk-nemlogin/ssoack",
        data={"SAMLResponse": saml_response},
        allow_redirects=False,
    )
    return request_code_part_one.headers["Location"]


def process_redirects(session, redirect_location: str) -> str:
    """Processes a redirect by sending a GET request to the given location
    and returning a location header.

    Args:
        session (Union[bytes, str]): A session to use for sending the GET request.
        redirect_location (str): The URL from the Location header in the previous response.

    Returns:
        str: The value of the Location header in the response.
    """
    request = session.get(redirect_location, allow_redirects=False)
    return request.headers["Location"]


def extract_authorization_code(redirect_location: str) -> str:
    """Extracts and returns an authorization code from a redirect URL."""
    code_start = redirect_location.index("code=") + 5
    code_end = redirect_location.index("&", code_start)
    return redirect_location[code_start:code_end]


def request_tokens(session, auth_code: str):
    """Requests and returns access and refresh tokens,
    using the given authorization code, code verifier, and redirect URL."""
    token_url = (
        "https://gateway.mit.dk/view/client/authorization/token"
        "?grant_type=authorization_code&redirect_uri="
        + REDIRECT_URL
        + "&client_id=view-client-id-mobile-prod-1-id&code="
        + auth_code
        + "&code_verifier="
        + code_verifier
    )
    return session.post(token_url)


def handle_post_login(
    session,
    saml_response: str,
) -> None:
    """
    Handles the post-login process after successful MitID or NemID authentication.

    This function performs a series of HTTP requests and redirects to obtain
    the authorization code. It then requests access and refresh tokens using
    the authorization code and saves them to the specified file.

    Args:
        session (requests.Session): The requests session instance for making HTTP requests.
        saml_response (str): The SAMLResponse extracted from the login process.
        redirect_url (str): The redirect URL used in the OAuth2 authorization process.

    Returns:
        None
    """
    driver.close()
    if saml_response:
        redirect_location_1 = process_saml_response(session, saml_response)
        redirect_location_2 = process_redirects(session, redirect_location_1)
        redirect_location_3 = process_redirects(session, redirect_location_2)
        authorization_code = extract_authorization_code(redirect_location_3)
        token_response = request_tokens(session, authorization_code)
        save_tokens(token_response.text)
        print("Tokens successfully saved.")
        print(f"Tokens saved to {config['files']['tokens']}.")
    else:
        print(
            "Something went wrong during login with MitID or NemID. "
            "Did you complete the login procedure?"
        )


def main():
    """Initiates the MitID login process, submits the username, and waits for approval.
    Handles login options if presented with multiple identities.
    Waits for OAuth process completion and redirection to post.mit.dk.
    Retrieves and saves tokens for later use.

    This function uses global variables and settings from the configuration file
    to perform the login process.
    """
    try:
        print("Starting login process...")
        init_login()
        submit_username()
        wait_for_approval()

        # Give time for potential redirects
        try:
            wait = WebDriverWait(driver, 10)
            wait.until(EC.url_changes(login_url))
        except TimeoutException:
            pass

        if "LoginOption.aspx" in driver.current_url:
            handle_login_options()

    except Exception as login_error:
        print("ERROR: Failed during login")
        driver.quit()
        raise login_error

    # Wait for oauth process and redirection to post.mit.dk
    wait = WebDriverWait(driver, 30)
    wait.until(EC.url_to_be(REDIRECT_URL))
    print("Login successful.")
    print("Getting your tokens and saving them. This may take a while...")

    session = requests.Session()

    saml_response = process_requests(session)
    handle_post_login(session, saml_response)


if __name__ == "__main__":
    main()
