"""
Logs in to mit.dk og saves tokens needed for further requests.
Method from https://github.com/dk/Net-MitDK/. Thank you.
"""
import base64
import gzip
import http.cookies
import json
import secrets
import string
import tomllib
from hashlib import sha256
from time import sleep
import sys

import requests
from bs4 import BeautifulSoup
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver

# Load variables from config file
with open("mit_dk_config.toml", "rb") as f:
    config = tomllib.load(f)


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


def save_tokens(response):
    """Save tokens from response to file."""
    with open(config["files"]["tokens"], "wt", encoding="utf8") as token_file:
        token_file.write(response)


def get_user_choice(options):
    """Get user choice from a list of options and return the chosen option"""
    while True:
        try:
            choice = int(
                input("Enter the number corresponding to your choice: "))
            if 1 <= choice <= len(options):
                return options[choice - 1]

            print("Invalid choice. Please enter a number from the list.")

        except ValueError:
            print("Invalid input. Please enter a number.")


def handle_login_options(chrome_driver):
    """
    If presented with multiple identity options, show them.
    This is relevant for users within organizations and/or with multiple MitID accounts.
    """
    login_options = chrome_driver.find_elements(By.CLASS_NAME, "list-link")

    print("\nThe following login options were found:\n")
    for i, identity in enumerate(login_options):
        # Decode and parse (base64(json)) from attribute
        identity_data_b64 = identity.get_attribute(
            "data-loginoptions").encode("utf-8")
        identity_data = json.loads(base64.b64decode(identity_data_b64))

        # Print identity names and types
        identity_name = identity_data["signingIdentityName"]
        identity_type = identity_data["type"]
        if "organizationName" in identity_data:
            org_name = identity_data["organizationName"]
            identity_name += f"\n\t\t{org_name}"
        print(f"\t{i+1}: {identity_name}\n\t\tType: {identity_type}\n")

    # if not args.identity_name:
    print("Please choose an identity to login as.")
    identity_choice = get_user_choice(login_options)
    identity_choice.click()


def submit_username(chrome_driver, username):
    """Submits username to MitID login form and waits for success indicator."""
    print("Submitting username...")
    # Username field is the default active element. Type username and submit.
    username_field = chrome_driver.switch_to.active_element
    username_field.send_keys(username)
    username_field.send_keys(Keys.RETURN)
    counter = 0
    while True:
        counter += 1

        # Wait 10*3 seconds for element indicating submission success
        if counter > 10:
            print("ERROR: Timeout waiting for submission response. Exiting.")
            chrome_driver.quit()
            sys.exit()

        print("Waiting for submission response...")
        tooltip = WebDriverWait(chrome_driver, 30).until(
            EC.presence_of_element_located(
                (By.CLASS_NAME, "mitid-tooltip__text "))
        )
        tooltip_success_strings = [
            "Åbn MitID app og godkend",
            "Open MitID app and approve",
        ]
        if any(tooltip.text == string for string in tooltip_success_strings):
            break
        sleep(3)


def wait_for_approval(chrome_driver):
    """Waits for approval from user interaction in MitID app."""
    print("Please open the MitID app and approve the login request.")
    try:
        # Wait 120 seconds for app interaction
        approval_wait = WebDriverWait(chrome_driver, 120)
        mitid_form_url = chrome_driver.current_url
        approval_wait.until(EC.url_changes(mitid_form_url))
    except Exception as wait_error:
        print(f"ERROR: Timeout waiting for app approval: {wait_error}")
        chrome_driver.quit()
        sys.exit()


def init_login(chrome_driver):
    """Navigates to MitID login page and waits for username field to load."""
    chrome_driver.get(login_url)
    print("Waiting for MitID login page to load...")
    WebDriverWait(chrome_driver, 30).until(
        EC.presence_of_element_located(
            (By.CLASS_NAME, "mitid-core-user__user-id"))
    )


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
    "https://gateway.mit.dk/view/client/authorization/login?client_id=view-client-id-mobile-prod-1-id&response_type=code&scope=openid&state="
    + state
    + "&code_challenge="
    + code_challenge
    + "&code_challenge_method=S256&response_mode=query&nonce="
    + nonce
    + "&redirect_uri="
    + REDIRECT_URL
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
chrome_options.add_experimental_option('useAutomationExtension', False)
chrome_options.add_argument("--disable-blink-features")
chrome_options.add_argument("--disable-blink-features=AutomationControlled")
driver = webdriver.Chrome(chrome_options=chrome_options)

# Change the property value of the `navigator` for webdriver to undefined
# This is to prevent mit.dk from detecting the use of headless Chrome
driver.execute_script(
    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
)
# Change the `userAgent` property
driver.execute_cdp_cmd('Network.setUserAgentOverride', {"userAgent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.53 Safari/537.36'})


# Initiate login process
try:
    init_login(driver)
    submit_username(driver, config["mitid"]["username"])
    wait_for_approval(driver)

    # Give time for potential redirects
    try:
        wait = WebDriverWait(driver, 10)
        wait.until(EC.url_changes(login_url))
    except TimeoutException:
        pass

    if "LoginOption.aspx" in driver.current_url:
        handle_login_options(driver)

except Exception as e:
    print(f"ERROR: Failed during login: {e}")
    driver.quit()
    sys.exit()

# Wait for oauth process and redirection to post.mit.dk
wait = WebDriverWait(driver, 30)
wait.until(EC.url_to_be(REDIRECT_URL))
print("Login successful.")
print("Getting your tokens and saving them. This may take a while...")

session = requests.Session()
SAML_RESPONSE = ""


def get_saml_response(mitid_request):
    """Extracts SAMLResponse from MitID login form."""
    if request.response.headers["content-encoding"] == "gzip":
        response = gzip.decompress(mitid_request.response.body).decode()
    else:
        response = mitid_request.response.body.decode()
    soup = BeautifulSoup(response, "html.parser")
    input_element = soup.find_all("input", {"name": "SAMLResponse"})
    samlresponse = input_element[0]["value"]
    return samlresponse


for request in driver.requests:
    session.cookies.set("cookiecheck", "Test", domain="nemlog-in.mitid.dk")
    session.cookies.set(
        "loginMethod",
        "noeglekort",
        domain="nemlog-in.mitid.dk")
    for request in driver.requests:
        if (
            "/api/mailboxes" in request.url
            and request.method == "GET"
            and request.response.status_code == 200
        ):
            cookies = request.headers["Cookie"].split("; ")
            for cookie in cookies:
                if "LoggedInBorgerDk" in cookie or "CorrelationId" in cookie:
                    key_value = cookie.split("=")
                    session.cookies.set(
                        key_value[0], key_value[1], domain=".post.borger.dk"
                    )
        if request.response:
            HEADERS_STRING = str(request.response.headers)
            headers_list = HEADERS_STRING.split("\n")
            for header in headers_list:
                if "set-cookie" in header:
                    cookie_string = header.replace("set-cookie: ", "")
                    cookie = http.cookies.BaseCookie(cookie_string)
                    for key, value in cookie.items():
                        # Requests is picky about dashes in cookie expiration
                        # dates. Fix.
                        if "expires" in value:
                            expiry = value["expires"]
                            if expiry:
                                expiry_list = list(expiry)
                                expiry_list[7] = "-"
                                expiry_list[11] = "-"
                                cookie[key]["expires"] = "".join(expiry_list)
                    session.cookies.update(cookie)
        # User has personal and company login
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/LoginOption.aspx"
            and request.response.status_code == 200
        ):
            SAML_RESPONSE = get_saml_response(request)
        # User has only personal login and uses mitid
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/mitid"
            and request.response.status_code == 200
        ):
            SAML_RESPONSE = get_saml_response(request)
        # User has only personal login and uses key card
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/noeglekort"
            and request.response.status_code == 200
        ):
            SAML_RESPONSE = get_saml_response(request)

driver.close()
if SAML_RESPONSE:
    request_code_part_one = session.post(
        "https://gateway.digitalpost.dk/auth/s9/mit-dk-nemlogin/ssoack",
        data={"SAMLResponse": SAML_RESPONSE},
        allow_redirects=False,
    )
    request_code_part_one_redirect_location = request_code_part_one.headers["Location"]
    request_code_part_two = session.get(
        request_code_part_one_redirect_location, allow_redirects=False
    )
    request_code_part_two_redirect_location = request_code_part_two.headers["Location"]
    request_code_part_three = session.get(
        request_code_part_two_redirect_location, allow_redirects=False
    )
    request_code_part_three_redirect_location = request_code_part_three.headers[
        "Location"
    ]
    code_start = request_code_part_three_redirect_location.index("code=") + 5
    code_end = request_code_part_three_redirect_location.index("&", code_start)
    code = request_code_part_three_redirect_location[code_start:code_end]
    token_url = (
        "https://gateway.mit.dk/view/client/authorization/token?grant_type=authorization_code&redirect_uri="
        + REDIRECT_URL
        + "&client_id=view-client-id-mobile-prod-1-id&code="
        + code
        + "&code_verifier="
        + code_verifier
    )
    request_tokens = session.post(token_url)
    save_tokens(request_tokens.text)
    print("Tokens successfully saved.")
    print(f"Tokens saved to {config['files']['tokens']}.")
else:
    print(
        "Something went wrong during login with MitID or NemID. Did you complete the login procedure?"
    )
