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
from hashlib import sha256
from sys import exit
from time import sleep

import chromedriver_autoinstaller
import requests
from bs4 import BeautifulSoup
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver

from mit_dk_configuration import mitid_username, tokens_filename

chromedriver_autoinstaller.install()


def random_string(size):
    letters = (
        string.ascii_lowercase
        + string.ascii_uppercase
        + string.digits
        + string.punctuation
        + string.whitespace
    )
    random_string = "".join(secrets.choice(letters) for i in range(size))
    encoded_string = random_string.encode(encoding="ascii")
    url_safe_string = base64.urlsafe_b64encode(encoded_string).decode()
    url_safe_string_no_padding = url_safe_string.replace("=", "")
    return url_safe_string_no_padding


def save_tokens(response):
    with open(tokens_filename, "wt", encoding="utf8") as token_file:
        token_file.write(response)


def get_user_choice(options):
    """Get user choice from a list of options and return the chosen option"""
    while True:
        try:
            choice = int(input("Enter the number corresponding to your choice: "))
            if 1 <= choice <= len(options):
                return options[choice - 1]
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def handle_login_options(driver):
    """
    If presented with multiple identity options, show them.
    This is relevant for users within organizations and/or with multiple MitID accounts.
    """
    login_options = driver.find_elements(By.CLASS_NAME, "list-link")

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

    # if not args.identity_name:
    print("Please choose an identity to login as.")
    identity_choice = get_user_choice(login_options)
    identity_choice.click()


def submit_username(driver, username):
    """Submits username to MitID login form and waits for success indicator."""
    counter = 0
    while True:
        counter += 1

        # Wait 10*3 seconds for element indicating submission success
        if counter > 10:
            print("ERROR: Timeout waiting for submission response. Exiting.")
            driver.quit()
            exit()

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
        sleep(3)


def wait_for_approval(driver):
    """Waits for approval from user interaction in MitID app."""
    print("Please open the MitID app and approve the login request.")
    try:
        # Wait 120 seconds for app interaction
        wait = WebDriverWait(driver, 120)
        login_url = driver.current_url
        wait.until(EC.url_changes(login_url))
    except Exception as e:
        print(f"ERROR: Timeout waiting for app approval: {e}")
        driver.quit()
        exit()


def init_login(driver, username):
    """Navigates to MitID login page and waits for username field to load."""
    login = driver.get(login_url)
    print("Waiting for MitID login page to load...")
    WebDriverWait(driver, 30).until(
        EC.presence_of_element_located((By.CLASS_NAME, "mitid-core-user__user-id"))
    )
    print("MitID login page loaded. Submitting username...")

    # Username field is the default active element. Send username and submit.
    username_field = driver.switch_to.active_element
    username_field.send_keys(username)
    username_field.send_keys(Keys.RETURN)


state = random_string(23)
nonce = random_string(93)
code_verifier = random_string(93)
code_challenge = (
    base64.urlsafe_b64encode(sha256(code_verifier.encode("ascii")).digest())
    .decode()
    .replace("=", "")
)
redirect_url = "https://post.mit.dk/main"
login_url = (
    "https://gateway.mit.dk/view/client/authorization/login?client_id=view-client-id-mobile-prod-1-id&response_type=code&scope=openid&state="
    + state
    + "&code_challenge="
    + code_challenge
    + "&code_challenge_method=S256&response_mode=query&nonce="
    + nonce
    + "&redirect_uri="
    + redirect_url
    + "&deviceName=digitalpost-utilities&deviceId=pc&lang=en_US"
)

# Set up Chrome driver options
options = webdriver.ChromeOptions()
options.add_argument("--log-level=3")
options.add_argument("--headless")

# Disable webdriver flags
options.add_argument("--disable-blink-features")
options.add_argument("--disable-blink-features=AutomationControlled")
driver = webdriver.Chrome(chrome_options=options)

# Change the property value of the `navigator` for webdriver to undefined
# This is to prevent mit.dk from detecting the use of headless Chrome
driver.execute_script(
    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
)


# Initiate login process
try:
    init_login(driver, mitid_username)
    submit_username(driver, args.username)
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
    exit()

# Wait for oauth process and redirection to post.mit.dk
wait = WebDriverWait(driver, 30)
wait.until(EC.url_to_be(redirect_url))
print("Login successful.")
print("Getting your tokens and saving them. This may take a while...")

session = requests.Session()
samlresponse = ""


def get_saml_response(request):
    if request.response.headers["content-encoding"] == "gzip":
        response = gzip.decompress(request.response.body).decode()
    else:
        response = request.response.body.decode()
    soup = BeautifulSoup(response, "html.parser")
    input = soup.find_all("input", {"name": "SAMLResponse"})
    samlresponse = input[0]["value"]
    return samlresponse


for request in driver.requests:
    session.cookies.set("cookiecheck", "Test", domain="nemlog-in.mitid.dk")
    session.cookies.set("loginMethod", "noeglekort", domain="nemlog-in.mitid.dk")
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
            headers_string = str(request.response.headers)
            headers_list = headers_string.split("\n")
            for header in headers_list:
                if "set-cookie" in header:
                    cookie_string = header.replace("set-cookie: ", "")
                    cookie = http.cookies.BaseCookie(cookie_string)
                    for key in cookie.keys():
                        # Requests is picky about dashes in cookie expiration dates. Fix.
                        if "expires" in cookie[key]:
                            expiry = cookie[key]["expires"]
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
            samlresponse = get_saml_response(request)
        # User has only personal login and uses mitid
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/mitid"
            and request.response.status_code == 200
        ):
            samlresponse = get_saml_response(request)
        # User has only personal login and uses key card
        if (
            request.method == "POST"
            and request.url == "https://nemlog-in.mitid.dk/login.aspx/noeglekort"
            and request.response.status_code == 200
        ):
            samlresponse = get_saml_response(request)

driver.close()
if samlresponse:
    request_code_part_one = session.post(
        "https://gateway.digitalpost.dk/auth/s9/mit-dk-nemlogin/ssoack",
        data={"SAMLResponse": samlresponse},
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
        + redirect_url
        + "&client_id=view-client-id-mobile-prod-1-id&code="
        + code
        + "&code_verifier="
        + code_verifier
    )
    request_tokens = session.post(token_url)
    save_tokens(request_tokens.text)
    print("Tokens successfully saved.")
    print(f"Tokens saved to {tokens_filename}.")
else:
    print(
        "Something went wrong during login with MitID or NemID. Did you complete the login procedure?"
    )
