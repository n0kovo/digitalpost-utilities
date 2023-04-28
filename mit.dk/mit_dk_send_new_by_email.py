"""
Sends unread messages from mit.dk to an e-mail.
"""
import json
import smtplib  # Sending e-mails
import time
from email.mime.application import \
    MIMEApplication  # Attaching files to e-mails
from email.mime.multipart import MIMEMultipart  # Creating multipart e-mails
from email.mime.text import MIMEText  # Attaching text to e-mails
# For correct encoding of senders with special chars in name:
from email.utils import formataddr
from smtplib import SMTPNotSupportedError, SMTPServerDisconnected

import requests
import yaml  # For parsing YAML config file
from yaml.parser import ParserError
from yaml.reader import ReaderError
from yaml.scanner import ScannerError

with open("mit_dk_config.yaml", "rb") as f:
    try:
        config = yaml.load(f, Loader=yaml.Loader)
    except (ScannerError, ParserError, ReaderError) as error:
        print("Unable to parse YAML config file. Here is the error:")
        print(error)
        exit()


BASE_URL = "https://gateway.mit.dk/view/client/"
session = requests.Session()


def open_tokens(filename):
    """Opens the token file and returns the tokens as a dict."""
    try:
        with open(filename, "r", encoding="utf8") as token_file:
            return json.load(token_file)
    except BaseException:
        return print(
            "Unable to open and parse token file. Did you run mit_dk_first_login.py?"
        )


def revoke_old_tokens(mitid_token, ngdp_token, dpp_refresh_token, ngdp_refresh_token):
    """Revokes old tokens and refresh tokens."""
    endpoint = "authorization/revoke?client_id=view-client-id-mobile-prod-1-id"
    json_data = {
        "dpp": {"token": mitid_token, "token_type_hint": "access_token"},
        "ngdp": {"token": ngdp_token, "token_type_hint": "access_token"},
    }
    revoke_access_tokens = session.post(BASE_URL + endpoint, json=json_data)
    if not revoke_access_tokens.status_code == 200:
        print(
            "Something went wrong when trying to revoke old access tokens. Here is the response:"
        )
        print(revoke_access_tokens.text)
    json_data = {
        "dpp": {"refresh_token": dpp_refresh_token, "token_type_hint": "refresh_token"},
        "ngdp": {
            "refresh_token": ngdp_refresh_token,
            "token_type_hint": "refresh_token",
        },
    }
    revoke_refresh_tokens = session.post(BASE_URL + endpoint, json=json_data)
    if not revoke_refresh_tokens.status_code == 200:
        print(
            "Something went wrong when trying to revoke old refresh tokens. Here is the response:"
        )
        print(revoke_refresh_tokens.text)


def refresh_and_save_tokens(dpp_refresh_token, ngdp_refresh_token):
    """Refreshes the tokens and saves them to the token file."""
    endpoint = "authorization/refresh?client_id=view-client-id-mobile-prod-1-id"
    json_data = {
        "dppRefreshToken": dpp_refresh_token,
        "ngdpRefreshToken": ngdp_refresh_token,
    }
    refresh = session.post(BASE_URL + endpoint, json=json_data)
    if not refresh.status_code == 200:
        print("Something went wrong trying to fetch new tokens.")
    refresh_json = refresh.json()
    if "code" in refresh_json or "status" in refresh_json:
        print("Something went wrong trying to fetch new tokens. Here's the response:")
        print(refresh_json)
        return False

    with open(config["files"]["tokens"], "wt", encoding="utf8") as token_file:
        token_file.write(refresh.text)
    return refresh_json


def get_fresh_tokens_and_revoke_old_tokens():
    """Gets fresh tokens and revokes old tokens."""
    tokens_from_file = open_tokens(config["files"]["tokens"])
    try:
        if "dpp" in tokens_from_file:
            dpp_refresh_token = tokens_from_file["dpp"]["refresh_token"]
            mitdk_token = tokens_from_file["dpp"]["access_token"]
        else:
            dpp_refresh_token = tokens_from_file["refresh_token"]
            mitdk_token = tokens_from_file["access_token"]
        ngdp_refresh_token = tokens_from_file["ngdp"]["refresh_token"]
        ngdp_token = tokens_from_file["ngdp"]["access_token"]
        fresh_tokens = refresh_and_save_tokens(dpp_refresh_token, ngdp_refresh_token)
        if fresh_tokens:
            revoke_old_tokens(
                mitdk_token, ngdp_token, dpp_refresh_token, ngdp_refresh_token
            )
        return fresh_tokens
    except Exception as error:
        print(error)
        print(
            "Unable to find tokens in token file. Try running mit_dk_first_login.py again."
        )
        return False


def get_simple_endpoint(endpoint):
    """Retrieves data from an endpoint and returns it as a dict."""
    tries = 1
    while tries <= 3:
        response = session.get(f"{BASE_URL}{endpoint}")
        try:
            return response.json()
        except BaseException:
            tries += 1
            time.sleep(1)

    if tries == 3:
        print(
            f"Unable to convert response to json when getting endpoint {endpoint} after 3 tries. Here is the response:"
        )
        print(response.text)
        return False


def get_inbox_folders_and_build_query(mailbox_ids):
    """B"""
    endpoint = "folders/query"
    json_data = {"mailboxes": {}}
    for mailbox in mailbox_ids:
        json_data["mailboxes"][mailbox["dataSource"]] = mailbox["mailboxId"]
    tries = 1
    while tries <= 3:
        response = session.post(f"{BASE_URL}{endpoint}", json=json_data)
        try:
            response_json = response.json()
            folders = []
            for folder in response_json["folders"]["INBOX"]:
                folder_info = {
                    "dataSource": folder["dataSource"],
                    "foldersId": [folder["id"]],
                    "mailboxId": folder["mailboxId"],
                    "startIndex": 0,
                }
                folders.append(folder_info)
            return folders
        except BaseException:
            tries += 1
            time.sleep(1)

    if tries == 3:
        print(
            "Unable to convert response to json when getting folders. Here is the response:"
        )
        print(response.text)
        return False


def get_messages(folders):
    tries = 1
    while tries <= 3:
        endpoint = "messages/query"
        json_data = {
            "any": [],
            "folders": folders,
            "size": 20,
            "sortFields": ["receivedDateTime:DESC"],
        }
        response = session.post(BASE_URL + endpoint, json=json_data)
        try:
            return response.json()
        except BaseException:
            tries += 1
            time.sleep(1)
            pass
    if tries == 3:
        print(
            "Unable to convert response to json when getting messages after 3 tries. Here is the response:"
        )
        print(response.text)
        return False


def get_content(message):
    content = []
    endpoint = (
        message["dataSource"]
        + "/mailboxes/"
        + message["mailboxId"]
        + "/messages/"
        + message["id"]
    )
    for document in message["documents"]:
        doc_url = "/documents/" + document["id"]
        for file in document["files"]:
            encoding_format = file["encodingFormat"]
            file_name = file["filename"]
            file_url = "/files/" + file["id"] + "/content"
            file_content = session.get(BASE_URL + endpoint + doc_url + file_url)
            content.append(
                {
                    "file_name": file_name,
                    "encoding_format": encoding_format,
                    "file_content": file_content,
                }
            )
    return content


def mark_as_read(message):
    endpoint = (
        message["dataSource"]
        + "/mailboxes/"
        + message["mailboxId"]
        + "/messages/"
        + message["id"]
    )
    session.headers["If-Match"] = str(message["version"])
    json_data = {"read": True}
    session.patch(BASE_URL + endpoint, json=json_data)

def main():
    MAILSERVER_CONNECT = False
    tokens = get_fresh_tokens_and_revoke_old_tokens()
    if tokens:
        session.headers["mitdkToken"] = tokens["dpp"]["access_token"]
        session.headers["ngdpToken"] = tokens["ngdp"]["access_token"]
        session.headers["platform"] = "web"
        mailboxes = get_simple_endpoint("mailboxes")
        mailbox_ids = []

        for mailboxes in mailboxes["groupedMailboxes"]:
            for mailbox in mailboxes["mailboxes"]:
                mailbox_info = {
                    "dataSource": mailbox["dataSource"],
                    "mailboxId": mailbox["id"],
                }
                mailbox_ids.append(mailbox_info)
        folders = get_inbox_folders_and_build_query(mailbox_ids)
        messages = get_messages(folders)
        server_config = config["email"]["server"]
        email_server = f"{server_config['host']}:{server_config['port']}"
        email_creds = config["email"]["credentials"]
        email_options = config["email"]["options"]

        for message in messages["results"]:
            if message["read"] is False:
                if not MAILSERVER_CONNECT:
                    print(f"Connecting to {email_server}")

                    if server_config["ssl"]:
                        try:
                            server = smtplib.SMTP(f"{email_server}")
                            server.starttls()

                        except SMTPNotSupportedError:
                            print(f"STARTTLS not supported on server")
                            print("Trying to connect without...")

                        except SMTPServerDisconnected:
                            pass

                        server = smtplib.SMTP_SSL(f"{email_server}")
                        server.ehlo()
                    else:
                        server = smtplib.SMTP(f"{email_server}")
                        server.ehlo()

                    server.login(email_creds["username"], email_creds["password"])
                    MAILSERVER_CONNECT = True

                label = message["label"]
                sender = message["sender"]["label"]
                message_content = get_content(message)

                msg = MIMEMultipart("alternative")
                msg["From"] = formataddr((sender, email_options["from"]))
                msg["To"] = email_options["to"]
                msg["Subject"] = "mit.dk: " + label

                for content in message_content:
                    if content["encoding_format"] == "text/plain":
                        body = content["file_content"].text
                        msg.attach(MIMEText(body, "plain"))
                        part = MIMEApplication(content["file_content"].content)
                        part.add_header(
                            "Content-Disposition",
                            "attachment",
                            filename=content["file_name"],
                        )
                        msg.attach(part)
                    elif content["encoding_format"] == "text/html":
                        body = content["file_content"].text
                        msg.attach(MIMEText(body, "html"))
                        part = MIMEApplication(content["file_content"].content)
                        part.add_header(
                            "Content-Disposition",
                            "attachment",
                            filename=content["file_name"],
                        )
                        msg.attach(part)
                    elif (
                        content["encoding_format"] == "application/pdf"
                        or content["encoding_format"] == "text/xml"
                    ):
                        part = MIMEApplication(content["file_content"].content)
                        part.add_header(
                            "Content-Disposition",
                            "attachment",
                            filename=content["file_name"],
                        )
                        msg.attach(part)
                    else:
                        encoding_format = content["encoding_format"]
                        print(f"Ny filtype {encoding_format}")
                        part = MIMEApplication(content["file_content"].content)
                        part.add_header(
                            "Content-Disposition",
                            "attachment",
                            filename=content["file_name"],
                        )
                        msg.attach(part)
                print(f"Sender en mail fra mit.dk fra {sender} med emnet {label}")
                server.sendmail(email_options["from"], email_options["to"], msg.as_string())
                mark_as_read(message)
        if MAILSERVER_CONNECT:
            server.quit()


def lambda_handler(event, context):
    main()


if __name__ == "__main__":
    main()