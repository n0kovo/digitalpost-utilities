"""
Sends unread messages from mit.dk to an e-mail.
"""
import json
import smtplib  # Sending e-mails
import time
import tomllib  # For parsing toml config file
from email.mime.application import \
    MIMEApplication  # Attaching files to e-mails
from email.mime.multipart import MIMEMultipart  # Creating multipart e-mails
from email.mime.text import MIMEText  # Attaching text to e-mails

# For correct encoding of senders with special chars in name:
from email.utils import formataddr

import requests

with open("mit_dk_config.toml", "rb") as f:
    config = tomllib.load(f)


base_url = "https://gateway.mit.dk/view/client/"
session = requests.Session()


def open_tokens():
    try:
        with open(config["files"]["tokens"], "r", encoding="utf8") as token_file:
            tokens = json.load(token_file)
            return tokens
    except:
        return print(
            "Unable to open and parse token file. Did you run mit_dk_first_login.py?"
        )


def revoke_old_tokens(mitdkToken, ngdpToken, dppRefreshToken, ngdpRefreshToken):
    endpoint = "authorization/revoke?client_id=view-client-id-mobile-prod-1-id"
    json_data = {
        "dpp": {"token": mitdkToken, "token_type_hint": "access_token"},
        "ngdp": {"token": ngdpToken, "token_type_hint": "access_token"},
    }
    revoke_access_tokens = session.post(base_url + endpoint, json=json_data)
    if not revoke_access_tokens.status_code == 200:
        print(
            "Something went wrong when trying to revoke old access tokens. Here is the response:"
        )
        print(revoke_access_tokens.text)
    json_data = {
        "dpp": {"refresh_token": dppRefreshToken, "token_type_hint": "refresh_token"},
        "ngdp": {"refresh_token": ngdpRefreshToken, "token_type_hint": "refresh_token"},
    }
    revoke_refresh_tokens = session.post(base_url + endpoint, json=json_data)
    if not revoke_refresh_tokens.status_code == 200:
        print(
            "Something went wrong when trying to revoke old refresh tokens. Here is the response:"
        )
        print(revoke_refresh_tokens.text)


def refresh_and_save_tokens(dppRefreshToken, ngdpRefreshToken):
    endpoint = "authorization/refresh?client_id=view-client-id-mobile-prod-1-id"
    json_data = {
        "dppRefreshToken": dppRefreshToken,
        "ngdpRefreshToken": ngdpRefreshToken,
    }
    refresh = session.post(base_url + endpoint, json=json_data)
    if not refresh.status_code == 200:
        print("Something went wrong trying to fetch new tokens.")
    refresh_json = refresh.json()
    if "code" in refresh_json or "status" in refresh_json:
        print("Something went wrong trying to fetch new tokens. Here's the response:")
        print(refresh_json)
        return False
    else:
        with open(config["files"]["tokens"], "wt", encoding="utf8") as token_file:
            token_file.write(refresh.text)
        return refresh_json


def get_fresh_tokens_and_revoke_old_tokens():
    tokens = open_tokens()
    try:
        if "dpp" in tokens:
            dppRefreshToken = tokens["dpp"]["refresh_token"]
            mitdkToken = tokens["dpp"]["access_token"]
        else:
            dppRefreshToken = tokens["refresh_token"]
            mitdkToken = tokens["access_token"]
        ngdpRefreshToken = tokens["ngdp"]["refresh_token"]
        ngdpToken = tokens["ngdp"]["access_token"]
        fresh_tokens = refresh_and_save_tokens(dppRefreshToken, ngdpRefreshToken)
        if fresh_tokens:
            revoke_old_tokens(mitdkToken, ngdpToken, dppRefreshToken, ngdpRefreshToken)
        return fresh_tokens
    except Exception as error:
        print(error)
        print(
            "Unable to find tokens in token file. Try running mit_dk_first_login.py again."
        )


def get_simple_endpoint(endpoint):
    tries = 1
    while tries <= 3:
        response = session.get(base_url + endpoint)
        try:
            response_json = response.json()
            return response.json()
        except:
            tries += 1
            time.sleep(1)
            pass
    if tries == 3:
        print(
            f"Unable to convert response to json when getting endpoint {endpoint} after 3 tries. Here is the response:"
        )
        print(response.text)
        return false


def get_inbox_folders_and_build_query(mailbox_ids):
    endpoint = "folders/query"
    json_data = {"mailboxes": {}}
    for mailbox in mailbox_ids:
        json_data["mailboxes"][mailbox["dataSource"]] = mailbox["mailboxId"]
    tries = 1
    while tries <= 3:
        response = session.post(base_url + endpoint, json=json_data)
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
        except:
            tries += 1
            time.sleep(1)
            pass
    if tries == 3:
        print(
            "Unable to convert response to json when getting folders. Here is the response:"
        )
        print(response.text)
        return false


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
        response = session.post(base_url + endpoint, json=json_data)
        try:
            response_json = response.json()
            return response.json()
        except:
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
            file_content = session.get(base_url + endpoint + doc_url + file_url)
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
    mark_as_read = session.patch(base_url + endpoint, json=json_data)


mailserver_connect = False
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
    email_creds = config["email"]["credentials"]
    email_options = config["email"]["options"]
    for message in messages["results"]:
        if message["read"] == False:
            if mailserver_connect == False:
                server = smtplib.SMTP(server_config["host"], int(server_config["port"]))
                server.ehlo()
                server.starttls()
                server.login(email_creds["username"], email_creds["password"])
                mailserver_connect = True
            label = message["label"]
            sender = message["sender"]["label"]
            message_content = get_content(message)

            msg = MIMEMultipart("alternative")
            msg["From"] = formataddr((sender,))
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
    if mailserver_connect:
        server.quit()
