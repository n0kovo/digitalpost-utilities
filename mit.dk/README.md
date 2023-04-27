Send messages from mit.dk to your own e-mail
============================================

This utility lets you set up a task to check your messages at https://mit.dk and send them to an e-mail. This is helpful if you're tired of using NemID or MitID each time you want to read your messages.

Requirements
============
* The files in the mit.dk folder in this repository.
* Python and the packages defined in `requirements.txt`
* A Danish NemID or MitID login for access to mit.dk.
* A webdriver to run and monitor your browser from a Python script. If running Chrome, get `chromedriver` from https://chromedriver.chromium.org/ and put it in your PATH or at the same location as your files from this repository.
* A server, service or PC that's on 24/7 to monitor mit.dk for new mails and keep your login active.
* An e-mail address and the ability to send e-mails using SMTP.

Steps to run
============

Step one
--------
* Clone repo: `git clone https://github.com/helmstedt/digitalpost-utilities.git`
* Install dependencies: `cd digitalpost-utilities.git && python3 -m pip install -r requirements.txt`
* Enter your e-mail and e-mail server details in `mit_dk_config.toml`.

Step two
--------

* Run `mit_dk_first_login.py`. The program is set up to work with Chrome and `chromedriver` in headless mode.
* The program will start the login procedure and notify you when you need to approve the login using the MitID app.
* If your login is successfull, the program will save access tokens for mit.dk to `mitdk_tokens.json`

Step three
----------

* Immediately after completing step two, copy `mit_dk_get_and_send_mail.py`, `mit_dk_config.toml` and `mitdk_tokens.json` to a computer or server that is on 24/7 (if this is your computer from step two, no need to copy anything.)
* If necessary edit the `files.tokens` field in `mit_dk_config.toml` to the full path of your `mitdk_tokens.json` file
* Run `mit_dk__send_new_by_email.py` from this computer at specific intervals to fetch messages from mit.dk and send them to your e-mail. I recommend somewhere between 5 and 15 minutes between each run. The access token for mit.dk expires after approximately 20 minutes. The program refreshes the access tokens for mit.dk on each run.
* If running `mit_dk__send_new_by_email.py` on Linux, set up a CRON job to automate running the program. If running the program on Windows, use Task Scheduler.

Questions
=========

Feel free to get in touch. My contact information is available on https://helmstedt.dk.

Thanks
======

The program is heavily inspired by the method of https://github.com/dk/Net-MitDK by Dmitry Karasik. Thanks, Dmitry.
