#!/usr/bin/env python3
import os
os.environ['SSL_CERT_FILE']='./CCIITD-CA.crt'
import sys
import signal
import threading
import ssl
from getpass import getpass
from datetime import datetime
from urllib import request, parse, error

VERBOSE = False
STATUS = 0
RESPONSE = 1


class Proxy:
    proxy_set = {
        'btech':22,'dual':62,'diit':21,'faculty':82,'integrated':21,
        'mtech':62,'phd':61,'retfaculty':82,'staff':21,'irdstaff':21,
        'mba':21,'mdes':21,'msc':21,'msr':21,'pgdip':21
    }

    google = "http://www.google.com"

    def __init__(self, username, password, proxy_cat):
        self.username = username
        self.password = password
        self.proxy_cat = proxy_cat
        self.loggedout = False

        self.proxy_page_address = (
            f"https://proxy{Proxy.proxy_set[proxy_cat]}"
            ".iitd.ernet.in/cgi-bin/proxy.cgi"
        )

        # IMPORTANT: NO ProxyHandler here
        ssl_ctx = ssl._create_unverified_context()
        self.urlopener = request.build_opener(
            request.HTTPSHandler(context=ssl_ctx)
        )

        self.new_session_id()
        self.details()

    # ---------------- Session Handling ---------------- #

    def get_session_id(self):
        try:
            response = self.open_page(self.proxy_page_address)
        except Exception:
            return None

        token = 'sessionid" type="hidden" value="'
        idx = response.find(token)
        if idx == -1:
            return None

        idx += len(token)
        return response[idx:idx + 16]

    def new_session_id(self):
        self.sessionid = self.get_session_id()

        self.loginform = {
            'sessionid': self.sessionid,
            'action': 'Validate',
            'userid': self.username,
            'pass': self.password
        }

        self.logout_form = {
            'sessionid': self.sessionid,
            'action': 'logout',
            'logout': 'Log out'
        }

        self.loggedin_form = {
            'sessionid': self.sessionid,
            'action': 'Refresh'
        }

    # ---------------- Core Actions ---------------- #

    def submitform(self, form):
        data = parse.urlencode(form).encode()
        req = request.Request(self.proxy_page_address, data=data)
        return self.urlopener.open(req, timeout=10).read().decode(errors="ignore")

    def open_page(self, url):
        return self.urlopener.open(url, timeout=10).read().decode(errors="ignore")

    def login(self):
        self.new_session_id()
        response = self.submitform(self.loginform)

        if "does'not match" in response:
            return "Incorrect", response

        if f"You are logged in successfully as {self.username}" in response:
            self.loggedout = False
            self._start_refresh_timer()
            return "Success", response

        if "already logged in" in response:
            return "Already", response

        if "Session Expired" in response:
            return "Expired", response

        return "Not Connected", response

    def logout(self):
        self.loggedout = True
        response = self.submitform(self.logout_form)

        if "logged out from the IIT Delhi Proxy Service" in response:
            return "Success", response

        if "Session Expired" in response:
            return "Expired", response

        return "Failed", response

    def refresh(self):
        response = self.submitform(self.loggedin_form)

        if f"You are logged in successfully as {self.username}" in response:
            return "Success", response

        if "Session Expired" in response:
            return "Expired", response

        return "Not Connected", response

    # ---------------- Keep Alive ---------------- #

    def _start_refresh_timer(self):
        def refresher():
            if self.loggedout:
                return

            status, _ = self.refresh()
            print("Refresh:", status, datetime.now())

            if status == "Expired":
                print("Session expired. Please login again.")
                return

            self.timer = threading.Timer(60, refresher)
            self.timer.daemon = True
            self.timer.start()

        self.timer = threading.Timer(60, refresher)
        self.timer.daemon = True
        self.timer.start()

    # ---------------- Utility ---------------- #

    def details(self):
        if VERBOSE:
            for k, v in vars(self).items():
                print(k, ":", v)


# ---------------- Signal Handling ---------------- #

def signal_handler(sig, frame):
    print("\nLogout:", user.logout()[STATUS])
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

# ---------------- Main ---------------- #

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 iitdproxy_py3.py <cred_file>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        username, proxycat = f.readline().strip().split()

    password = getpass("Password: ")

    user = Proxy(username, password, proxycat)
    status = user.login()[STATUS]

    print("\nLogin:", status)

    if status == "Success":
        signal.pause()
