#!/usr/bin/env python3

import os
os.environ['SSL_CERT_FILE']='./CCIITD-CA.crt'
import signal
import ssl
import sys
import threading
from datetime import datetime
from getpass import getpass
from urllib import parse, request


class Proxy:
    proxy_set = {
        "btech": 22,
        "dual": 62,
        "diit": 21,
        "faculty": 82,
        "integrated": 21,
        "mtech": 62,
        "phd": 61,
        "retfaculty": 82,
        "staff": 21,
        "irdstaff": 21,
        "mba": 21,
        "mdes": 21,
        "msc": 21,
        "msr": 21,
        "pgdip": 21,
    }

    google = "http://www.google.com"

    def __init__(self, username, password, proxy_cat):
        self.username = username
        self.password = password
        self.proxy_cat = proxy_cat

        self.auto_proxy = f"http://www.cc.iitd.ernet.in/cgi-bin/proxy.{proxy_cat}"
        self.proxy_page_address = (
            f"https://proxy{Proxy.proxy_set[proxy_cat]}.iitd.ernet.in/cgi-bin/proxy.cgi"
        )

        ssl_ctx = ssl._create_unverified_context()

        self.urlopener = request.build_opener(
            request.HTTPSHandler(context=ssl_ctx),
            request.ProxyHandler({"http": self.auto_proxy, "https": self.auto_proxy}),
        )

        self.new_session_id()
        self.details()

    def is_connected(self):
        proxies = {
            "http": f"http://proxy{Proxy.proxy_set[self.proxy_cat]}.iitd.ernet.in:3128"
        }
        try:
            proxy_handler = request.ProxyHandler(proxies)
            opener = request.build_opener(proxy_handler)
            response = opener.open(Proxy.google).read().decode()
        except Exception:
            return "Not Connected"

        if "<title>IIT Delhi Proxy Login</title>" in response:
            return "Login Page"
        elif "<title>Google</title>" in response:
            return "Google"
        else:
            return "Not Connected"

    def get_session_id(self):
        try:
            response = self.open_page(self.proxy_page_address)
        except Exception:
            return None

        check_token = 'sessionid" type="hidden" value="'
        token_index = response.index(check_token) + len(check_token)
        return response[token_index : token_index + 16]

    def new_session_id(self):
        self.sessionid = self.get_session_id()
        self.loginform = {
            "sessionid": self.sessionid,
            "action": "Validate",
            "userid": self.username,
            "pass": self.password,
        }
        self.logout_form = {
            "sessionid": self.sessionid,
            "action": "logout",
            "logout": "Log out",
        }
        self.loggedin_form = {"sessionid": self.sessionid, "action": "Refresh"}

    def login(self):
        self.new_session_id()
        response = self.submitform(self.loginform)

        if "Either your userid and/or password does'not match." in response:
            return "Incorrect", response

        elif f"You are logged in successfully as {self.username}" in response:

            def ref():
                if not self.loggedout:
                    res = self.refresh()
                    print("Refresh", datetime.now())
                    if res == "Session Expired":
                        print("Session Expired. Run Script again")
                    else:
                        self.timer = threading.Timer(60.0, ref)
                        self.timer.daemon = True
                        self.timer.start()

            self.timer = threading.Timer(60.0, ref)
            self.timer.daemon = True
            self.timer.start()
            self.loggedout = False
            return "Success", response

        elif "already logged in" in response:
            return "Already", response
        elif "Session Expired" in response:
            return "Expired", response
        else:
            return "Not Connected", response

    def logout(self):
        self.loggedout = True
        response = self.submitform(self.logout_form)

        if "you have logged out from the IIT Delhi Proxy Service" in response:
            return "Success", response
        elif "Session Expired" in response:
            return "Expired", response
        else:
            return "Failed", response

    def refresh(self):
        response = self.submitform(self.loggedin_form)

        if "You are logged in successfully" in response:
            if f"You are logged in successfully as {self.username}" in response:
                return "Success", response
            else:
                return "Not Logged In"
        elif "Session Expired" in response:
            return "Expired", response
        else:
            return "Not Connected", response

    def details(self):
        if VERBOSE:
            for prop, val in vars(self).items():
                print(prop, ":", val)

    def submitform(self, form):
        data = parse.urlencode(form).encode()
        req = request.Request(self.proxy_page_address, data=data)
        return self.urlopener.open(req).read().decode()

    def open_page(self, address):
        return self.urlopener.open(address).read().decode()


STATUS = 0
RESPONSE = 1
VERBOSE = False


def signal_handler(sig, frame):
    print("\nLogout", user.logout()[STATUS])
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("\nUsage: python3 login_terminal.py file\n")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        uname, proxycat = f.readline().strip().split()

    passwd = getpass()

    user = Proxy(username=uname, password=passwd, proxy_cat=proxycat)
    login_status = user.login()[STATUS]
    print("\nLogin", login_status)

    if login_status == "Success":
        signal.pause()
