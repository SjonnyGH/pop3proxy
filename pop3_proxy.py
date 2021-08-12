#!/usr/bin/env python3
# Minimum requirement: python3.5
# SPDX-License-Identifier: MIT

import argparse
import hashlib
import imaplib
import logging
import os
import re
import socket
import sys
import threading
import time

from typing import Tuple, Optional

imaplib.Commands["ID"] = ("NONAUTH", "AUTH", "SELECTED")

POP3_RESPONSE_OK = b"+OK %b\r\n"
POP3_RESPONSE_ERR = b"-ERR %b\r\n"
POP3_RESPONSE_END = b".\r\n"

uid_size_matcher = re.compile(b"[0-9]+ \(UID ([0-9]+) RFC822.SIZE ([0-9]+)\)")

_conn_cache = {}
_debug = False
_endpoint = None


class Disconnect(Exception):
    pass


class IMAPConnection:
    hostname = None
    username = None
    imap_conn = None
    # uid -> size
    mails = {}
    uids = []

    def __init__(self, client_socket: socket.socket) -> None:
        self.client = client_socket

    def check_status(self, status: str, reply: bytes, error: str, fatal: bool = True) -> None:
        if status == "OK":
            return
        response = b"failed %b" % (error.encode())
        logging.info(reply)
        logging.error(response.decode())
        self.client.send(POP3_RESPONSE_ERR % (response))
        if fatal:
            raise Exception()

    def send_id(self) -> Tuple[str, str]:
        name = "ID"
        typ, dat = self.imap_conn._simple_command(name, '("name" "POP3Proxy" "version" "1.0")')
        return self.imap_conn._untagged_response(typ, dat, name)

    def lookup_user(self, username: str) -> None:
        self.username = username
        if not _endpoint:
            domain = username.split("@")[1]
            autodiscover = f"autodiscover.{domain}"
            logging.info(f"Looking up {autodiscover}")
            disco, _, _ = socket.gethostbyname_ex(autodiscover)
            self.hostname = disco.replace("autodiscover", "imap")
        else:
            self.hostname = _endpoint
        self.client.send(POP3_RESPONSE_OK % b"send password")

    def find_connection(self, username: str, password: str) -> Tuple[str, Optional[imaplib.IMAP4_SSL]]:
        if _conn_cache is None:
            return "", None
        hasher = hashlib.sha256()
        hasher.update(username.encode())
        hasher.update(password.encode())
        digest = hasher.hexdigest()
        return digest, _conn_cache.pop(digest, None)

    def login(self, password: str) -> None:
        digest, self.imap_conn = self.find_connection(self.username, password)
        if self.imap_conn:
            logging.info(f"Trying to reuse session {digest}")
            try:
                # possible bug in imaplib when running noop and debug is >= 3.
                # https://bugs.python.org/issue26543
                # just make sure to avoid it.
                d = self.imap_conn.debug
                self.imap_conn.debug = 0
                status, reply = self.imap_conn.noop()
                self.check_status(status, reply, "noop")
                self.imap_conn.debug = d
                self.make_email_list()
                logging.info(f"Reusing connection to {self.hostname}")
                self.client.send(POP3_RESPONSE_OK % b"logged in with cached connection")
                return
            except Exception as err:
                logging.error(f"Failed to reuse connection: {err}")
                self.imap_conn = None
                _conn_cache.pop(digest)
        logging.info(f"Connecting to {self.hostname}")
        try:
            self.imap_conn = imaplib.IMAP4_SSL(self.hostname)
        except Exception as err:
            logging.error(f"Error connecting to {self.hostname}, error: {err}")
            self.client.send(POP3_RESPONSE_ERR % b"upstream connection error")
            raise Disconnect()
        self.imap_conn.last_check = 0
        if _debug:
            self.imap_conn.debug = 4
        logging.debug(self.imap_conn.welcome.decode("ascii"))
        logging.info(f"Logging in for {self.username}")
        try:
            status, reply = self.imap_conn.login(self.username, password)
        except Exception as err:
            logging.error(f"Error connecting to {self.hostname}, error: {err}")
            self.client.send(POP3_RESPONSE_ERR % b"invalid username/password")
            raise Disconnect()
        self.check_status(status, reply, "username or password")
        status, reply = self.send_id()
        self.check_status(status, reply, "id")
        status, reply = self.imap_conn.select("INBOX")
        self.check_status(status, reply, "inbox")
        self.make_email_list()
        self.client.send(POP3_RESPONSE_OK % b"logged in")
        if not _conn_cache is None:
            _conn_cache[digest] = self.imap_conn

    def make_email_list(self) -> None:
        self.mails = {}
        self.uids = []
        if self.imap_conn.last_check + 10 > time.time():
            return
        status, reply = self.imap_conn.uid("FETCH", "1:*", "(UID RFC822.SIZE)")
        self.check_status(status, reply, "email ids and sizes")
        for line in reply:
            if not line:
                continue
            values = uid_size_matcher.match(line)
            self.mails[int(values[1])] = int(values[2])
            self.uids.append(int(values[1]))
        self.imap_conn.last_check = time.time()

    def fetch_by_id(self, row_id: int) -> bytes:
        status, reply = self.imap_conn.uid("fetch", str(self.uids[row_id - 1]), "(BODY.PEEK[])")
        self.check_status(status, reply, f"email {row_id}")
        return reply[0][1]

    def mark_deleted(self, row_id: int) -> None:
        status, reply = self.imap_conn.uid("STORE", str(self.uids[row_id - 1]), "+FLAGS", r"(\Deleted)")
        self.check_status(status, reply, "mark deleted")

    def expunge(self) -> None:
        status, reply = self.imap_conn.expunge()
        self.check_status(status, reply, "expunge", False)

    def get_mail_size(self, row_id: int) -> int:
        return self.mails[self.uids[row_id - 1]]


def serve_pop3(client: socket.socket) -> None:
    client.send(POP3_RESPONSE_OK % (b"ready"))
    proxy = IMAPConnection(client)
    # pre-auth
    while True:
        line = client.recv(4096).decode("ascii").strip()
        logging.debug(line)
        parts = line.split()
        if not parts:
            logging.info("No data received from client")
            return
        command = parts[0].upper()
        if command == "QUIT":
            client.send(POP3_RESPONSE_OK % (b"bye"))
            return
        elif command == "CAPA":
            client.send(POP3_RESPONSE_OK % (b"\r\nUSER\r\n."))
        elif command == "USER":
            username = parts[1]
            proxy.lookup_user(username)
        elif command == "PASS":
            proxy.login(parts[1])
            break
        else:
            logging.error(f"Not implemented command {line}")
            client.send(POP3_RESPONSE_ERR % (b"not implemented"))
    # post-auth
    while True:
        line = client.recv(4096).decode("ascii").strip()
        logging.debug(line)
        parts = line.split()
        if not parts:
            logging.info("No data received from client")
            return
        command = parts[0].upper()
        if command == "QUIT":
            proxy.expunge()
            client.send(POP3_RESPONSE_OK % (b"bye"))
            return
        elif command == "STAT":
            total_size = 0
            for uid, size in proxy.mails.items():
                total_size += size
            client.send(POP3_RESPONSE_OK % (b"%d %d" % (len(proxy.mails), total_size)))
        elif command == "LIST":
            if len(parts) > 1:
                offset = int(parts[1])
                client.send(POP3_RESPONSE_OK % (b"%d %d" % (offset, proxy.get_mail_size(offset))))
            else:
                client.send(POP3_RESPONSE_OK % (b"%d" % (len(proxy.mails))))
                for offset, uid in enumerate(proxy.mails):
                    client.send(b"%d %d\r\n" % (offset + 1, proxy.mails[uid]))
                client.send(POP3_RESPONSE_END)
        elif command == "RETR":
            mail_data = proxy.fetch_by_id(int(parts[1]))
            client.send(POP3_RESPONSE_OK % (b"%d octets" % (len(mail_data))))
            client.send(mail_data)
            # buggy mails that do not end with \r\n need some fixing for the end response to make sense.
            if mail_data[-2:] != b"\r\n" or mail_data[-1:] != b"\n":
                client.send(b"\r\n")
            client.send(POP3_RESPONSE_END)
        elif command == "DELE":
            proxy.mark_deleted(int(parts[1]))
            client.send(POP3_RESPONSE_OK % (b"will delete email"))
            pass
        elif command == "NOOP":
            pass
        elif command == "RSET":
            pass
        else:
            logging.error(f"Not implemented command {line}")
            client.send(POP3_RESPONSE_ERR % (b"not implemented"))


def do_pop3_session(client_info):
    try:
        serve_pop3(client_info[0])
    except Disconnect as err:
        pass
    except Exception as err:
        logging.exception(f"Error during session: {err}")
    client_info[0].close()
    logging.info(f"Disconnecting {client_info[1][0]}:{client_info[1][1]}")


_quit = False
_threads = []
_event = threading.Event()


def thread_joiner() -> None:
    logging.debug("Thread joiner")
    global _quit
    while not _quit:
        logging.debug("waiting for events")
        _event.wait()
        _event.clear()
        logging.debug("joining threads")
        while _threads:
            thread = _threads.pop()
            thread.join()
            logging.debug(f"joined {thread}")
    logging.debug("Thread joiner done")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", default=False, help="Log some network traffic too")
    parser.add_argument(
        "--disable-connection-cache", action="store_true", default=False, help="Do not cache connections"
    )
    parser.add_argument("--port", default=1110, type=int, help="Port to listen on for incoming POP3 connections")
    parser.add_argument("--endpoint", help="Force IMAP endpoint only to this server, no autodiscover taking place")
    args = parser.parse_args()
    global _debug
    _debug = args.debug
    if args.endpoint:
        global _endpoint
        _endpoint = args.endpoint
    level = logging.DEBUG if _debug else logging.INFO
    logging.basicConfig(format="[%(asctime)s] [%(thread)s] [%(levelname)-8s] %(message)s", level=level)
    if args.disable_connection_cache:
        logging.info("Not using connection caching")
        global _conn_cache
        _conn_cache = None
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    logging.info(f"Listening for incoming connections on 127.0.0.1:{args.port}")
    joiner = threading.Thread(target=thread_joiner)
    joiner.start()
    try:
        while True:
            client_info = server.accept()
            logging.info(f"Accepted connection from {client_info[1][0]}:{client_info[1][1]}")
            thread = threading.Thread(target=do_pop3_session, args=(client_info,))
            thread.start()
            _threads.append(thread)
            _event.set()
    except KeyboardInterrupt:
        logging.info("Exiting...")
        pass
    except Exception:
        logging.info("Exiting...")
        pass
    global _quit
    _quit = True
    _event.set()
    joiner.join()


if __name__ == "__main__":
    sys.exit(main())
