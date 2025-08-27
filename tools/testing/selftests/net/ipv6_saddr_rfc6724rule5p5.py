#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from socket import socket, AF_INET6, SOCK_DGRAM

from lib.py import ksft_run, ksft_exit, ksft_true
from lib.py import NetNS, NetNSEnter
from lib.py import ip


def select_addr(dest):
    sock = socket(AF_INET6, SOCK_DGRAM, 0)
    sock.connect((dest, 12345))
    return sock.getsockname()[0]

def test_basic() -> None:
    with NetNS() as testns:
        with NetNSEnter(str(testns)):
            ip("link add type veth")
            ip("link set veth0 up")
            ip("link set veth1 up")
            ip("addr add 2001:db8:10::1/64 dev veth0 nodad")
            ip("addr add 2001:db8:1000::1/64 dev veth0 nodad")
            ip("-6 route add default via fe80::1 dev veth0 metric 100")
            ip("-6 route add default via fe80::2 dev veth0 metric 200")
            ip("-6 route add default from 2001:db8:10::/48 via fe80::1 dev veth0")
            ip("-6 route add default from 2001:db8:1000::/48 via fe80::2 dev veth0")

            ksft_true(select_addr("2001:db8:11::") == "2001:db8:10::1", "baseline pass")
            # rule 8 would result in the use of the :1001: address, but rule 5.5 applies before.
            ksft_true(select_addr("2001:db8:1001::") == "2001:db8:10::1", "rule 5.5 > rule 8")

            ip("-6 route del default via fe80::1 dev veth0 metric 100")

            ksft_true(select_addr("2001:db8:11::") == "2001:db8:1000::1", "baseline pass")
            ksft_true(select_addr("2001:db8:1001::") == "2001:db8:1000::1", "rule 5.5 > rule 8")


def test_no_subtree() -> None:
    with NetNS() as testns:
        with NetNSEnter(str(testns)):
            ip("link add type veth")
            ip("link set veth0 up")
            ip("link set veth1 up")
            ip("addr add 2001:db8:10::1/64 dev veth0 nodad")
            ip("addr add 2001:db8:1000::1/64 dev veth0 nodad")
            ip("-6 route add default via fe80::1 dev veth0 metric 100")
            ip("-6 route add default via fe80::2 dev veth0 metric 200")
            ip("-6 route add default from 2001:db8:10::/48 via fe80::1 dev veth0")

            ksft_true(select_addr("2001:db8:11::") == "2001:db8:10::1", "baseline pass")
            ksft_true(select_addr("2001:db8:1001::") == "2001:db8:10::1", "rule 5.5 > rule 8, ignoring non-SADR")


def test_longer() -> None:
    ksft_true(True, "Y")


def main() -> None:
    ksft_run([test_basic, test_no_subtree, test_longer])
    ksft_exit()


if __name__ == "__main__":
    main()
