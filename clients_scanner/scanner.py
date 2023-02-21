"""scanner module for clients_scanner"""
import os
import queue
import random
import re
import subprocess
import time
from functools import namedtuple
from threading import Thread

# 3rd party
from scapy.all import ARP, Ether, srp
from termcolor import colored

# my modules
from clients_scanner.logger import log

Client = namedtuple("Client", "mac ip bssid ssid time")


class ScapyScanner:
    """class for cooperate with matcher and deauthenticator objects
    https://www.juniper.net/documentation/en_US/junos-space-apps/network-director3.7/topics/concept/wireless-ssid-bssid-essid.html
    console color - magenta
    """
    def __init__(self, debug=False, scan_time=2, scan=True, log=log):
        self.debug = debug
        self.color = "magenta"
        if log is None:
            self.log = lambda text, color: print(colored(text, color))
        else:
            self.log = log
        self.log("[*] scanner", self.color)
        self.scan_time = scan_time

        # network info
        self.ssid = ""
        self.bssid = ""
        self.gateway_ip = ""
        self.gateway_mac = ""
        self.target_ip = ""

        # thread
        self.scanner_thread = None
        if scan:
            self.hold_thread = False
        else:
            self.hold_thread = True
        self.join_thread_flag = False

        # main queue
        self.clients_queue = queue.Queue()

    def run(self):
        """run scanner"""
        if not self._scanner_init():
            return False

        self.scanner_thread = Thread(target=self._devices_scanner)
        self.scanner_thread.start()
        return True

    def join_thread(self):
        """join thread from external object"""
        self.join_thread_flag = True
        try:
            self.scanner_thread.join()
        except AttributeError as error:
            self.log("[x] error catched: {}".format(error), self.color)
        self.log("[*] scanner thread joined", self.color)
        return None

    def _scanner_init(self):
        """get network bssid, ssid, gateway (ip, mac)
        BSSID - AP MAC address
        SSID - name of network
        possible error:
            [*] SSID: off/any
            [*] BSSID: not-associated
        """
        if self.debug:
            self.ssid, self.bssid = ("My wifi network", "aa:bb:cc:dd:ee:ff")
            self.gateway_ip, self.gateway_mac = ("192.168.0.1", "aa:bb:cc:dd:ee:ff")
            self.target_ip = "{}/24".format(self.gateway_ip)
            return True

        ssid_error = "off/any"
        bssid_error = "not-associated"

        self.ssid, self.bssid = self.get_ssid_bssid()
        if not all((self.ssid, self.bssid)):
            self.log("[x] can't find network (SSID, BSSID)", self.color)
            return False

        if (self.ssid == ssid_error) or (self.bssid == bssid_error):
            self.log("[x] errors: (SSID: {}, BSSID: {})".format(self.ssid, self.bssid),
            self.color)
            return False

        self.log("[*] SSID: {}, BSSID: {}".format(self.ssid, self.bssid), self.color)

        self.gateway_ip, self.gateway_mac = self.get_gateway(self.bssid)
        if not all((self.gateway_ip, self.gateway_mac)):
            self.log("[x] can't find gateway: (IP: {}, MAC: {})".format(repr(self.gateway_ip), repr(self.gateway_mac)), self.color)
            return False

        self.target_ip = "{}/24".format(self.gateway_ip)
        self.log("[*] gateway (IP, MAC, network): ({}, {}, {})".format(self.gateway_ip, self.gateway_mac, self.target_ip), self.color)
        return True

    def _devices_scanner_debug(self):
        """debug version of _devices_scanner method
        it produces fake devices info
        """
        random_time = time.time()
        random_devices = []
        for x in range(30):
            random_devices.append(
                Client(
                    "{:02x}:af:de:ff:aa:ff".format(random.randrange(256)),
                    "11.{}.33.44".format(random.randrange(256)),
                    self.bssid,
                    self.ssid,
                    random_time
                )
            )
            
        while True:
            if self.hold_thread:
                if self.join_thread_flag:
                    return False
                time.sleep(0.01)
                continue

            if self.join_thread_flag:
                return False

            clients = [random.choice(random_devices) for x in range(random.randint(1, 2))]
            clients = list(set(clients))
            time.sleep(2)
            for client in clients:
                self.clients_queue.put(client)
        return None

    def _devices_scanner(self):
        """function for continous searching for new devices in thread"""
        if self.debug:
            self._devices_scanner_debug()
            return None

        # ****** real scan ******
        while True:
            if self.hold_thread:
                if self.join_thread_flag:
                    return False
                time.sleep(0.1)
                continue

            if self.join_thread_flag:
                return False

            clients = self.get_clients(self.target_ip, self.scan_time, iterations=1)
            self.log('[*] found: {}'.format(clients), self.color)
            # in case of change in ssid/bssid we should send all data
            now = time.time()
            clients = [Client(mac, ip, self.bssid, self.ssid, now) for (ip, mac) in clients]
            for client in clients:
                self.clients_queue.put(client)
        return None

    @staticmethod
    def get_gateway(bssid=""):
        """get gateway_ip and gateway_mac

        commands:
            arp -n | grep wlan0 | head -n 1
            arp -n
            ip route
        """
        os_name = os.name
        if os_name == "nt":
            command = "arp -a"
            with subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="cp852",
                    universal_newlines=True,
                ) as cmd_output:
                response = cmd_output.stdout.read()
            response_lines = [line for line in response.splitlines() if line.strip()]

            if not bssid:
                # it will fail, if connect any device over ethernet
                gateway_mac = re.search(r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", response, re.I).group()
                gateway_ip = [
                    line.split()[0]
                    for line in response_lines
                    if gateway_mac in line.split()
                ][0]
                gateway_mac = gateway_mac.replace("-", ":")
            else:
                bssid_minus = bssid.replace(":", "-")
                bssid_minus_half = "-".join(bssid_minus.split("-")[:3])
                gateway_ip_lines = [
                    line.split()[0]
                    for line in response_lines
                    if line.split()[1].startswith(bssid_minus_half)
                ]
                gateway_ip = gateway_ip_lines[0]
                gateway_mac = bssid

        else:
            # get gateway IP
            command = "ip route"  # route -n
            response = subprocess.getoutput(command)
            gateway_ip = response.splitlines()[0].split()[2]

            # get gateway mac
            command = "arp -n"
            response = subprocess.getoutput(command)
            if not response.strip():
                return ("", "")
            lines = [line for line in response.splitlines() if gateway_ip in line.split()[0]]
            try:
                _, _, gateway_mac = lines[0].split()[:3]
            except IndexError:
                return ("", "")
        return gateway_ip, gateway_mac

    @staticmethod
    def get_ssid_bssid():
        """get ssid(network name) and bssid(gateway mac)"""
        os_name = os.name
        if os_name == "nt":
            command = "Netsh WLAN show interfaces"
            with subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding="cp852",
                    universal_newlines=True,
                ) as cmd_output:
                response = cmd_output.stdout.readlines()
            ssid_line = [line for line in response if "SSID" in line.split()]
            bssid_line = [line for line in response if "BSSID" in line.split()]
            ssid = ""
            if ssid_line:
                ssid = (ssid_line[0].split(":", 1)[1]).strip()
            bssid = ""
            if bssid_line:
                bssid = (bssid_line[0].split(":", 1)[1]).strip()
        else:
            command = "iwgetid"
            command = "iwconfig"
            response = subprocess.getoutput(command).splitlines()
            essid_line = [line for line in response if "ESSID:" in line]
            bssid_line = [line for line in response if "Access Point:" in line]
            ssid = ""
            if essid_line:
                ssid = (essid_line[0].split("ESSID:", 1)[1]).strip().replace('"', "")
            bssid = ""
            if bssid_line:
                bssid = (bssid_line[0].split("Access Point:", 1)[1]).strip().lower()
        return (ssid, bssid)

    def get_clients(self, target_ip, timeout=2, iterations=1):
        """get all clients in local network; return list of (ip, mac)

        https://scapy.readthedocs.io/en/latest/usage.html#ip-scan
        https://scapy.readthedocs.io/en/latest/usage.html#arp-ping
        """
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        clients = []
        for _ in range(iterations):
            try:
                result = srp(packet, timeout=timeout, verbose=0)[0]
            except OSError:
                self.log("[x] OSError catched, while searching for clients...", self.color)
                time.sleep(2)
                break
            clients.extend([(received.psrc, received.hwsrc.lower()) for (sent, received) in result])
        clients = list(set(clients))
        return clients


if __name__ == "__main__":
    print('import it as module rather than call')
    scapy_scanner = ScapyScanner(debug=False)
    scapy_scanner.run()
    while True:
        item = scapy_scanner.clients_queue.get()
        print(item)
        