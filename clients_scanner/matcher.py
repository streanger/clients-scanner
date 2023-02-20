import datetime
import ipaddress
import os
import queue
import time
from functools import namedtuple
from threading import Thread

from mac_vendor_lookup import MacLookup
from termcolor import colored

# my modules
from clients_scanner.logger import log
from clients_scanner.utils import (get_config_directory, read_json, write_json)


GuiRow = namedtuple('GuiRow', 'name vendor ip mac visible')


class DevicesMatcher:
    """
    class purposes:
        -match devices; send data to gui; store data in files (jsons)
        -receive data from Scanner object
        -send performed data to gui
        -send new data to json
    console color - green
    """
    def __init__(self, scanner=None, log=log):
        self.scanner = scanner
        self.color = "green"
        if log is None:
            self.log = lambda text, color: print(colored(text, color))
        else:
            self.log = log
        self.log("[*] matcher", self.color)
        self.config_directory = get_config_directory()
        self.log('[*] config_directory: {}'.format(self.config_directory), self.color)
        self.clients_file = self.config_directory.joinpath("clients.json")
        self.clients_all = read_json(self.clients_file)
        self.save_trigger = False
        self.save_trigger_timeout_in_minutes = 15  # timeout between auto save if no user interaction was taken
        self.last_clients_all = self.clients_all.copy()
        self.last_seen_timeout = 20  # [s]
        self.last_save_time = time.time()

        self.names_queue = queue.Queue()
        names = [{mac: item["name"]} for mac, item in self.clients_all.items()]
        [self.names_queue.put(pair) for pair in names]
        self.names_definitions = {mac: item["name"] for mac, item in self.clients_all.items()}
        self.last_ssid = ""
        self.last_bssid = ""

        self.gui_table_queue = queue.Queue()
        self._remove_queue = queue.Queue()

        # init table
        table = self._prepare_gui_table(init=True)
        for item in table:
            self.log('[*] cached item: {}'.format(item), self.color)
        self.gui_table_queue.put(table)

        # threading
        self.hold_thread = False
        self.join_thread_flag = False
        self.matcher_thread = None

    def run(self):
        """run matcher thread"""
        self.matcher_thread = Thread(target=self._matcher_loop)
        self.matcher_thread.start()

    def join_thread(self):
        """join thread from external object"""
        self.join_thread_flag = True
        self.matcher_thread.join()
        self.log('[*] matcher thread joined', self.color)
        return None

    def filter_out_table_queue(self, mac):
        """filter table queue from removed device
        
        it should be used while matcher thread is hold
        but gui table data is already produced
        """
        # put mac to remove queue
        self._remove_queue.put(mac)

        # filter out
        filtered = []
        while not self.gui_table_queue.empty():
            table = self.gui_table_queue.get()
            filtered_table = [row for row in table if row.mac != mac]
            filtered.append(filtered_table)

        # append filtered tables to queue
        for table in filtered:
            self.gui_table_queue.put(table)
        return None

    def _matcher_loop(self):
        """matcher queue loop"""
        while True:
            if self.hold_thread:
                if self.join_thread_flag:
                    return False
                time.sleep(0.01)
                continue

            if self.join_thread_flag:
                # break
                return False

            # do the job
            self._match_queues()
            time.sleep(0.1)  # to reduce cpu usage
        return None

    def _match_queues(self):
        """match all queues from scanner and user entries"""
        # do i need this?
        if self.scanner is None:
            self.log('[!] no scanner connected to matcher', self.color)
            return False

        # ******** get devices from scanner queue ********
        new_clients = []
        while True:
            if self.scanner.clients_queue.empty():
                break
            client = self.scanner.clients_queue.get()
            if client.bssid != self.last_bssid:
                # TODO: handle that case on gui side
                self.log('[!] NETWORK CHANGED: {} -> {}'.format(self.last_bssid, client.bssid), 'red')
                self.last_bssid = client.bssid
                new_clients = []
            self.last_bssid = client.bssid
            self.last_ssid = client.ssid
            new_clients.append(client)

        # ******* get new names if exists *******
        while True:
            if self.names_queue.empty():
                break
            pair = self.names_queue.get()
            self.names_definitions.update(pair)
            self.save_trigger = True  # user action
            self.log('[*] new name: {}'.format(pair), self.color)

        # ******* update all clients with names *******
        for mac, value in self.clients_all.items():
            value['name'] = self.names_definitions.get(mac, "unknown")
            self.clients_all[mac] = value
            
        # ******* update clients with new devices *******
        for (mac, ip, bssid, ssid, timestamp) in new_clients:
            item = {}
            item["name"] = self.names_definitions.get(mac, "unknown")
            item["ip"] = ip
            item["mac"] = mac
            item["vendor"] = self._get_vendor(mac)
            item["last_seen"] = str(self._unix_to_datetime(timestamp))
            item["ssid"] = ssid
            item["bssid"] = bssid
            self.clients_all[mac] = item

        # ******* remove clients definitions *******
        while True:
            if self._remove_queue.empty():
                break
            mac = self._remove_queue.get()
            self.clients_all.pop(mac, False)
            self.names_definitions[mac] = 'unknown'
            self.save_trigger = True  # user action
            self.log('[x] client definition removed: {}'.format(mac), self.color)

        # ******* prepare table for gui queue *******
        table = self._prepare_gui_table()
        if table:
            self.gui_table_queue.put(table)

        # ******* update json db *******
        if self.clients_all != self.last_clients_all:
            now = time.time()
            save_time_diff = (now - self.last_save_time)//60
            if save_time_diff > self.save_trigger_timeout_in_minutes:
                self.log('[*] auto save triggered at: {}'.format(self._unix_to_datetime(now)), self.color)
                self.save_trigger = True
            if self.save_trigger:
                self.save_clients_db()

        self.last_clients_all = self.clients_all.copy()
        return None

    def save_clients_db(self):
        """save clients data to .json file"""
        self.log('[*] local clients changed; writing to json', self.color)
        write_json(self.clients_file, self.clients_all)
        self.save_trigger = False
        self.last_save_time = time.time()

    def _prepare_gui_table(self, init=False):
        """convert json data about clients, to table possible for print by gui
        table shape: (name, vendor, ip, mac, visible)
        """
        table = []
        for key, value in self.clients_all.items():
            # if bssid is ok +1
            if (not init) and (value['bssid'] != self.last_bssid):
                # not interested in that
                continue
            # if time diff is greater/lower then red/green
            last_seen = self._timestamp_to_datetime(value["last_seen"])
            now = datetime.datetime.now()
            time_diff_seconds = (now - last_seen).total_seconds()
            visible = bool(time_diff_seconds < self.last_seen_timeout)
            gui_row = GuiRow(
                value["name"],
                value["vendor"],
                value["ip"],
                value["mac"],
                visible,
            )
            table.append(gui_row)
        table = sorted(table, key=lambda x: self._ip_sorter(x[2]))
        return table

    @staticmethod
    def _ip_sorter(ip):
        """sorting by IP handler"""
        try:
            if "." in ip:
                # IPv4
                return ".".join([item.zfill(3) for item in ip.split(".")])
            else:
                # IPv6
                return ipaddress.IPv6Address(ip).exploded
        except Exception:
            return ip
 
    @staticmethod
    def _get_vendor(mac):
        """get vendor for specified mac"""
        try:
            mac_lookup_info = MacLookup().lookup(mac)
        except KeyError:
            mac_lookup_info = "device not recognized"
        return mac_lookup_info

    @staticmethod
    def _timestamp():
        """generate timestamp in string format"""
        out = str(datetime.datetime.now())
        return out

    @staticmethod
    def _unix_to_datetime(unix_time):
        """convert unix to datetime"""
        out = datetime.datetime.fromtimestamp(unix_time)
        return out

    @staticmethod
    def _timestamp_to_datetime(str_timestamp):
        """convert string timestamp to datetime type"""
        return datetime.datetime.strptime(str_timestamp, "%Y-%m-%d %H:%M:%S.%f")


if __name__ == "__main__":
    print('import it as module rather than call')
    if os.name == "nt":
        os.system("color")
    matcher = DevicesMatcher()
    matcher.run()
    