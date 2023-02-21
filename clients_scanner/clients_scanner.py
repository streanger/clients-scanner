"""clients_scanner
version: 0.1.3
date: 20.10.2022
author: streanger
"""
import gc
import os
from functools import partial

# external modules
from termcolor import colored
from tkinter import (BOTH, BOTTOM, END, HORIZONTAL, LEFT, NO, RIGHT, TOP,
                     VERTICAL, YES, Button, Canvas, Entry, Frame, Label,
                     Scrollbar, StringVar, Tk, Widget, X, Y, font, messagebox,
                     scrolledtext)

# my modules
from clients_scanner.config import ConfigAndStyle
from clients_scanner.deauth import Deauthenticator
from clients_scanner.logger import Logger, log
from clients_scanner.matcher import DevicesMatcher
from clients_scanner.scanner import ScapyScanner
from clients_scanner.scrolled_frame import VerticalScrolledFrame
from clients_scanner.utils import (get_proper_image, write_json,
                                   notification_sound, hide_console)
from clients_scanner.__version__ import __version__


class ScannerGUI(Frame, ConfigAndStyle):
    """clients scanner main class; provides gui and connection between other classes"""
    def __init__(self, master, log=log):
        ConfigAndStyle.__init__(self, master)
        super().__init__(master)
        if log is None:
            self.log = lambda text, color: print(colored(text, color))
        else:
            self.log = log

        # ******** components ********
        self.scanner = ScapyScanner(debug=False, scan=self.config['scan'])
        if not self.scanner.run():
            raise Exception('scanner failed to start properly, ssid, bssid: ({}, {})'.format(self.scanner.ssid, self.scanner.bssid))
        gateway_ip, gateway_mac = self.scanner.gateway_ip, self.scanner.gateway_mac
        self.deauthenticator = Deauthenticator(debug=False, gateway_ip=gateway_ip, gateway_mac=gateway_mac)
        self.deauthenticator.run()
        self.matcher = DevicesMatcher(scanner=self.scanner)
        self.matcher.run()
        self.hold_thread = False
        self.join_thread = False
        self.after_id = None  # id to be used when closing window
        self.log("[*] gui", self.color)

        # ******** setup ********
        self.ssid, self.bssid = self.scanner.ssid, self.scanner.bssid
        self.ssid_format = "SSID: {}"
        self.bssid_format = "BSSID: {}"

        self.rows_widgets = {}  # widgets reference
        self.top_widgets = {}  # ssid, bssid, buttons, label
        self.entries = {}  # entries reference
        self.clients_names = {}
        self.deauth_status = {}  # mac - status reference
        self.footer = None
        self.debug_text = None
        self.rows_frame = None

        # ******** create gui ********
        self.after_timeout = 500  # [ms]
        self.run_gui()
        self.update_rows_after()

    def update_rows_after(self):
        """update rows using table, with after method"""
        # handle on_closing method
        if (self.hold_thread) or (self.matcher is None):
            self.after_id = self.master.after(self.after_timeout, self.update_rows_after)
            return None

        # get table to be displayed
        table = []
        while not self.matcher.gui_table_queue.empty():
            table = self.matcher.gui_table_queue.get()

        # create or update gui rows
        self.gui_rows(table)

        # debug log
        self.pump_debug_logs()

        # call yourself
        self.after_id = self.master.after(self.after_timeout, self.update_rows_after)
        return None

    def pump_debug_logs(self):
        """get debug logs from queue and insert them into debug text view"""
        while True:
            row = self.log.get()
            if not row:
                break
            # log text
            date, text, color = row
            formatted = "{} {}\n".format(date, text)
            self.debug_text.insert(END, formatted, color)
            self.debug_text.see(END)

    def run_gui(self):
        """create widgets; use after specifing matcher and deauthenticator objects
        consider:
            self.master.geometry("{}x{}+333+50".format(self.initial_width, self.initial_height))
        """
        # ******** init gui ********
        # self.hide_console()
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.minsize(700, 80)  # width, height (minimal values for window)
        self.master.geometry("{}x{}".format(self.initial_width, self.initial_height))
        self.master.configure(background=self.widgets_bg_color)
        self.master.resizable(width=True, height=True)
        self.master.wm_title("scanner {}".format(__version__))
        self.pack()

        # ******** widgets ********
        self.gui_shape()

        # ******** lift, get focus ********
        self.master.attributes("-topmost", True)  # always on top
        self.master.update()
        self.master.attributes("-topmost", False)
        self.master.lift()  # move window to the top
        self.master.focus_force()
        return None

    def gui_shape(self):
        """run first time to create gui window with topbar; for now ssid and bssid are fixed"""
        # ******** define topbar frames ********
        topbar = Frame(self.master, relief=self.relief)
        topbar.pack(expand=NO, fill=BOTH, side=TOP)

        # use wrapper
        vertical_scrolled_frame = VerticalScrolledFrame(self.master, relief=self.relief, bg=self.widgets_bg_color)
        vertical_scrolled_frame.pack(expand=YES, fill=BOTH, side=TOP)

        # ******** frame for rows (common -> self) ********
        # just in case of problems with scrollbar
        # self.rows_frame = Frame(self.master, relief=self.relief)
        self.rows_frame = Frame(vertical_scrolled_frame, relief=self.relief, bg=self.widgets_bg_color)
        self.rows_frame.pack(expand=YES, fill=BOTH, side=TOP)

        # ******** footer ********
        self.footer = Frame(self.master, relief=self.relief)
        if self.config['debug']:
            self.footer.pack(expand=NO, fill=BOTH, side=BOTTOM)
        green = '#16C60C'
        self.debug_text = scrolledtext.ScrolledText(
            self.footer,
            height=20,
            font=self.mono_small,
            bg='black',
            fg=green,
            insertbackground=green,
        )
        self.debug_text.pack(expand=YES, fill=BOTH, side=TOP)
        # tag known colors
        self.debug_text.tag_config('red', foreground='red')
        self.debug_text.tag_config('cyan', foreground='cyan')
        self.debug_text.tag_config('green', foreground=green)
        self.debug_text.tag_config('yellow', foreground='yellow')
        self.debug_text.tag_config('magenta', foreground='magenta')

        # ******** ssid, bssid ********
        top_ssid = Label(
            topbar,
            relief=self.relief,
            font=self.mono_top,
            text=self.ssid_format.format(self.ssid),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_ssid.pack(expand=YES, fill=BOTH, side=LEFT)
        top_bssid = Label(
            topbar,
            relief=self.relief,
            font=self.mono_top,
            text=self.bssid_format.format(self.bssid),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        top_bssid.pack(expand=YES, fill=BOTH, side=LEFT)

        # ******** 1st button (night_mode) ********
        img = get_proper_image(self.night_mode_image, self.swap_image_color)
        top_night_mode_button = Button(
            topbar,
            font=self.mono_small,
            image=img,
            command=self.switch_night_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            borderwidth=4,
        )
        top_night_mode_button.image = img
        top_night_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ******** 2nd button (sound_mode) ********
        img = get_proper_image(self.sound_mode_image, self.swap_image_color)
        top_sound_mode_button = Button(
            topbar,
            font=self.mono_small,
            image=img,
            command=self.switch_sound_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            borderwidth=4,
        )
        top_sound_mode_button.image = img
        top_sound_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ******** 3rd button (scan_mode) ********
        img = get_proper_image(self.scan_mode_image, self.swap_image_color)
        scan_mode_button = Button(
            topbar,
            font=self.mono_small,
            image=img,
            command=self.switch_scan_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            borderwidth=4,
        )
        scan_mode_button.image = img
        scan_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ******** 4th button (debug_mode) ********
        img = get_proper_image(self.debug_mode_image, self.swap_image_color)
        debug_mode_button = Button(
            topbar,
            font=self.mono_medium,
            image=img,
            # text=self.debug_button_text,
            command=self.switch_debug_mode,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            borderwidth=4,
        )
        debug_mode_button.image = img
        debug_mode_button.pack(expand=YES, fill=BOTH, side=LEFT)

        # ******** widgets reference ********
        self.top_widgets = {
            "ssid": top_ssid,
            "bssid": top_bssid,
            "night_mode": top_night_mode_button,
            "sound_mode": top_sound_mode_button,
            "scan_mode": scan_mode_button,
            "debug_mode": debug_mode_button,
            "vertical_scrolled_frame": vertical_scrolled_frame,
        }
        return None

    def gui_rows(self, rows):
        """create or update gui rows
        name, vendor, ip, mac, visible = row
        """
        for row in rows:
            if row.mac in self.rows_widgets:
                # already exist, just update
                self.update_row(row)
            else:
                # create new row at the bottom
                self.create_row(row)
                if self.config["sound"]:
                    notification_sound()
                    self.log("[+] new device (sound here)", self.color)
        return None

    def create_row(self, table_row):
        """create new single row
        pass index for colorizing rows
        name, vendor, ip, mac, visible = row
        """
        name, vendor, ip, mac, visible = table_row
        visible_color = self.color_by_status(visible)
        visible_text = self.active_text_by_status(visible)
        self.deauth_status[mac] = False

        # ******** main rows ********
        row_wrapper = Frame(self.rows_frame, relief=self.relief)
        row_wrapper.pack(expand=NO, fill=BOTH, side=TOP)
        row = Frame(row_wrapper, relief=self.relief)
        row.pack(expand=YES, fill=BOTH, side=TOP)

        # remove button (for removing ghost clients)
        remove_client_button = Button(
            row,
            font=self.serif,
            text="X",
            command=lambda ip=ip, mac=mac: self.remove_client(ip, mac),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            justify="center",
        )
        remove_client_button.pack(expand=NO, fill=BOTH, side=LEFT)

        img = get_proper_image(name, self.swap_image_color)
        image_label = Label(row, relief=self.relief, image=img, bg=self.widgets_bg_color)
        image_label.image = img  # remember to keep a reference
        image_label.name = name  # name for something
        image_label.pack(expand=NO, fill=BOTH, side=LEFT, ipadx=5)

        # Label -> Entry widget
        str_var = StringVar()
        client_name_entry = Entry(
            row,
            relief=self.entry_relief,
            font=self.mono_medium,
            textvariable=str_var,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
            insertbackground=self.widgets_fg_color,
            justify="center",
            width=20,
        )
        client_name_entry.insert(0, name)
        client_name_entry.bind("<Return>", partial(self.entry_callback, mac))
        client_name_entry.pack(expand=NO, fill=BOTH, side=LEFT)
        self.entries[mac] = client_name_entry

        # Frame (3 labels -> device, ip, mac)
        info_frame = Frame(row, relief=self.relief)
        info_frame.pack(expand=YES, fill=BOTH, side=LEFT)
        # https://stackoverflow.com/questions/9996599/tkinters-pack-propagate-method
        # https://stackoverflow.com/questions/11949391/how-do-i-use-tkinter-to-create-line-wrapped-text-that-fills-the-width-of-the-win
        info_frame.pack_propagate(0)

        # device
        info_frame_device = Label(
            info_frame,
            relief=self.relief,
            font=self.mono_small,
            # text=vendor*4,  # FOR DEBUG
            text=vendor,
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        info_frame_device.pack(expand=YES, fill=BOTH, side=TOP)

        # ip & mac frame
        info_frame_bottom = Frame(info_frame, relief=self.relief)
        info_frame_bottom.pack(expand=YES, fill=BOTH, side=TOP)

        # ip
        info_frame_ip = Label(
            info_frame_bottom,
            relief=self.relief,
            font=self.mono_small,
            text=ip.center(15),
            bg=self.widgets_bg_color,
            fg=self.widgets_fg_color,
        )
        info_frame_ip.pack(expand=YES, fill=BOTH, side=LEFT)

        # mac
        info_frame_mac = Label(
            info_frame_bottom,
            relief=self.relief,
            font=self.mono_small,
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
            font=self.mono_small,
            text=self.deauth_button_deauth_text,
            command=lambda ip=ip, mac=mac: self.switch_deauth_mode(ip, mac),
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

    def remove_client(self, ip, mac):
        """remove client specified by mac"""
        # filter out and remove mac definition
        self.matcher.filter_out_table_queue(mac)  # workaround

        # clear deauth
        self.deauthenticator.deauth_queue.put((mac, ip, False))

        # pack_forget widget
        current_row_widgets = self.rows_widgets.get(mac, False)
        row_wrapper_widget = current_row_widgets.get("row_wrapper")
        row_wrapper_widget.pack_forget()
        self.rows_widgets.pop(mac)
        self.entries.pop(mac)

        # destroy widget and it childs
        for child in row_wrapper_widget.winfo_children():
            child.destroy()
            del child
        del row_wrapper_widget

        # collect garbage
        gc.collect()

        self.log("[!] row unpacked for: {}".format(mac), self.color)
        return None

    def switch_deauth_mode(self, victim_ip, victim_mac):
        """switch button"""
        # ******** gui update ********
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

        # ******** data for deatuch object ********
        self.log("[*] client to deauth: ({}, {})".format(victim_mac, victim_ip), self.color)
        self.deauthenticator.deauth_queue.put((victim_mac, victim_ip, status))
        return None

    def update_row(self, row):
        """update row for specified mac address

        row: GuiRow(
            name='unknown',
            vendor='vendor',
            ip='1.2.3.4',
            mac='aa:bb:cc:dd:ee:ff',
            visible=False
            )
        """
        ip = row.ip
        mac = row.mac
        visible = row.visible
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
            self.log("[*] ip updated from {} to {}".format(info_frame_ip.cget("text").strip(), ip), self.color)
            info_frame_ip.config(text=ip.center(15))
        return None

    def on_closing(self, force=False):
        """handle closing; https://stackoverflow.com/questions/111155/how-do-i-handle-the-window-close-event-in-tkinter"""
        self.hold_thread = True
        self.scanner.hold_thread = True
        self.matcher.hold_thread = True
        self.deauthenticator.hold_thread = True

        if force or messagebox.askokcancel("Quit", "Do you want to quit?"):
            # ****** save config data ******
            self.config["height"] = self.master.winfo_height()
            self.config["width"] = self.master.winfo_width()
            write_json(self.config_file, self.config)
            self.matcher.save_clients_db()

            # ****** destroy main app ******
            # https://stackoverflow.com/questions/26168967/invalid-command-name-while-executing-after-script
            # http://web.archive.org/web/20201112030233/http://effbot.org/tkinterbook/widget.htm
            # If you have a manual quit button, you can use the after_cancel() method
            # to cancel an after method before calling root.destroy() to kill your program
            # example: id = w.after(time, callback)
            self.master.after_cancel(self.after_id)
            self.master.destroy()

            # ****** join threads etc ******
            self.scanner.join_thread()
            self.log("[*] scanner thread joined", self.color)
            self.matcher.join_thread()
            self.log("[*] matcher thread joined", self.color)
            self.deauthenticator.join_thread()
            self.log("[*] deauthenticator thread joined", self.color)
        else:
            # ****** release threads ******
            self.hold_thread = False
            self.scanner.hold_thread = False
            self.matcher.hold_thread = False
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
            img = get_proper_image(entry_text, self.swap_image_color)
            image_label.config(image=img)
            image_label.image = img
            image_label.name = entry_text

            # ****** send new name to matcher ******
            self.matcher.names_queue.put({mac: entry_text})

        # ****** set focus on next entry ******
        entries_keys = list(self.entries.keys())
        current_index = entries_keys.index(mac)
        if current_index+1 >= len(entries_keys):
            self.master.focus()
            return None
        next_entry_mac = entries_keys[current_index+1]
        self.entries[next_entry_mac].focus()
        return None

    def switch_night_mode(self):
        """switch night mode -> on/off"""
        self.config["night"] = not self.config["night"]
        self.config["height"] = self.master.winfo_height()
        self.config["width"] = self.master.winfo_width()
        write_json(self.config_file, self.config)

        self.set_night_mode_attributes()
        self.master.configure(background=self.widgets_bg_color)

        # ******** switch topbar color ********
        # rows_frame is orphan so do it like that for now :(
        self.rows_frame.config(bg=self.widgets_bg_color)
        for key, value in self.top_widgets.items():
            if key == "night_mode":
                img = get_proper_image(self.night_mode_image, self.swap_image_color)
                value.config(image=img)
                value.image = img
            elif key == "sound_mode":
                img = get_proper_image(self.sound_mode_image, self.swap_image_color)
                value.config(image=img)
                value.image = img
            elif key == "scan_mode":
                img = get_proper_image(self.scan_mode_image, self.swap_image_color)
                value.config(image=img)
                value.image = img
            elif key == "debug_mode":
                img = get_proper_image(self.debug_mode_image, self.swap_image_color)
                value.config(image=img)
                value.image = img
            elif key == "vertical_scrolled_frame":
                # canvas has only background
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
            # image color swap
            name = value["image_label"].name
            img = get_proper_image(name, self.swap_image_color)
            value["image_label"].config(image=img)
            value["image_label"].image = img

            # widgets colors by rows iteration
            for item in items_to_color:
                value[item].config(bg=self.widgets_bg_color, fg=self.widgets_fg_color)

            # entry widget cursor blink
            value["client_name_entry"].config(insertbackground=self.widgets_fg_color)
        return None

    def switch_sound_mode(self):
        """switch sound mode -> on/off"""
        self.config["sound"] = not self.config["sound"]
        write_json(self.config_file, self.config)

        if self.config["sound"]:
            self.sound_mode_image = "sound_on"
        else:
            self.sound_mode_image = "sound_off"

        img = get_proper_image(self.sound_mode_image, self.swap_image_color)
        top_sound_mode_button = self.top_widgets["sound_mode"]
        top_sound_mode_button.config(image=img)
        top_sound_mode_button.image = img
        self.log('[*] sound status: {}'.format(self.config["sound"]), self.color)
        return None

    def switch_scan_mode(self):
        """switch scan mode -> on/off"""
        self.config["scan"] = not self.config["scan"]
        self.scanner.hold_thread = (not self.config["scan"])
        write_json(self.config_file, self.config)

        if self.config["scan"]:
            self.scan_mode_image = "scan_on"
        else:
            self.scan_mode_image = "scan_off"

        img = get_proper_image(self.scan_mode_image, self.swap_image_color)
        scanner_setup_button = self.top_widgets["scan_mode"]
        scanner_setup_button.config(image=img)
        scanner_setup_button.image = img
        self.log('[*] scanner status: {}'.format(self.config["scan"]), self.color)
        return None

    def switch_debug_mode(self):
        """switch debug between on/off modes"""
        self.config['debug'] = not self.config['debug']
        write_json(self.config_file, self.config)
        if self.config['debug']:
            self.debug_button_text = "debug\non"
            self.footer.pack(expand=NO, fill=BOTH, side=TOP)
        else:
            self.debug_button_text = "debug\noff"
            self.footer.pack_forget()
        debug_button = self.top_widgets["debug_mode"]
        debug_button.config(text=self.debug_button_text)
        self.log('[*] debug status: {}'.format(self.config['debug']), self.color)
        return None


def scanner(hide=False):
    """commandline entrypoint"""
    if os.name == "nt":
        os.system("color")
        if hide:
            # for now supported on Windows only
            hide_console()
    try:
        app = ScannerGUI(master=Tk())
        app.mainloop()
    except KeyboardInterrupt:
        app.on_closing(force=True)
    return None


if __name__ == "__main__":
    scanner()
