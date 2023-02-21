import os

# external modules
from tkinter import font
from termcolor import colored

# my modules
from clients_scanner.logger import log
from clients_scanner.utils import read_json, get_config_directory, get_proper_image


class ConfigAndStyle:
    """class that provides config and style for GuiClass"""
    def __init__(self, master, log=log) -> None:
        self.color = "cyan"
        if log is None:
            self.log = lambda text, color: print(colored(text, color))
        else:
            self.log = log
        self.log('[*] config init', self.color)
        self.config_file = "config.json"
        self.config_directory = get_config_directory()
        self.log("[*] config_directory: {}".format(self.config_directory), self.color)
        self.config_file = self.config_directory.joinpath(self.config_file)
        self.log("[*] config_file: {}".format(self.config_file), self.color)
        self.config = read_json(self.config_file)
        if not self.config:
            self.config = {
                "night": False,
                "sound": True,
                "scan": True,
                "debug": False,
                "width": 750,
                "height": 600,
            }
        if self.config["sound"]:
            self.sound_mode_image = "sound_on"
        else:
            self.sound_mode_image = "sound_off"

        self.original_color = master.cget("background")
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

        # scan mode
        if self.config['scan']:
            self.scan_mode_image = 'scan_on'
        else:
            self.scan_mode_image = 'scan_off'

        # debug mode
        if self.config['debug']:
            self.debug_mode_image = "debug"
            self.debug_button_text = "debug\non"
        else:
            self.debug_button_text = "debug\noff"
            self.debug_mode_image = "debug"

        # ******** app gui, consts, variables ********
        # raised, sunken, flat, ridge, solid, groove
        self.relief = "groove"
        self.entry_relief = "sunken"
        if os.name == "nt":
            self.app_font = "Source Code Pro Medium"
        else:
            self.app_font = "DejaVu Sans Mono"
        self.serif_family = "Noto Serif"
        self.mono_small = font.Font(family=self.app_font, size=8, weight="normal")
        self.mono_medium = font.Font(family=self.app_font, size=9, weight="normal")
        self.mono_top = font.Font(family=self.app_font, size=9, weight="normal")
        self.mono_big = font.Font(family=self.app_font, size=11, weight="normal")
        self.mono_large = font.Font(family=self.app_font, size=12, weight="normal")
        self.serif = font.Font(family=self.serif_family, size=13, weight="bold")

    def set_night_mode_attributes(self):
        """set attributes depend on night mode status"""
        bg_dark_color, bg_bright_color, = ("black", self.original_color,)
        fg_dark_color, fg_bright_color = "black", "yellow"
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
