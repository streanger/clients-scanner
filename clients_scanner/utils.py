import ctypes
import json
import os
import sys
import time
import pkg_resources
from pathlib import Path

# external modules
from PIL import Image, ImageDraw, ImageOps, ImageTk
from playsound import playsound


PLATFORM = sys.platform


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


def hide_console():
    """hide console window"""
    if os.name == "nt":
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0
        )
    return None


def static_file_path(directory, filename):
    """get path of the specified filename from specified directory"""
    resource_path = "/".join((directory, filename))  # Do not use os.path.join()
    try:
        template = pkg_resources.resource_filename(__name__, resource_path)
    except KeyError:
        # empty string cause AttributeError, and non empty FileNotFoundError
        return ("none")
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


def get_proper_image(name, swap_image_color):
    """get proper image, for specified name; if image does not exists, draw circle
    
    https://stackoverflow.com/questions/14350645/is-there-an-antialiasing-method-for-python-pil
    """
    pairs = {
        "router": "router.png",
        "pc": "pc.png",
        "debug": "debug.png",
        "laptop": "laptop.png",
        "phone": "phone.png",
        "watch": "watch.png",
        "scan_on": "scan_on.png",
        "scan_off": "scan_off.png",
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
        img = Image.new("RGBA", (128, 128))
        draw = ImageDraw.Draw(img)
        draw.ellipse((0, 0, 127, 127), outline="black", width=5)
        img = img.resize((32, 32), resample=Image.ANTIALIAS)

    # swap image color, to fit current night mode
    if swap_image_color:
        if img.mode == "RGBA":
            r_origin, g_origin, b_origin, a_origin = img.split()
            rgb_image = Image.merge("RGB", (r_origin, g_origin, b_origin))
            inverted_image = ImageOps.invert(rgb_image)
            r_inv, g_inv, b_inv = inverted_image.split()
            img = Image.merge("RGBA", (r_inv, g_inv, b_inv, a_origin))
        else:
            img = ImageOps.invert(img)

    img.thumbnail((32, 32), resample=Image.ANTIALIAS)
    img = ImageTk.PhotoImage(img)
    return img


def notification_sound():
    """play notification sound

    https://mixkit.co/free-sound-effects/notification/
    mixkit-long-pop-2358.wav
    mixkit-message-pop-alert-2354.mp3
    """
    if PLATFORM == 'win32':
        sound_file = static_file_path("sounds", "mixkit-message-pop-alert-2354.mp3")
        playsound(sound_file, block=False)
    elif PLATFORM == 'linux':
        # TODO: fix issues with ALSA
        # INFO: non-blocking mode doesn't work under linux
        #       so the solution might be use of threads
        # sound_file = static_file_path("sounds", "mixkit-message-pop-alert-2354.mp3")
        # thread = Thread(target=playsound, args=(sound_file,))
        # thread.start()
        pass
    else:
        # not supported; make issue or pull request if needed
        pass
    return None


if __name__ == "__main__":
    print('import it as module rather than call')
