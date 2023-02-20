import time
from queue import Queue
from termcolor import colored


class Logger():
    """
    dummy wrapper for Queue
    inb4 you could derive from Queue - kinda yes
    """
    def __init__(self, print=True):
        self.log = Queue()
        self.print = print  # print to terminal

    def __call__(self, *args, **kwargs):
        """wrapper to self.put method"""
        self.put(*args, **kwargs)
        return None

    def put(self, text, color):
        """wrapper for log queue put method"""
        now = self.datetime_now()
        self.log.put((now, text, color))
        if self.print:
            print(colored("{} {}".format(now, text), color))
        return True

    def get(self):
        """wrapper for log queue get method"""
        if not self.log.empty():
            return self.log.get()
        return False

    def datetime_now(self):
        """return current date & time"""
        return time.strftime('%Y-%m-%d %H:%M:%S')

log = Logger(print=False)


if __name__ == "__main__":
    log = Logger()
    log.put('test 1', 'red')
    log.put('test 2', 'green')
    log.put('test 3', 'yellow')

    while True:
        out = log.get()
        if not out:
            break
        print(out)
