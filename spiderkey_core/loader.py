import threading
import time

class Loader:
    def __init__(self, message="Processing"):
        self.message = message
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.start()

    def _animate(self):
        i = 0
        dots = ['.  ', '.. ', '...']
        while self.running:
            print(f"\r{self.message}{dots[i % 3]}", end="", flush=True)
            i += 1
            time.sleep(0.5)
        print("\r" + " " * (len(self.message) + 3) + "\r", end="", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
