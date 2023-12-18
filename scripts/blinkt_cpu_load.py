#!/usr/bin/env python
# Courtesy of https://github.com/pimoroni/blinkt/blob/master/examples/cpu_load.py

import time
from sys import exit

try:
    import psutil
except ImportError:
    exit('This script requires the psutil module\nInstall with: sudo apt install python3-psutil')

import blinkt

blinkt.set_clear_on_exit()


def show_graph(v, r, g, b):
    v *= blinkt.NUM_PIXELS
    for x in range(blinkt.NUM_PIXELS):
        if v < 0:
            r, g, b = 0, 0, 0
        else:
            r, g, b = [int(min(v, 1.0) * c) for c in [r, g, b]]
        blinkt.set_pixel(x, r, g, b)
        v -= 1

    blinkt.show()


blinkt.set_brightness(0.1)

while True:
    v = psutil.cpu_percent() / 100.0
    if v <= .25:
        # green
        show_graph(v, 0, 255, 0)
    elif v > .25 and v <= .5:
        # yellow
        show_graph(v, 255, 191, 0)
    elif v > .5 and v <= .75:
        # orange
        show_graph(v, 255, 136, 0)
    elif v > .75:
        # red
        show_graph(v, 255, 0, 0)
    time.sleep(0.5)
