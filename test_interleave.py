#!/usr/bin/env python3

import time
import threading

t1 = threading.Thread(target=time.sleep, args=(1,))
t2 = threading.Thread(target=time.sleep, args=(1.5,))
t3 = threading.Thread(target=time.sleep, args=(0.5,))

t1.start()
t2.start()
t3.start()
t2.join()
t1.join()
