#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import zmq
import time
import string
import random

#reload(sys)
#sys.setdefaultencoding("utf-8")


def start_client(ip_addr, port, channel):
    port = port
    ip_addr = ip_addr
    
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.connect("tcp://%s:%s" % (ip_addr, port))
     
    while True:
        msg = "%s random() :%f " %(channel,random.random())
        socket.send(msg.encode("ascii"))
        time.sleep(1)


if __name__ == "__main__":
    start_client(sys.argv[1], sys.argv[2], sys.argv[3])