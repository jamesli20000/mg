#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import zmq
import time
import string

#reload(sys)
#sys.setdefaultencoding("utf-8")


def start_client(ip_addr, port, channel):
    port = port
    ip_addr = ip_addr

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect("tcp://%s:%s" % (ip_addr, port))

    socket.setsockopt(zmq.SUBSCRIBE, channel.encode("ascii"))

    while True:
        msg = socket.recv()
        print("recv:"+str(len(msg))+"bytes")
        #time.sleep(2)


if __name__ == "__main__":
    start_client(sys.argv[1], sys.argv[2], sys.argv[3])