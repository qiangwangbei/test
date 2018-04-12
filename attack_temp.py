#!/usr/bin/env python
# Designed for use with boofuzz v0.0.1-dev3

from boofuzz import *
from pwn import *


context.terminal = ['tmux', 'splitw', '-v']

def fuzz():

    target_host='106.75.66.195'
    target_port=20000
    name = './pwnme'
    local = False 

    if local:
        target = process(name)
    else:
        target = Target(connection=SocketConnection(target_host, target_port, proto='tcp'))
    
    session = Session(target=target, target_name = name, local=local)

    s_initialize('who')
    s_string('name')
    s_static('1\n')

    s_initialize('real')
    s_string('password')
    s_static('1\n')

    session.connect(s_get('who'))
    session.connect(s_get('who'), s_get('real'))

    session.fuzz()


if __name__ == '__main__':

    fuzz()

    pass




