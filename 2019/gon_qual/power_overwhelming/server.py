#!/usr/bin/env python2.7
import os
import sys
import time
import struct
import subprocess

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)


def write(buf):
    sys.stdout.write(buf)
    sys.stdout.flush()


def main():
    LIBC = None
    try:
        pipe = subprocess.Popen(['./power'],
                                stdin=subprocess.PIPE, stdout=sys.stdout)
        time.sleep(0.1)
        with open("/proc/{:d}/maps".format(pipe.pid)) as f:
            for line in f.readlines():
                if 'stack' in line:
                    STACK = int(line.split('-')[0], 16)
                elif LIBC is None and 'libc' in line:
                    LIBC = int(line.split('-')[0], 16)

        write("What a kind!\n")
        write('Stack: {:8x}\n'.format(STACK))
        write('Libc: {:8x}\n'.format(LIBC))
        # read ./flag
        write('Since you cannot communicate with binary, '
              'I think you should build open, read, write chain!\n')
        payload = []
        while len(payload) < (0x1800 // 4):
            write('>')
            pay = raw_input()
            if pay == '':
                break
            try:
                pay = int(pay, 16) & 0xffffffff
            except:
                write('What are you doing?\n')
                exit(0)

            # You can only use stack, and text except plt, got, and bss
            if 0x8048470 < pay < 0x8048927 or pay > STACK:
                payload.append(pay)
            else:
                write('Nope:%x\n' % pay)
                exit(0)
        write('Now Exploit!\n')
        _input = ''.join(map(lambda x: struct.pack('<I', x), payload))
        pipe.stdin.write(_input.ljust(0x1800))
        time.sleep(0.5)
        pipe.wait()
    except KeyboardInterrupt:
        write("bye~~\n")
        pipe.kill()
    except Exception:
        write('something wrong... tell admin\n')
        pipe.kill()
    finally:
        exit(0)


if __name__ == '__main__':
    main()

