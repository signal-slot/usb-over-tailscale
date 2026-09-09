import serial, sys, time
port = sys.argv[1]; secs = float(sys.argv[2]); reset = len(sys.argv) > 3 and sys.argv[3] == 'reset'
s = serial.Serial(port, 115200, timeout=0.2)
if reset:
    s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False
end = time.time() + secs
buf = b''
while time.time() < end:
    buf += s.read(4096)
sys.stdout.write(buf.decode('utf-8', 'replace'))
