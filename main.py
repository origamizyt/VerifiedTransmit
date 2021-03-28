import sys

HOST = 'localhost'
PORT = 5000

from channels import Server
import logging, time

def wait_forever():
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt: pass

class Logger:
    _buffer = ''
    def write(self, text: str):
        if text.startswith('\r'):
            print(text, file=sys.__stdout__, end='')
            return
        self._buffer += text
        while '\n' in self._buffer:
            data, self._buffer = self._buffer.split('\n', 2)
            if data:
                logging.info(data)
            else:
                print(file=sys.__stdout__) # new line
    flush = close = lambda self: None

if not '-nolog' in sys.argv:
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s:%(threadName)s] %(message)s')
    sys.stdout = Logger()

if '-stop' in sys.argv:
    print('Stopping server...')

s = Server(PORT)
s.prepare()
logging.info('Server running on 0.0.0.0:%i' % PORT)
if '-block' in sys.argv:
    s.serve()
else:
    s.serve(True)
    wait_forever()
sys.stdout = sys.__stdout__
logging.info('Server stopped.')