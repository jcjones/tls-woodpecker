import subprocess
import logging

logger = logging.getLogger(__name__)

class TCPDumpWorker(object):
  def __init__(self, app, sudo=None):
    self.__app = app
    self.__sudo = sudo
    self.__worker_thread = None

  def start_session(self, pcap_file="/tmp/out.pcap", host="localhost"):
    global logger, module_dir

    cmd = [self.__app, '-w', pcap_file, 'tcp port 443 and host {}'.format(host)]

    if self.__sudo is not None:
      cmd.insert(0, self.__sudo)

    logger.debug("Executing worker shell command `%s`" % ' '.join(cmd))

    self.__worker_thread = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1)  # `1` means line-buffered

  def end_session(self):
    self.__worker_thread.stdin.close()
    # self.__worker_thread.terminate()

