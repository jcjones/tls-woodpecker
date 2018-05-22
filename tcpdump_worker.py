import subprocess
import logging
import time

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
      cmd = [self.__sudo, "-A"] + cmd

    logger.debug("Executing worker shell command `%s`" % ' '.join(cmd))

    self.__worker_thread = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1)  # `1` means line-buffered

    time.sleep(0.5) # run a moment, check for immediate failures
    if self.__worker_thread.poll() is not None:
      logger.error("tcpdump exited immediately [code={}]: {}".format(self.__worker_thread.returncode, ' '.join(cmd)))
      if self.__sudo is not None:
        logger.warning("Since you're using sudo ({}), you'll want to either make sure sudo is".format(self.__sudo))
        logger.warning("already authorized before launching this program, make sure either the SUDO_ASKPASS")
        logger.warning("environment variable is set, or that sudo.conf has a path to askpass set.")
        logger.warning("See 'man sudo' manual page for details.")
      raise Exception("tcpdump immediate error")

  def end_session(self):
    self.__worker_thread.stdin.close()
    # self.__worker_thread.terminate()

