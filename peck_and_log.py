import argparse
import subprocess
import logging
import coloredlogs
import time
import os
import tempfile
import shutil

from tlscanary import xpcshell_worker, firefox_app, worker_pool
import tcpdump_worker


# Initialize coloredlogs
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)
coloredlogs.DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s %(threadName)s %(name)s %(message)s"
coloredlogs.install(level="INFO")

parser = argparse.ArgumentParser(prog="peck_and_log")
parser.add_argument("-d", "--debug", help="Enable debug", action="store_true")
parser.add_argument("--host", help="Host to peck", default="news.ycombinator.com")
parser.add_argument("-a", "--app", help="Path to Firefox", default=os.path.expanduser("~/.tlscanary/cache/firefox-nightly_osx"))
parser.add_argument("-s", "--sudo", help="Path to sudo", default="/usr/bin/sudo")
parser.add_argument("-t", "--tcpdump", help="Path to tcpdump", default="/usr/sbin/tcpdump")
parser.add_argument("--timeout", help="Connection timeout", default=10)

args = parser.parse_args()

if args.debug:
    coloredlogs.install(level='DEBUG')

timeout = args.timeout
app = firefox_app.FirefoxApp(args.app)

logger.info("firefox binary: {}".format(app.exe))
logger.info("sudo binary: {}".format(args.sudo))
logger.info("tcpdump binary: {}".format(args.tcpdump))


wakeup_cmd = xpcshell_worker.Command("wakeup")
scan_cmd = xpcshell_worker.Command("scan", host=args.host, rank=None, include_certificates=False, timeout=timeout)

is_running = True

tcpdumpw = tcpdump_worker.TCPDumpWorker(args.tcpdump, sudo=args.sudo)

total_count = 0
failed_count = 0
failed_pcaps = []


try:
  while is_running:

    profile_dir = tempfile.mkdtemp()

    # Spawn a worker instance
    xpcw = xpcshell_worker.XPCShellWorker(app, profile=profile_dir, prefs=None)
    xpcw.spawn()

    xpcw.send(scan_cmd)
    xpcw.send(wakeup_cmd)

    connection_okay = False

    temp_dir = tempfile.mkdtemp()
    fd, pcap_file=tempfile.mkstemp(".pcap", dir=temp_dir)
    os.close(fd) # We don't need it, and we don't want to hold the handle open

    tcpdumpw.start_session(pcap_file=pcap_file, host=args.host)

    timeout_time = time.time() + timeout + 1
    while time.time() < timeout_time:

      for response in xpcw.receive():
        logger.debug("{} {} {}".format(response, response.result, response.original_cmd))

        if response.result == "ACK":
          if response.original_cmd["mode"] == "scan":
              timeout_time = time.time() + timeout + 1
          # Ignore other ACKs.
          continue

        if response.original_cmd["mode"] == "scan":
          result = worker_pool.ScanResult(response)
          connection_okay = result.success
          logger.info("ScanResult: {}: Success: {} [{}]".format(result.host, result.success, result.rank))
          timeout_time = 0

      if xpcw.send(wakeup_cmd):
        time.sleep(1.0)

    tcpdumpw.end_session()

    total_count += 1

    if connection_okay:
      logger.info("Deleting OK pcap file: {}".format(pcap_file))
      os.remove(pcap_file)
    else:
      logger.info("Bad capture in {}".format(pcap_file))
      failed_pcaps.append(pcap_file)
      failed_count += 1

    # Wind down the worker
    xpcw.send(xpcshell_worker.Command("quit"))
    xpcw.terminate()

    # Wait between runs
    time.sleep(10.0)

    # Clean up the old profile
    logger.debug("Cleaning up profile directory {}".format(profile_dir))
    shutil.rmtree(profile_dir)

except KeyboardInterrupt:
    logger.critical("\nUser interrupt. Quitting...")


logger.info("Failed pcap files:")
for cap in failed_pcaps:
  logger.info(cap)

logger.info("Exited. Failed count = {}, total count = {}".format(failed_count, total_count))