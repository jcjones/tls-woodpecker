import subprocess
import logging
import coloredlogs
import time
import os
import tempfile

from tlscanary import xpcshell_worker, firefox_app, worker_pool
import tcpdump_worker


# Initialize coloredlogs
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)
coloredlogs.DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s %(threadName)s %(name)s %(message)s"
coloredlogs.install(level="INFO")

timeout = 30
app = firefox_app.FirefoxApp("/Users/jcjones/.tlscanary/cache/firefox-nightly_osx")
profile = "/tmp/profile_dir"
host = "news.ycombinator.com"

# Spawn a worker instance
xpcw = xpcshell_worker.XPCShellWorker(app, profile=profile, prefs=None)
xpcw.spawn()

wakeup_cmd = xpcshell_worker.Command("wakeup")

scan_cmd = xpcshell_worker.Command("scan", host=host, rank=None, include_certificates=False, timeout=timeout)

is_running = True

tcpdumpw = tcpdump_worker.TCPDumpWorker("/usr/sbin/tcpdump", sudo="/usr/bin/sudo")

total_count = 0
failed_count = 0
failed_pcaps = []

try:
  while is_running:
    xpcw.send(scan_cmd)
    xpcw.send(wakeup_cmd)

    connection_okay = False

    temp_dir = tempfile.mkdtemp()
    _, pcap_file=tempfile.mkstemp(".pcap", dir=temp_dir)

    tcpdumpw.start_session(pcap_file=pcap_file, host=host)

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

    # Wait between runs
    time.sleep(10.0)
except KeyboardInterrupt:
    logger.critical("\nUser interrupt. Quitting...")

# Wind down the worker
xpcw.send(xpcshell_worker.Command("quit"))
xpcw.terminate()

logger.info("Failed pcap files:")
for cap in failed_pcaps:
  logger.info(cap)

logger.info("Exited. Failed count = {}, total count = {}".format(failed_count, total_count))