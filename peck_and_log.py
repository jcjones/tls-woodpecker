import subprocess
import logging
import coloredlogs
import time

from tlscanary import xpcshell_worker, firefox_app, worker_pool


# Initialize coloredlogs
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)
coloredlogs.DEFAULT_LOG_FORMAT = "%(asctime)s %(levelname)s %(threadName)s %(name)s %(message)s"
coloredlogs.install(level="INFO")

timeout = 30
app = firefox_app.FirefoxApp("/Users/jcjones/.tlscanary/cache/firefox-nightly_osx")
profile = "/tmp/profile_dir"

# Spawn a worker instance
xpcw = xpcshell_worker.XPCShellWorker(app, profile=profile, prefs=None)
xpcw.spawn()

wakeup_cmd = xpcshell_worker.Command("wakeup")

scan_cmd = xpcshell_worker.Command("scan", host="pugsplace.net", rank=None, include_certificates=False, timeout=timeout)

is_running = True

while is_running:
  xpcw.send(scan_cmd)
  xpcw.send(wakeup_cmd)

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
        logger.info("ScanResult: {}: Success: {} [{}]".format(result.host, result.success, result.rank))
        timeout_time = 0

    if xpcw.send(wakeup_cmd):
      time.sleep(1.0)

  # Wait between runs
  time.sleep(5.0)

# Wind down the worker
xpcw.send(xpcshell_worker.Command("quit"))
xpcw.terminate()

logger.info("Exited")