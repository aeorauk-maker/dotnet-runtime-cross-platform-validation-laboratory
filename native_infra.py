"""Owned-lab Redis observation helpers; never imported by the HTTP actor."""

import os
import subprocess
import time


def redis_cmd(command, buyer_id, value=None):
    container = os.environ["G06_REDIS_CONTAINER"]
    envs = ["-e", "BASKET_ID=" + buyer_id]
    if value is not None:
        envs += ["-e", "BASKET_JSON=" + value]
    script = 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli -p 6380 ' + command + ' "/basket/$BASKET_ID"'
    if value is not None:
        script += ' "$BASKET_JSON"'
    result = subprocess.run(["docker", "exec", *envs, container, "sh", "-c", script],
                            check=True, capture_output=True, text=True, timeout=15)
    return result.stdout.strip()


def wait_redis_absent(buyer_id):
    for _ in range(40):
        if redis_cmd("EXISTS", buyer_id) == "0":
            return True
        time.sleep(0.25)
    return False
