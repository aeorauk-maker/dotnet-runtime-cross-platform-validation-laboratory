#!/usr/bin/env bash
set -euo pipefail
echo 'SERVICE_ENTRY_CODE_READY'
control=/tmp/eop062-r14-service-control.env
for _ in $(seq 1 1800); do
    if [[ -f "$control" ]]; then break; fi
    sleep .1
done
test -f "$control"
source "$control"
rm -f "$control"
echo 'SERVICE_ENTRY_CONTROL_RECEIVED'
perl /opt/eop062-autostart-fake.pl "$EOP062_MODE" "$EOP062_PORT"
echo 'SERVICE_ENTRY_RESULT=PASS'
exec sleep infinity
