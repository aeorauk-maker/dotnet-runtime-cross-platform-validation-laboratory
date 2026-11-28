#!/usr/bin/env bash
set -euo pipefail

# This runs as the GitHub-managed service's entrypoint, before job steps.
# Source is public inert lab code, pinned by its content hash.
actor=/tmp/eop062-r14-autostart-fake.pl
control=/tmp/eop062-r14-service-control.env
url='https://raw.githubusercontent.com/aeorauk-maker/dotnet-runtime-cross-platform-validation-laboratory/rank-14-eop062-pa30-20261128/eop062-autostart-fake.pl'
curl --fail --silent --show-error --location "$url" --output "$actor"
printf '%s  %s\n' '58eb8c530a4af76027044b0854392fb2007e2d349a46194fade389c534dcc317' "$actor" | sha256sum --check --status
echo 'SERVICE_ENTRY_CODE_READY'

for _ in $(seq 1 1800); do
    if [[ -f "$control" ]]; then break; fi
    sleep .1
done
test -f "$control"
# The host harness supplies only the actor's own Low credential and public
# coordinates; Owner credential, protected secret and project are absent.
source "$control"
rm -f "$control"
echo 'SERVICE_ENTRY_CONTROL_RECEIVED'
perl "$actor" "$EOP062_MODE" "$EOP062_PORT"
echo 'SERVICE_ENTRY_RESULT=PASS'
exec sleep infinity
