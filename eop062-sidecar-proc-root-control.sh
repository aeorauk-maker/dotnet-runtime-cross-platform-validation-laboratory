#!/usr/bin/env bash
set -euo pipefail

suffix="$(date +%s)-$$"
victim="eop062-r14-proc-victim-$suffix"
volume="eop062-r14-proc-tmp-$suffix"
lab="$(mktemp -d)"
runner_uid="$(id -u)"
runner_gid="$(id -g)"
cleanup() {
  docker rm -f "$victim" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$lab"
}
trap cleanup EXIT

mkdir "$lab/source"
printf 'original\n' > "$lab/source/protected.txt"
chmod 0700 "$lab/source"
chmod 0600 "$lab/source/protected.txt"
docker volume create "$volume" >/dev/null

docker run -d --name "$victim" --network none --user "$runner_uid:$runner_gid" \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$lab/source:/src:rw" -v "$volume:/tmp" \
  alpine:3.21 sh -c 'sleep 90' >/dev/null

echo 'CASE=separate-pid-same-uid-shared-tmp'
docker run --rm --network none --user "$runner_uid:$runner_gid" \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$volume:/tmp" alpine:3.21 sh -c '
    test ! -e /src/protected.txt
    test ! -e /proc/1/root/src/protected.txt
    echo "SOURCE_ABSENT_IN_ATTACKER_NAMESPACE=TRUE"
    echo "SOURCE_ABSENT_VIA_OWN_PROC_ROOT=TRUE"
  '
test "$(cat "$lab/source/protected.txt")" = 'original'

echo 'CASE=shared-pid-same-uid-shared-tmp'
docker run --rm --network none --pid="container:$victim" --user "$runner_uid:$runner_gid" \
  --cap-drop ALL --security-opt no-new-privileges \
  -v "$volume:/tmp" alpine:3.21 sh -c '
    test ! -e /src/protected.txt
    echo "SOURCE_ABSENT_IN_ATTACKER_NAMESPACE=TRUE"
    if test -r /proc/1/root/src/protected.txt; then
      echo "PROC_ROOT_READ=ALLOWED"
      if printf "changed\n" > /proc/1/root/src/protected.txt 2>/dev/null; then
        echo "PROC_ROOT_WRITE=ALLOWED"
      else
        echo "PROC_ROOT_WRITE=DENIED"
      fi
    else
      echo "PROC_ROOT_READ=DENIED"
    fi
  '

echo "HOST_PROTECTED_CONTENT=$(cat "$lab/source/protected.txt")"
docker inspect --format 'VICTIM_PID_MODE={{.HostConfig.PidMode}} VICTIM_USER={{.Config.User}} VICTIM_CAPDROP={{.HostConfig.CapDrop}} VICTIM_SECURITY={{.HostConfig.SecurityOpt}}' "$victim"
