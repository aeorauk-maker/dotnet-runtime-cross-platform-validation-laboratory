#!/usr/bin/env bash
set -euo pipefail

suffix="$(date +%s)-$$"
user_a="eop062a$suffix"
user_b="eop062b$suffix"
lab="$(mktemp -d /tmp/eop062-crossuid-XXXXXXXX)"
created_a=0
created_b=0
server_pid=''
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" >/dev/null 2>&1 || true; fi
  if [[ "$created_a" == 1 ]]; then sudo userdel "$user_a" >/dev/null 2>&1 || true; fi
  if [[ "$created_b" == 1 ]]; then sudo userdel "$user_b" >/dev/null 2>&1 || true; fi
  rm -rf "$lab"
}
trap cleanup EXIT

cat > "$lab/OwnerClient.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework></PropertyGroup>
</Project>
EOF
cat > "$lab/Program.cs" <<'EOF'
using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;

string path = args[0], result = args[1], option = args[2];
string prefix = $"UID={geteuid()} OPTION={option} ";
try
{
    var opts = option == "current" ? PipeOptions.CurrentUserOnly : PipeOptions.None;
    using var pipe = new NamedPipeClientStream(".", path, PipeDirection.InOut, opts);
    pipe.Connect(3000);
    pipe.WriteByte(7);
    pipe.Flush();
    File.WriteAllText(result, prefix + "CONNECT=ALLOWED");
}
catch (Exception e)
{
    File.WriteAllText(result, prefix + $"CONNECT=DENIED TYPE={e.GetType().Name} MESSAGE={e.Message}");
}

[DllImport("libc")] static extern uint geteuid();
EOF
cat > "$lab/server.py" <<'EOF'
import os, socket, sys
path, ready, result = sys.argv[1:]
server = socket.socket(socket.AF_UNIX)
server.bind(path)
os.chmod(path, 0o777)
server.listen(1)
server.settimeout(8)
open(ready, 'w').write('READY')
try:
    client, _ = server.accept()
    client.settimeout(5)
    data = client.recv(1)
    open(result, 'w').write(f'UID={os.geteuid()} SOCKET_MODE={oct(os.stat(path).st_mode & 0o777)} ACCEPTED_BYTE={data.hex()}')
    client.close()
except Exception as e:
    open(result, 'w').write(f'UID={os.geteuid()} SERVER_ERROR={type(e).__name__}:{e}')
finally:
    server.close()
EOF

dotnet build "$lab/OwnerClient.csproj" -c Release -v:q -p:UseSharedCompilation=false
chmod 0777 "$lab"
sudo useradd --no-create-home --shell /bin/sh "$user_a"
created_a=1
sudo useradd --no-create-home --shell /bin/sh "$user_b"
created_b=1
uid_a="$(id -u "$user_a")"
uid_b="$(id -u "$user_b")"
[[ "$uid_a" != "$uid_b" ]]
echo "SDK_VERSION=$(dotnet --version) UID_A=$uid_a UID_B=$uid_b"

run_case() {
  local label="$1" client_user="$2" option="$3" expected="$4"
  local socket_path="$lab/$label.sock" ready="$lab/$label.ready"
  local server_result="$lab/$label.server" client_result="$lab/$label.client"
  sudo -u "$user_b" python3 "$lab/server.py" "$socket_path" "$ready" "$server_result" &
  server_pid=$!
  local found=0
  for ((i=0;i<100;i++)); do
    if [[ -f "$ready" ]]; then found=1; break; fi
    sleep 0.1
  done
  [[ "$found" == 1 ]]
  sudo -u "$client_user" "$lab/bin/Release/net11.0/OwnerClient" "$socket_path" "$client_result" "$option"
  wait "$server_pid"
  server_pid=''
  echo "CASE=$label SERVER=$(cat "$server_result") CLIENT=$(cat "$client_result")"
  grep -q "CONNECT=$expected" "$client_result"
  if [[ "$expected" == ALLOWED ]]; then grep -q 'ACCEPTED_BYTE=07' "$server_result"; fi
}

run_case 'cross-uid-no-option' "$user_a" none ALLOWED
run_case 'same-uid-current' "$user_b" current ALLOWED
run_case 'cross-uid-current' "$user_a" current DENIED
echo 'EOP062_UNIX_CROSSUID_OWNER_CONTROL_PASS'
