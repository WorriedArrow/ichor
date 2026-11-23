#!/bin/bash
# Live-migration campaign against an Ichor VM on GCE (see README.md).
# Runs on the peer VM: keeps load on Ichor through its API, triggers
# maintenance events one after another, and records everything with this
# machine's (chrony-synced) clock.
#
# Usage: campaign.sh ICHOR_VM ZONE RUNS OUT_DIR
# Needs: ICHOR_IP (Ichor's internal address), PEER_IP (this VM's), and in
# $HOME: xtask (built from the repo), ca.pem, api-token.
set -u
vm=$1 zone=$2 runs=$3 out=$4
mkdir -p "$out"
: "${ICHOR_IP:?}" "${PEER_IP:?}"

# Every line stamped with this machine's wall clock.
ts() { while IFS= read -r l; do printf '%s %s\n' "$(date +%s.%N)" "$l"; done; }
api() {
  "$HOME/xtask" api "$ICHOR_IP:50051" --name ichor.example --ca "$HOME/ca.pem" \
    --token-file "$HOME/api-token" "$@"
}

# The serial console, polled (the guest logs its view of every event).
serial() {
  local next=0
  while true; do
    gcloud compute instances get-serial-port-output "$vm" --zone "$zone" \
      --start="$next" --format=json > "$out/.serial.json" 2>> "$out/serial.err" &&
      next=$(python3 - "$out/.serial.json" "$out/serial.log" <<'EOF'
import json, sys, time
d = json.load(open(sys.argv[1]))
with open(sys.argv[2], "a") as f:
    for line in d.get("contents", "").splitlines():
        f.write(f"{time.time():.3f} {line}\n")
print(d.get("next", 0))
EOF
)
    sleep 10
  done
}

# A load: a container run again whenever it ends (each end is logged).
load() {
  local name=$1 image=$2 cmd=$3
  while true; do
    echo "START"
    api --memory 1024 "$image" -- sh -c "$cmd" 2>&1
    echo "EXIT $?"
    sleep 5
  done | ts > "$out/load-$name.log"
}

iperf3 -s -D --logfile "$out/iperf-server.log"
# The peer end of a steady TCP stream: a line every 200 ms while it holds.
(while true; do nc -l 9001; echo "CLOSED"; done | ts > "$out/tcp-recv.log") &
serial &
alpine=docker.io/library/alpine:3.20
load iperf "$alpine" "apk add -q iperf3 && iperf3 -c $PEER_IP -t 86400 -i 1 --forceflush" &
load tcp "$alpine" 'i=0; while true; do i=$((i+1)); echo $i; sleep 0.2; done | nc '"$PEER_IP"' 9001' &
load fio "$alpine" "apk add -q fio && fio --name=mem --directory=/tmp --rw=randrw --bs=64k --size=128m --time_based --runtime=86400 --status-interval=10 --output-format=terse --eta=never" &
load cpu "$alpine" 'while true; do head -c 33554432 /dev/urandom | sha256sum >/dev/null; echo round; done' &

echo "$(date +%s.%N) campaign of $runs on $vm ($zone); Ichor $ICHOR_IP, peer $PEER_IP" >> "$out/runs.log"
sleep 120  # the loads get going
for i in $(seq 1 "$runs"); do
  echo "$(date +%s.%N) RUN $i request" >> "$out/runs.log"
  gcloud compute instances simulate-maintenance-event "$vm" --zone "$zone" --quiet \
    >> "$out/gcloud.log" 2>&1
  rc=$?  # (not inside the echo: `$(date)` would set it first)
  echo "$(date +%s.%N) RUN $i done rc=$rc" >> "$out/runs.log"
  # After each: does the API still pull and run, and reach the internet?
  api "$alpine" -- sh -c 'echo alive; wget -q -T 10 -O /dev/null http://dl-cdn.alpinelinux.org/alpine/ && echo internet' \
    2>&1 | ts >> "$out/health-$i.log"
  sleep $((150 + RANDOM % 120))
done
echo "$(date +%s.%N) campaign over" >> "$out/runs.log"
sleep 60
kill 0
