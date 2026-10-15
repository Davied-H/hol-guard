#!/usr/bin/env bash
# Scratch profiling helper: sample the resident serve process while a bench phase runs.
# usage: profile_resident.sh <out-prefix> <delay-seconds> <record-seconds>
set -uo pipefail
out=${1:?out prefix}
delay=${2:?delay}
seconds=${3:?seconds}
pid=""
for _ in $(seq 1 600); do
  pid=$(pgrep -f 'hol-guard-runtime serve-managed' | head -1)
  [[ -n "$pid" ]] && break
  sleep 0.2
done
[[ -z "$pid" ]] && { echo "no resident" > "$out-error.txt"; exit 0; }
sleep "$delay"
pid=$(pgrep -f 'hol-guard-runtime serve-managed' | head -1)
threads() {
  for task in /proc/"$pid"/task/*; do
    printf '%s %s %s\n' "${task##*/}" "$(cat "$task/comm" 2>/dev/null)" "$(awk '{print $14+$15}' "$task/stat" 2>/dev/null)"
  done
}
threads > "$out-threads-before.txt"
sudo perf record -F 997 -g --call-graph dwarf,16384 -p "$pid" -o "$out.perf.data" -- sleep "$seconds" 2> "$out-record.log"
threads > "$out-threads-after.txt"
sudo chmod a+r "$out.perf.data"
sudo perf report -i "$out.perf.data" --stdio --no-children --sort symbol --percent-limit 0.3 2> /dev/null | head -400 > "$out-self.txt"
sudo perf report -i "$out.perf.data" --stdio --children --sort symbol --percent-limit 2 -g none 2> /dev/null | head -300 > "$out-children.txt"
sudo perf report -i "$out.perf.data" --stdio --no-children --sort tid --percent-limit 0.5 -g none 2> /dev/null | head -80 > "$out-tid.txt"
rm -f "$out.perf.data"
