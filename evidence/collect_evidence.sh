#!/usr/bin/env bash
# collect_evidence.sh — RQ3 native evidence, collected with the AWS CLI only.
#
# kit v3: CloudTrail delivers every event to CloudWatch Logs, so all three
# evidence sources are queried the same way, with CloudWatch Logs Insights
# (aws logs start-query / get-query-results). Each query's results are saved
# as a CSV in results/. No Python; jq only reshapes the CLI's JSON into CSV.
#
#   evidence_cloudtrail.csv   CloudTrail management + data events (T1)
#   evidence_lambda.csv       the four tool Lambdas' own log lines (T2)
#   evidence_runtime.csv      the AgentCore runtime's log lines (T3)
#
# Usage:
#   ./collect_evidence.sh <START_ISO> <END_ISO>
#   e.g. ./collect_evidence.sh 2026-10-16T00:15:00Z 2026-10-16T01:10:00Z
# Pass the window that covers the scored run (and the robustness check if you
# want its evidence too). Widen it by a few minutes at each end: CloudTrail
# delivery to CloudWatch Logs lags by a minute or two.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KIT="$(cd "$HERE/.." && pwd)"
OUT="$KIT/results"
Q="$HERE/queries"
REGION="${AWS_REGION:-us-east-1}"
OUTPUTS="$KIT/private/terraform_outputs.json"

[ -f "$OUTPUTS" ] || { echo "missing $OUTPUTS (run: terraform output -json > private/terraform_outputs.json)"; exit 1; }
[ $# -eq 2 ] || { echo "usage: $0 <START_ISO> <END_ISO>"; exit 1; }
START_MS=$(date -u -d "$1" +%s)000 2>/dev/null || START_MS=$(date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$1" +%s)000
END_MS=$(date -u -d "$2" +%s)000   2>/dev/null || END_MS=$(date -u -jf "%Y-%m-%dT%H:%M:%SZ" "$2" +%s)000
START=$((START_MS/1000)); END=$((END_MS/1000))
echo "window: $1 ($START) -> $2 ($END)"

tfout() { jq -r ".${1}.value" "$OUTPUTS"; }

TRAIL_GROUP=$(tfout trail_log_group)
AGENT_GROUP=$(tfout agentcore_log_group)
mapfile -t LAMBDA_GROUPS < <(jq -r '.lambda_log_groups.value[]' "$OUTPUTS")

# Runtime logs land in the base group AND a "-DEFAULT" group; discover both by
# prefix so a renamed suffix never silently drops the runtime evidence.
mapfile -t RUNTIME_GROUPS < <(
  aws logs describe-log-groups --region "$REGION" \
    --log-group-name-prefix "$AGENT_GROUP" \
    --query 'logGroups[].logGroupName' --output text | tr '\t' '\n' | sed '/^$/d')

# run_query <out.csv> <query_file> <group> [group...]
run_query() {
  local out="$1" qfile="$2"; shift 2
  local groups=("$@")
  local query; query="$(cat "$qfile")"
  echo "  querying ${#groups[@]} group(s) -> $(basename "$out")"
  # --log-group-names (plural) takes the whole list; the singular
  # --log-group-name keeps only the last value when repeated.
  local qid
  qid=$(aws logs start-query --region "$REGION" \
        --log-group-names "${groups[@]}" --start-time "$START" --end-time "$END" \
        --query-string "$query" --query 'queryId' --output text)
  local status="Running"
  while [ "$status" = "Running" ] || [ "$status" = "Scheduled" ]; do
    sleep 3
    status=$(aws logs get-query-results --region "$REGION" --query-id "$qid" \
             --query 'status' --output text)
  done
  [ "$status" = "Complete" ] || { echo "    query status: $status"; }
  # Flatten results (array of arrays of {field,value}) to CSV. Drop the
  # Insights pseudo-field @ptr. Header = union of field names, first row order.
  aws logs get-query-results --region "$REGION" --query-id "$qid" --output json \
  | jq -r '
      .results as $rows
      # header = union of all field names across rows, in first-seen order,
      # excluding the Insights pointer pseudo-field.
      | ([ $rows[][] | .field ] | map(select(. != "@ptr")) | unique) as $hdr
      | ($hdr | @csv),
        ( $rows[]
          | (reduce .[] as $c ({}; .[$c.field] = $c.value)) as $m
          | [ $hdr[] as $h | ($m[$h] // "") ]
          | @csv )
    ' > "$out"
  echo "    rows: $(( $(wc -l < "$out") - 1 ))"
}

mkdir -p "$OUT"
echo "CloudTrail (T1):"
run_query "$OUT/evidence_cloudtrail.csv" "$Q/cloudtrail.txt" "$TRAIL_GROUP"
echo "Lambda tool logs (T2):"
run_query "$OUT/evidence_lambda.csv" "$Q/lambda.txt" "${LAMBDA_GROUPS[@]}"
echo "AgentCore runtime logs (T3):"
run_query "$OUT/evidence_runtime.csv" "$Q/runtime.txt" "${RUNTIME_GROUPS[@]}"

echo "done. CSVs in $OUT/"
