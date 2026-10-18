#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# Namespaces
# ============================================================

INFRA_NAMESPACE="${K8S_INFRA_NAMESPACE:-infrastructure}"
APPLICATION_NAMESPACE="${K8S_APPLICATION_NAMESPACE:-ocm-wstack}"
SECURITY_NAMESPACE="${K8S_SECURITY_NAMESPACE:-security}"
# ============================================================
# Port forwards
#
# Format:
#   "namespace:service-name:local-port:remote-port"
#
# Nur Service-Namen und ggf. Ports anpassen.
# ============================================================

FORWARDS=(
  # Infrastructure
  "${INFRA_NAMESPACE}:cassandra:9042:9042"
  "${INFRA_NAMESPACE}:nats:4222:4222"
  "${INFRA_NAMESPACE}:universal-resolver-service:8082:8080"

  # Application
  "${APPLICATION_NAMESPACE}:storage-service:9080:8080"
  "${APPLICATION_NAMESPACE}:signer:8081:8080"
  "${SECURITY_NAMESPACE}:openbao:8200:8200"
)

PID_DIR="${TMPDIR:-/tmp}/xfsc-verification-port-forwards"

mkdir -p "${PID_DIR}"

# ============================================================
# Functions
# ============================================================

start_forward() {
  local namespace="$1"
  local service="$2"
  local local_port="$3"
  local remote_port="$4"

  local id="${namespace}-${service}-${local_port}"
  local pid_file="${PID_DIR}/${id}.pid"
  local log_file="${PID_DIR}/${id}.log"

  # Existing port-forward stoppen
  if [[ -f "${pid_file}" ]]; then
    local old_pid
    old_pid="$(cat "${pid_file}")"

    if kill -0 "${old_pid}" 2>/dev/null; then
      echo "Stopping existing port-forward:"
      echo "  ${namespace}/${service} (PID ${old_pid})"

      kill "${old_pid}" || true
      wait "${old_pid}" 2>/dev/null || true
    fi

    rm -f "${pid_file}"
  fi

  echo "Starting:"
  echo "  localhost:${local_port} -> ${namespace}/service/${service}:${remote_port}"

  kubectl \
    --namespace "${namespace}" \
    port-forward \
    "service/${service}" \
    "${local_port}:${remote_port}" \
    >"${log_file}" 2>&1 &

  local pid=$!

  echo "${pid}" > "${pid_file}"

  # kubectl kurz Zeit geben, um Fehler zu melden
  sleep 0.5

  if ! kill -0 "${pid}" 2>/dev/null; then
    echo
    echo "ERROR: Port-forward failed:"
    echo "  ${namespace}/service/${service}"
    echo
    echo "kubectl output:"
    cat "${log_file}"

    rm -f "${pid_file}"
    exit 1
  fi

  echo "  OK (PID ${pid})"
  echo
}

# ============================================================
# Checks
# ============================================================

if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl not found"
  exit 1
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "ERROR: Kubernetes cluster is not reachable"
  exit 1
fi

# ============================================================
# Information
# ============================================================

echo
echo "=========================================="
echo " XFSC Kubernetes Port Forwards"
echo "=========================================="
echo
echo "Infrastructure namespace:"
echo "  ${INFRA_NAMESPACE}"
echo
echo "Application namespace:"
echo "  ${APPLICATION_NAMESPACE}"
echo

# ============================================================
# Start
# ============================================================

for entry in "${FORWARDS[@]}"; do
  IFS=":" read -r namespace service local_port remote_port <<< "${entry}"

  start_forward \
    "${namespace}" \
    "${service}" \
    "${local_port}" \
    "${remote_port}"
done

echo "=========================================="
echo " All port-forwards started"
echo "=========================================="
echo
echo "Active forwards:"
echo

for entry in "${FORWARDS[@]}"; do
  IFS=":" read -r namespace service local_port remote_port <<< "${entry}"

  printf "  %-6s -> %s/%s:%s\n" \
    "localhost:${local_port}" \
    "${namespace}" \
    "${service}" \
    "${remote_port}"
done

echo
echo "Logs:"
echo "  ${PID_DIR}"
echo