#!/usr/bin/env bash
# 启动 mihomo 透明代理，强制调度低风控免滑块节点。
# 环境变量支持:
#   CHECKIN_PROXY_URL       已有的直接代理地址
#   PROXY_SUBSCRIPTION_URL  订阅链接
#   PROXY_TEST_URL          测速目标，默认 https://www.gstatic.com/generate_204
#   PROXY_REQUIRED          true 时测速失败退出 1
#   PROXY_PORT              本地 mixed-port，默认 7890

set -euo pipefail

if [[ -n "${CHECKIN_PROXY_URL:-}" ]]; then
	PROXY_TEST_URL="${DIRECT_PROXY_TEST_URL:-https://agentrouter.org}"
	if curl -fsS -x "${CHECKIN_PROXY_URL}" --max-time 20 "${PROXY_TEST_URL}" -o /dev/null; then
		echo "[SUCCESS] Direct proxy is ready"
		if [[ -n "${GITHUB_ENV:-}" ]]; then
			echo "CHECKIN_PROXY_URL=${CHECKIN_PROXY_URL}" >> "${GITHUB_ENV}"
		fi
		exit 0
	fi
	echo "[FAILED] Direct proxy health check failed for ${PROXY_TEST_URL}"
	exit 1
fi

if [[ -z "${PROXY_SUBSCRIPTION_URL:-}" ]]; then
	echo "[INFO] PROXY_SUBSCRIPTION_URL not set, skip proxy setup"
	exit 0
fi

PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"
PROXY_PORT="${PROXY_PORT:-7890}"
PROXY_TEST_URL="${PROXY_TEST_URL:-https://www.gstatic.com/generate_204}"
MIHOMO_VERSION="${MIHOMO_VERSION:-v1.19.27}"
PROXY_REQUIRED="${PROXY_REQUIRED:-false}"

# Detect runner's direct public IP first to prevent any false-positive bypass
RUNNER_DIRECT_IP=$(curl -s --max-time 6 "https://api.ipify.org" 2>/dev/null || echo "")
echo "[INFO] Runner direct public IP: ${RUNNER_DIRECT_IP:-unknown}"

mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

echo "[INFO] Pre-fetching subscription file..."
if ! curl --retry 5 --retry-delay 3 --retry-all-errors --http1.1 -fsSL -k -H "User-Agent: ClashMeta" -o subscription.yaml \
	"${PROXY_SUBSCRIPTION_URL}"; then
	echo "[WARN] Failed to pre-fetch subscription, skip proxy setup"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi

# Filter subscription using Python stdlib: retain clean VMess TCP nodes (low WAF risk, zero UDP drops)
echo "[INFO] Filtering and optimizing subscription proxy nodes..."
python3 -c "
with open('subscription.yaml', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
in_proxies = False
for line in lines:
    if line.startswith('proxies:'):
        in_proxies = True
        new_lines.append(line)
        continue
    if in_proxies:
        if line.startswith('proxy-groups:') or line.startswith('rules:') or (line and not line.startswith(' ') and not line.startswith('\t')):
            in_proxies = False
            new_lines.append(line)
            continue
        # Prioritize clean VMess nodes and exclude dummy/status nodes
        if 'type: vmess' in line and not any(k in line for k in ['剩余', '重置', '到期']):
            new_lines.append(line)
    else:
        new_lines.append(line)

vmess_count = sum(1 for l in new_lines if 'type: vmess' in l)
if vmess_count > 0:
    with open('subscription.yaml', 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    print(f'[INFO] Retained {vmess_count} clean VMess proxy nodes (bypassing datacenter/WAF blocks)')
else:
    print('[WARN] No VMess nodes detected, keeping original subscription')
"

echo "[INFO] Downloading mihomo ${MIHOMO_VERSION}..."
ARCHIVE="mihomo-linux-amd64-${MIHOMO_VERSION}.gz"
if ! curl --retry 3 --retry-delay 5 --retry-all-errors -fsSL -o "${ARCHIVE}" \
	"https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VERSION}/${ARCHIVE}"; then
	echo "[WARN] Failed to download mihomo ${MIHOMO_VERSION}, skip proxy setup"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi
gunzip -f "${ARCHIVE}"
chmod +x "mihomo-linux-amd64-${MIHOMO_VERSION}"
MIHOMO_BIN="${PROXY_DIR}/mihomo-linux-amd64-${MIHOMO_VERSION}"

cat > config.yaml <<EOF
mixed-port: ${PROXY_PORT}
allow-lan: false
ipv6: false
mode: rule
log-level: info
unified-delay: true
external-controller: 127.0.0.1:9090

proxy-providers:
  subscription:
    type: file
    path: ./subscription.yaml
    health-check:
      enable: true
      interval: 120
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: CHECKIN_SG
    type: url-test
    url: "${PROXY_TEST_URL}"
    interval: 60
    tolerance: 50
    lazy: false
    filter: "(?i)新加坡|SG|Singapore"
    use:
      - subscription

  - name: CHECKIN_ALL
    type: url-test
    url: "${PROXY_TEST_URL}"
    interval: 60
    tolerance: 50
    lazy: false
    filter: "(?i)新加坡|SG|Singapore|香港|HK|Hong|日本|JP|Japan|台湾|TW|Taiwan|美国|US|America"
    use:
      - subscription

  - name: CHECKIN
    type: fallback
    url: "${PROXY_TEST_URL}"
    interval: 60
    lazy: false
    proxies:
      - CHECKIN_SG
      - CHECKIN_ALL

rules:
  - MATCH,CHECKIN
EOF

echo "[INFO] Starting mihomo on 127.0.0.1:${PROXY_PORT}..."
nohup "${MIHOMO_BIN}" -d "${PROXY_DIR}" -f config.yaml > mihomo.log 2>&1 &
echo $! > mihomo.pid

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

# Trigger immediate parallel latency benchmarks via REST API
echo "[INFO] Triggering initial proxy group delay benchmarks..."
sleep 1
curl -s "http://127.0.0.1:9090/group/CHECKIN_SG/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true
curl -s "http://127.0.0.1:9090/group/CHECKIN_ALL/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true

READY=false
SELECTED_GROUP="none"
SELECTED_NODE="none"

for attempt in $(seq 1 35); do
	G_NAME=$(curl -s "http://127.0.0.1:9090/proxies/CHECKIN" 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('now', ''))" 2>/dev/null || echo "")
	if [[ -n "${G_NAME}" && "${G_NAME}" != "COMPATIBLE" && "${G_NAME}" != "DIRECT" && "${G_NAME}" != "REJECT" ]]; then
		SELECTED_GROUP="${G_NAME}"
		N_NAME=$(curl -s "http://127.0.0.1:9090/proxies/${SELECTED_GROUP}" 2>/dev/null | python3 -c "import sys, json; print(json.load(sys.stdin).get('now', ''))" 2>/dev/null || echo "${SELECTED_GROUP}")
		if [[ -n "${N_NAME}" && "${N_NAME}" != "COMPATIBLE" && "${N_NAME}" != "DIRECT" && "${N_NAME}" != "REJECT" ]]; then
			SELECTED_NODE="${N_NAME}"
			# Verify HTTP 204 connectivity through proxy
			if curl -fsS -x "${PROXY_URL}" --max-time 8 "${PROXY_TEST_URL}" -o /dev/null 2>/dev/null; then
				# Verify outbound IP is different from runner direct IP (not Azure direct traffic)
				PROXY_OUTBOUND_IP=$(curl -s -x "${PROXY_URL}" --max-time 8 "https://api.ipify.org" 2>/dev/null || echo "")
				if [[ -n "${PROXY_OUTBOUND_IP}" && ( -z "${RUNNER_DIRECT_IP}" || "${PROXY_OUTBOUND_IP}" != "${RUNNER_DIRECT_IP}" ) ]]; then
					READY=true
					break
				fi
			fi
		fi
	fi
	echo "[INFO] Waiting for proxy to select active node (${attempt}/35)... (group: ${SELECTED_GROUP}, node: ${SELECTED_NODE})"
	if (( attempt % 5 == 0 )); then
		curl -s "http://127.0.0.1:9090/group/CHECKIN_SG/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true
		curl -s "http://127.0.0.1:9090/group/CHECKIN_ALL/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true
	fi
	sleep 2
done

if [[ "${READY}" != "true" ]]; then
	echo "[FAILED] Proxy health check failed: no valid proxy node selected or outbound is direct runner IP"
	tail -n 40 mihomo.log || true
	if [[ -f mihomo.pid ]]; then
		kill "$(cat mihomo.pid)" 2>/dev/null || true
	fi
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
fi

echo "[SUCCESS] Proxy is ready: ${PROXY_URL}"
echo "[INFO] Active Proxy Node: ${SELECTED_NODE} (Group: ${SELECTED_GROUP})"

# Test and verify outbound IP and Country
OUTBOUND_INFO=$(curl -s -x "${PROXY_URL}" --max-time 15 "http://ip-api.com/line?fields=country,city,query,isp" 2>/dev/null || echo "unknown")
echo "[INFO] Outbound Route Details:"
echo "${OUTBOUND_INFO}"

# Probe AgentRouter web page to verify anti-bot bypass
echo "[INFO] Probing AgentRouter connectivity via proxy..."
AR_READY=false
for ar_attempt in $(seq 1 3); do
	AR_TITLE=$(curl -s -L -x "${PROXY_URL}" --max-time 15 "https://agentrouter.org" 2>/dev/null | grep -o '<title>[^<]*</title>' || echo "none")
	if [[ "${AR_TITLE}" =~ "Agent Router" ]]; then
		AR_READY=true
		echo "[INFO] AgentRouter Page Title: ${AR_TITLE}"
		break
	fi
	echo "[WARN] AgentRouter connectivity check (attempt ${ar_attempt}/3) returned: ${AR_TITLE}, triggering proxy re-benchmark..."
	curl -s "http://127.0.0.1:9090/group/CHECKIN_SG/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true
	curl -s "http://127.0.0.1:9090/group/CHECKIN_ALL/delay?url=${PROXY_TEST_URL}&timeout=4000" >/dev/null 2>&1 || true
	curl -X DELETE "http://127.0.0.1:9090/connections" >/dev/null 2>&1 || true
	sleep 3
done

echo "[INFO] Proxy is scoped to CHECKIN_PROXY_URL (browser/python only, not global HTTP_PROXY)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
fi
