#!/usr/bin/env bash
set -euo pipefail

ENCLAVE_NAME="devnet"
ARGS_FILE="single-geth.yaml"
IMAGE_DOWNLOAD="always"
OUTPUT_FILE="endpoints.json"

usage() {
    echo "Usage: $0 [OPTIONS] [config_file]"
    echo ""
    echo "Reset a Kurtosis Ethereum devnet: clean old enclaves, start fresh."
    echo ""
    echo "Options:"
    echo "  -n, --name NAME       Enclave name (default: devnet)"
    echo "  -o, --output FILE     Output file for endpoints (default: endpoints.json)"
    echo "  -h, --help            Show this help"
    echo ""
    echo "Notes:"
    echo "  - Relative output paths are resolved against the current working directory."
    echo "  - Relative config paths are also resolved against the current working directory."
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 ../ethpackage/network_params.yaml"
    echo "  $0 -n mynet -o output/endpoints.json ../ethpackage/network_params.yaml"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--name)
            ENCLAVE_NAME="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            ARGS_FILE="$1"
            shift
            ;;
    esac
done

if [[ ! -f "$ARGS_FILE" ]]; then
    echo "Error: config file '$ARGS_FILE' not found"
    exit 1
fi

if [[ "$OUTPUT_FILE" = /* ]]; then
    OUTPUT_PATH="$OUTPUT_FILE"
else
    OUTPUT_PATH="$(pwd)/$OUTPUT_FILE"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

echo "==> Stopping Kurtosis engine"
kurtosis engine stop 2>/dev/null || true

echo "==> Cleaning all enclaves"
kurtosis clean -a 2>/dev/null || true

echo "==> Starting Kurtosis engine"
kurtosis engine start

echo "==> Starting enclave '$ENCLAVE_NAME' with config '$ARGS_FILE'"
kurtosis run github.com/ethpandaops/ethereum-package \
    --enclave "$ENCLAVE_NAME" \
    --args-file "$ARGS_FILE" \
    --image-download "$IMAGE_DOWNLOAD"

echo ""
echo "==> Extracting endpoints..."

raw=$(kurtosis enclave inspect "$ENCLAVE_NAME" 2>&1)

python3 << PYEOF | tee "$OUTPUT_PATH"
import json, re, urllib.request
from datetime import datetime

raw = r'''$raw'''

service_pattern = re.compile(r'^([0-9a-f]{12})\s+(el|vc|cl)-(\d+)-(\S+)\s+(.*)', re.MULTILINE)

services = []
for m in service_pattern.finditer(raw):
    services.append({
        'uuid': m.group(1),
        'type': m.group(2),
        'index': int(m.group(3)),
        'name': m.group(4),
        'rest': m.group(5),
        'start': m.start(),
    })

for i, svc in enumerate(services):
    end = services[i+1]['start'] if i+1 < len(services) else len(raw)
    svc['block'] = raw[svc['start']:end]

def extract_port(block, port_name, port_num):
    p = re.compile(rf'{re.escape(port_name)}:\s*{port_num}/tcp\s*->\s*(\S+)')
    m = p.search(block)
    return m.group(1).strip() if m else None

el_nodes = []
cl_nodes = []

for svc in services:
    if svc['type'] == 'el':
        idx = svc['index']
        name_parts = svc['name'].rsplit('-', 1) if '-' in svc['name'] else [svc['name'], '']
        el_client = name_parts[0]
        cl_client = name_parts[1] if len(name_parts) > 1 else ''

        block = svc['block']
        el_nodes.append({
            'index': idx,
            'el_client': el_client,
            'cl_client': cl_client,
            'rpc': extract_port(block, 'rpc', '8545'),
            'ws': extract_port(block, 'ws', '8546') or extract_port(block, 'ws-rpc', '8545'),
            'engine_rpc': extract_port(block, 'engine-rpc', '8551'),
        })

    elif svc['type'] == 'cl':
        idx = svc['index']
        name_parts = svc['name'].split('-', 1) if '-' in svc['name'] else [svc['name'], '']
        cl_client = name_parts[0]
        el_client = name_parts[1] if len(name_parts) > 1 else ''

        block = svc['block']
        cl_nodes.append({
            'index': idx,
            'cl_client': cl_client,
            'el_client': el_client,
            'beacon': extract_port(block, 'http', '4000'),
        })

def get_enode(rpc_addr):
    if not rpc_addr:
        return None
    url = f"http://{rpc_addr}"
    payload = json.dumps({"jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp_data = json.loads(resp.read())
            return resp_data.get("result", {}).get("enode", None)
    except Exception:
        return None

for node in el_nodes:
    node['enode'] = get_enode(node.get('rpc'))

result = {
    'enclave': '$ENCLAVE_NAME',
    'config': '$ARGS_FILE',
    'timestamp': datetime.now().isoformat(),
    'execution_nodes': sorted(el_nodes, key=lambda x: x['index']),
    'consensus_nodes': sorted(cl_nodes, key=lambda x: x['index']),
}

json_str = json.dumps(result, indent=2)
print(json_str)

with open('$OUTPUT_PATH', 'w') as f:
    f.write(json_str + '\n')
PYEOF

echo ""
echo "==> Endpoints saved to $OUTPUT_PATH"
echo "==> Done! Inspect with: kurtosis enclave inspect $ENCLAVE_NAME"
