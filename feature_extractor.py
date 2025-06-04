import socket
import struct
import time
import statistics
from collections import defaultdict
import pandas as pd

# Important features list
imp_feats = [
    'Bwd Packet Length Min', 'Init_Win_bytes_forward', 'Bwd Packets/s', 'Average Packet Size',
    'Destination Port', 'Packet Length Std', 'Bwd Packet Length Std', 'Bwd Packet Length Mean',
    'Bwd Packet Length Max', 'PSH Flag Count', 'Avg Bwd Segment Size', 'Bwd Header Length',
    'Packet Length Variance', 'Min Packet Length', 'Packet Length Mean', 'Fwd Packet Length Max',
    'Subflow Bwd Bytes', 'Max Packet Length', 'Fwd Packet Length Min', 'Fwd Header Length',
    'Fwd IAT Max', 'URG Flag Count', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow IAT Std', 'Subflow Bwd Packets', 'Subflow Fwd Packets', 'Active Min', 'ACK Flag Count', 'Idle Std'
]

# Flow key format: (src_ip, dst_ip, src_port, dst_port, protocol)
flows = defaultdict(lambda: {
    'packets': [],
    'fwd_pkt_lens': [], 'bwd_pkt_lens': [],
    'fwd_times': [], 'bwd_times': [],
    'fwd_win_sizes': [], 'bwd_win_sizes': [],
    'flags': defaultdict(int),
    'timestamps': []
})

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

timer = 2400
print(f"[*] Capturing packets... Ctrl+C to stop. Default timer {timer} seconds.")
start_time = time.time()
try:
    while time.time() - start_time < timer:
        raw_data, addr = s.recvfrom(65535)
        timestamp = time.time()

        eth_proto = struct.unpack("!H", raw_data[12:14])[0]
        if eth_proto != 0x0800:  # IPv4 only
            continue

        ip_hdr = struct.unpack("!BBHHHBBH4s4s", raw_data[14:34])
        proto = ip_hdr[6]
        src_ip = socket.inet_ntoa(ip_hdr[8])
        dst_ip = socket.inet_ntoa(ip_hdr[9])
        ttl = ip_hdr[5]

        if proto != 6:
            continue  # Only TCP

        ip_header_len = (ip_hdr[0] & 0x0F) * 4
        tcp_start = 14 + ip_header_len
        tcp_hdr = struct.unpack("!HHLLBBHHH", raw_data[tcp_start:tcp_start+20])
        src_port, dst_port, _, _, offset_res, flags, window, _, _ = tcp_hdr

        flow_key = (src_ip, dst_ip, src_port, dst_port, 'TCP')
        reverse_key = (dst_ip, src_ip, dst_port, src_port, 'TCP')
        direction = 'fwd' if flow_key in flows else 'bwd' if reverse_key in flows else 'fwd'

        flow = flows[flow_key if direction == 'fwd' else reverse_key]
        pkt_len = len(raw_data)
        flow['packets'].append(pkt_len)
        flow['timestamps'].append(timestamp)

        if direction == 'fwd':
            flow['fwd_pkt_lens'].append(pkt_len)
            flow['fwd_times'].append(timestamp)
            flow['fwd_win_sizes'].append(window)
        else:
            flow['bwd_pkt_lens'].append(pkt_len)
            flow['bwd_times'].append(timestamp)
            flow['bwd_win_sizes'].append(window)

        if flags & 0x02: flow['flags']['SYN'] += 1
        if flags & 0x01: flow['flags']['FIN'] += 1
        if flags & 0x10: flow['flags']['ACK'] += 1
        if flags & 0x08: flow['flags']['PSH'] += 1
        if flags & 0x20: flow['flags']['URG'] += 1

except KeyboardInterrupt:
    pass

print("[*] Extraction complete.")


# --- Feature Extraction ---
feat_list = []
for key, flow in flows.items():
    total_packets = len(flow['packets'])
    duration = max(flow['timestamps']) - min(flow['timestamps']) if len(flow['timestamps']) > 1 else 0.0
    fwd_count = len(flow['fwd_pkt_lens'])
    bwd_count = len(flow['bwd_pkt_lens'])

    features = {
        'Source IP': key[0],
        'Destination IP': key[1], # remove these while training the model... - only for printing attack src
        'Destination Port': key[3],
        'Bwd Packet Length Min': min(flow['bwd_pkt_lens'], default=0),
        'Bwd Packet Length Max': max(flow['bwd_pkt_lens'], default=0),
        'Bwd Packet Length Mean': statistics.mean(flow['bwd_pkt_lens']) if flow['bwd_pkt_lens'] else 0,
        'Bwd Packet Length Std': statistics.stdev(flow['bwd_pkt_lens']) if len(flow['bwd_pkt_lens']) > 1 else 0,
        'Packet Length Variance': statistics.variance(flow['packets']) if len(flow['packets']) > 1 else 0,
        'Packet Length Mean': statistics.mean(flow['packets']) if flow['packets'] else 0,
        'Packet Length Std': statistics.stdev(flow['packets']) if len(flow['packets']) > 1 else 0,
        'Min Packet Length': min(flow['packets'], default=0),
        'Max Packet Length': max(flow['packets'], default=0),
        'Average Packet Size': sum(flow['packets']) / total_packets if total_packets else 0,
        'Total Length of Fwd Packets': sum(flow['fwd_pkt_lens']),
        'Total Length of Bwd Packets': sum(flow['bwd_pkt_lens']),
        'Bwd Packets/s': bwd_count / duration if duration > 0 else 0,
        'Fwd Packets/s': fwd_count / duration if duration > 0 else 0,
        'Init_Win_bytes_forward': flow['fwd_win_sizes'][0] if flow['fwd_win_sizes'] else 0,
        'Fwd Packet Length Min': min(flow['fwd_pkt_lens'], default=0),
        'Fwd Packet Length Max': max(flow['fwd_pkt_lens'], default=0),
        'Fwd Header Length': sum(flow['fwd_win_sizes']),
        'Bwd Header Length': sum(flow['bwd_win_sizes']),
        'Subflow Fwd Packets': fwd_count,
        'Subflow Bwd Packets': bwd_count,
        'Subflow Bwd Bytes': sum(flow['bwd_pkt_lens']),
        'Avg Bwd Segment Size': statistics.mean(flow['bwd_pkt_lens']) if flow['bwd_pkt_lens'] else 0,
        'Flow IAT Std': statistics.stdev([t2 - t1 for t1, t2 in zip(flow['timestamps'], flow['timestamps'][1:])]) if len(flow['timestamps']) > 2 else 0,
        'Fwd IAT Max': max([t2 - t1 for t1, t2 in zip(flow['fwd_times'], flow['fwd_times'][1:])], default=0),
        'URG Flag Count': flow['flags']['URG'],
        'ACK Flag Count': flow['flags']['ACK'],
        'PSH Flag Count': flow['flags']['PSH'],
        'SYN Flag Count': flow['flags']['SYN'],
        'FIN Flag Count': flow['flags']['FIN'],
        'Active Min': min([t2 - t1 for t1, t2 in zip(flow['timestamps'], flow['timestamps'][1:])], default=0),
        'Idle Std': statistics.stdev([t2 - t1 for t1, t2 in zip(flow['timestamps'], flow['timestamps'][1:])]) if len(flow['timestamps']) > 2 else 0,
        'Flow IAT Mean': statistics.mean(iats) if len(iats := [t2 - t1 for t1, t2 in zip(flow['timestamps'], flow['timestamps'][1:])]) > 0 else 0,
        'Flow IAT Max': max(iats, default=0),
        'Fwd IAT Std': statistics.stdev(iats_fwd) if len(iats_fwd := [t2 - t1 for t1, t2 in zip(flow['fwd_times'], flow['fwd_times'][1:])]) > 1 else 0,
        'Fwd Packet Length Mean': statistics.mean(flow['fwd_pkt_lens']) if flow['fwd_pkt_lens'] else 0,
        'Avg Fwd Segment Size': statistics.mean(flow['fwd_pkt_lens']) if flow['fwd_pkt_lens'] else 0,
        'Flow Bytes/s': sum(flow['packets']) / duration if duration > 0 else 0,
    }
    print(features)
    feat_list.append(features)


df = pd.DataFrame(feat_list)
df.to_csv("extracted_feats.csv", index=False)
print("[+] Features saved to extracted_features.csv")
