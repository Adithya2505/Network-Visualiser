from parser import read_pcap, preprocess_packets, build_topology
from detector import run_detections
from graph_maker import add_layout_positions
from json_exporter import export_json

def main():
    dataset_name = input("Enter PCAP file name w/ .file_type(pcap/pcapng): ")
    packets = read_pcap(f"./dataset/{dataset_name}")
    print(f"Read {dataset_name}")
    flows = preprocess_packets(packets)
    topology = build_topology(flows)
    alerts = run_detections(flows)
    print("Anomaly detection completed")
    topology = add_layout_positions(topology)
    print("Topology made")
    export_json(topology, flows, alerts, dataset_name)
    print("JSON Exported")

if __name__ == "__main__":
    main()