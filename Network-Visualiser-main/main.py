from pathlib import Path

from parser import read_pcap, preprocess_packets, build_topology
from detector import run_detections
from graph_maker import add_layout_positions
from json_exporter import export_json

def main():
    dataset_name = input("Enter PCAP file name w/ .file_type(pcap/pcapng): ")
    project_dir = Path(__file__).resolve().parent
    pcap_path = project_dir / "dataset" / dataset_name
    packets = read_pcap(str(pcap_path))

    flows = preprocess_packets(packets)

    topology = build_topology(flows)

    alerts = run_detections(flows)

    topology = add_layout_positions(topology, flows)
    
    export_json(topology, flows, alerts, dataset_name)

if __name__ == "__main__":
    main()