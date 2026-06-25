from pathlib import Path

from parser import preprocess_packets, build_topology
from detector import run_detections
from graph_maker import add_layout_positions
from json_exporter import export_json

def main():
    dataset_name = input("Enter PCAP file name w/ .file_type(pcap/pcapng): ")
    project_dir = Path(__file__).resolve().parent
    pcap_path = project_dir / "dataset" / dataset_name
    
    flows = preprocess_packets(str(pcap_path))

    topology = build_topology(flows)

    alerts = run_detections(flows)

    topology = add_layout_positions(topology, flows)
    
    export_json(topology, flows, alerts, dataset_name)

if __name__ == "__main__":
    main()