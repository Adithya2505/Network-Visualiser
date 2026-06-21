import json
import os

BASE_OUTPUT_DIR = "output"

def export_json(topology, flows, alerts, dataset_name):
    pcap_name  = os.path.splitext(dataset_name)[0]
    output_dir = os.path.join(BASE_OUTPUT_DIR, pcap_name)
    os.makedirs(output_dir, exist_ok=True)
    print(f"Output directory ready: {output_dir}")

    with open(os.path.join(output_dir, "topology.json"), "w") as f:
        json.dump(topology, f, indent=2)

    timeline = sorted(flows, key=lambda flow: flow["timestamp"])
    with open(os.path.join(output_dir, "timeline.json"), "w") as f:
        json.dump(timeline, f, indent=2)

    with open(os.path.join(output_dir, "alerts.json"), "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"Exported JSON files to {output_dir}")