import json
import sys
from typing import List, Dict, Any

# Load MITRE ATT&CK data from local JSON
def load_attack_data(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

# Extract techniques matching the given list of MITRE IDs (e.g., T1059)
def get_technique_by_id(attack_objects: List[Dict[str, Any]], technique_ids: List[str]) -> List[Dict[str, Any]]:
    id_set = set(technique_ids)
    results = []

    for obj in attack_objects:
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in id_set:
                result = {
                    "id": ref["external_id"],
                    "name": obj.get("name"),
                    "description": obj.get("description", "").strip(),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])],
                    "url": ref.get("url"),
                }
                results.append(result)
                break
    return results

# Main function to load and process technique IDs
def main(json_path: str, technique_ids: List[str]):
    attack_data = load_attack_data(json_path)
    matched_techniques = get_technique_by_id(attack_data, technique_ids)

    if not matched_techniques:
        print("No matching techniques found.")
        return

    for tech in matched_techniques:
        print(f"\n--- {tech['id']} | {tech['name']} ---")
        print(f"Tactics    : {', '.join(tech['tactics'])}")
        print(f"Platforms  : {', '.join(tech['platforms'])}")
        print(f"URL        : {tech['url']}")
        print(f"Description:\n{tech['description'][:500]}...\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python mitre_lookup.py /path/to/enterprise-attack.json T1059 T1082 ...")
        sys.exit(1)

    json_file_path = sys.argv[1]
    technique_ids = sys.argv[2:]
    main(json_file_path, technique_ids)
