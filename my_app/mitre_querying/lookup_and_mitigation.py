import json
import sys
from typing import List, Dict, Any

def load_attack_data(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

def index_attack_data(objects: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {obj.get("id"): obj for obj in objects if "id" in obj}

def get_techniques(attack_objects: List[Dict[str, Any]], technique_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    result = {}
    for obj in attack_objects:
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id") in technique_ids:
                result[obj["id"]] = {
                    "id": ref["external_id"],
                    "name": obj.get("name"),
                    "description": obj.get("description", "").strip(),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])],
                    "url": ref.get("url"),
                    "stix_id": obj["id"],
                }
    return result

def get_mitigations(attack_objects: List[Dict[str, Any]], techniques: Dict[str, Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
    mitigation_map = {}
    id_map = index_attack_data(attack_objects)

    for obj in attack_objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        target_ref = obj.get("target_ref")
        source_ref = obj.get("source_ref")
        if target_ref in techniques:
            mitigation_obj = id_map.get(source_ref)
            if mitigation_obj and mitigation_obj.get("type") == "course-of-action":
                mitigation = {
                    "name": mitigation_obj.get("name"),
                    "description": mitigation_obj.get("description", "").strip()
                }
                mitigation_map.setdefault(target_ref, []).append(mitigation)

    return mitigation_map

def main(json_path: str, technique_ids: List[str]):
    attack_data = load_attack_data(json_path)
    techniques = get_techniques(attack_data, technique_ids)
    mitigations = get_mitigations(attack_data, techniques)

    if not techniques:
        print("No matching techniques found.")
        return

    for tid, tech in techniques.items():
        print(f"\n--- {tech['id']} | {tech['name']} ---")
        print(f"Tactics    : {', '.join(tech['tactics'])}")
        print(f"Platforms  : {', '.join(tech['platforms'])}")
        print(f"URL        : {tech['url']}")
        print(f"Description:\n{tech['description'][:5000]}...\n")

        if tid in mitigations:
            print("Mitigations:")
            for m in mitigations[tid]:
                print(f"- {m['name']}: {m['description'][:5000]}...")
        else:
            print("Mitigations: None found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python mitre_lookup.py /path/to/enterprise-attack.json T1059 T1082 ...")
        sys.exit(1)

    json_file_path = sys.argv[1]
    technique_ids = sys.argv[2:]
    main(json_file_path, technique_ids)
