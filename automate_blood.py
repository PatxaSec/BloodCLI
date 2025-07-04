#!/usr/local/bin/python3
# CREATOR: PatxaSec

import json
import zipfile
import sys
import os
import argparse

def parse_json(zip_path):
    sid_map = {}
    relaciones = []

    with zipfile.ZipFile(zip_path, 'r') as z:
        json_files = [f for f in z.namelist() if f.endswith('.json')]

        if not json_files:
            print("[ERROR] No JSON files found in the ZIP.")
            return sid_map, relaciones

        for file in json_files:
            with z.open(file) as f:
                content = json.load(f)
                objs = content.get("data", [])
                general_type = content.get("meta", {}).get("type", "Unknown")

                for obj in objs:
                    sid = obj.get("ObjectIdentifier", None)
                    if sid:
                        entity_type = obj.get("type", general_type)
                        obj["_tipo"] = entity_type
                        sid_map[sid] = obj
                        if "Aces" in obj:
                            for ace in obj["Aces"]:
                                right = ace.get("RightName", "")
                                if right in (
                                    "AdminTo", "GenericAll", "GenericWrite", "WriteOwner",
                                    "WriteDacl", "AddMember", "ForceChangePassword",
                                    "AllExtendedRights", "MemberOf", "AllowedToDelegate",
                                    "AllowedToAct", "HasSession", "Contains", "Owns"
                                ):
                                    origin_name = obj.get("Properties", {}).get("name", "Unknown")
                                    dest_sid = ace.get("PrincipalSID", "Unknown")
                                    dest_type = ace.get("PrincipalType", "Unknown")
                                    relaciones.append({
                                        "origen_sid": sid,
                                        "origen_nombre": origin_name,
                                        "origen_tipo": entity_type,
                                        "derecho": right,
                                        "destino_sid": dest_sid,
                                        "destino_tipo": dest_type
                                    })

    return sid_map, relaciones

def is_admin(entity):
    return entity.get("Properties", {}).get("admincount") == True

def is_kerberoastable(entity):
    props = entity.get("Properties", {})
    return props.get("hasspn", False)

def is_asrep_roastable(entity):
    props = entity.get("Properties", {})
    return props.get("trustedtoauth", False) and not props.get("userpassword", None)

def is_disabled(entity):
    props = entity.get("Properties", {})
    return not props.get("enabled", True)

def pwd_never_expires(entity):
    props = entity.get("Properties", {})
    return props.get("pwdneverexpires", False)

def is_old_os(entity):
    props = entity.get("Properties", {})
    os_name = props.get("operatingsystem")

    if not os_name:
        return False

    os_name = str(os_name).lower()

    deprecated_keywords = [
        "windows xp", "windows vista", "windows 7", "windows 8", "windows 8.1",
        "windows embedded standard", "windows embedded 8", "windows embedded 8.1",
        "windows server 2003", "windows server 2008", "windows server® 2008",
        "windows server 2012", "windows server 2012 r2"
    ]

    return any(keyword in os_name for keyword in deprecated_keywords)

def get_display_items(items, limit):
    if limit == ':':
        return items
    else:
        return items[:int(limit)]

def name_matches_filter(entity_name, entity_type, filter_name):
    if not filter_name:
        return True
    if not entity_name and not entity_type:
        return False

    filter_lower = filter_name.lower()

    # Check if filter is substring of the name
    if entity_name and filter_lower in entity_name.lower():
        return True

    # Check if filter matches types like container, ou, domain, gpo (case insensitive)
    if entity_type:
        entity_type_lower = entity_type.lower()
        if filter_lower in entity_type_lower:
            return True

    return False

def main():
    parser = argparse.ArgumentParser(description="Process BloodHound ZIP files and analyze relationships.")
    parser.add_argument("zip_path", help="Path to the BloodHound ZIP file")
    parser.add_argument("limit", nargs='?', default=':', help="Limit output number per category (default: all)")
    parser.add_argument("-f", "--filter", dest="filter_name", default=None,
                        help="Filter by user, computer, group, container, OU, domain or GPO name (case insensitive)")
    parser.add_argument("-a", "--filter-admin", dest="filter_admin", action="store_true",
                        help="Exclude relationships where entity is admin")
    args = parser.parse_args()

    zip_path = args.zip_path
    limit = args.limit
    filter_name = args.filter_name
    filter_admin = args.filter_admin

    if limit != ':' and not limit.isdigit():
        print("[ERROR] The 'limit' must be an integer or ':'.")
        sys.exit(1)

    print("[INFO] Reading data from ZIP...")
    sid_map, relaciones = parse_json(zip_path)

    kerberoastables = []
    asrep_roastables = []
    admins = []
    obsolete_computers = []
    disabled_admins = []
    pwd_never_expire = []

    for sid, entity in sid_map.items():
        if is_admin(entity):
            admins.append(entity)
        if is_kerberoastable(entity):
            kerberoastables.append(entity)
        if is_asrep_roastable(entity):
            asrep_roastables.append(entity)
        if is_admin(entity) and is_disabled(entity):
            disabled_admins.append(entity)
        if pwd_never_expires(entity):
            pwd_never_expire.append(entity)
        if is_old_os(entity):
            obsolete_computers.append(entity)

    def print_entities(title, entities):
        filtered_entities = [e for e in entities if name_matches_filter(
            e.get("Properties", {}).get("name", ""),
            e.get("_tipo", ""),
            filter_name)]
        print(f"- {title}: {len(filtered_entities)}")
        if filtered_entities:
            shown = get_display_items(filtered_entities, limit)
            for u in shown:
                name = u.get("Properties", {}).get("name", "Unknown")
                tipo = u.get("_tipo", "Unknown")
                print(f"   • {name} ({tipo})")
            if limit != ':' and len(filtered_entities) > int(limit):
                print(f"  ... ({len(filtered_entities) - int(limit)} more)")
        else:
            print("   (none)")

    print("\n=== DETECTED ENTITIES ===")
    print(f"- Total entities: {len(sid_map)}")

    print("\n=== POTENTIALLY CRITICAL USERS ===")
    print_entities("Kerberoastable accounts", kerberoastables)
    print_entities("AS-REP Roastable accounts", asrep_roastables)
    print_entities("AdminCount=true accounts", admins)
    print(f"- Computers with obsolete OS: {len(obsolete_computers)}")
    if obsolete_computers:
        filtered_obsolete = [c for c in obsolete_computers if name_matches_filter(
            c.get("Properties", {}).get("name", ""),
            c.get("_tipo", ""),
            filter_name)]
        if filtered_obsolete:
            shown = get_display_items(filtered_obsolete, limit)
            for u in shown:
                name = u.get("Properties", {}).get("name", "Unknown")
                os_name = u.get("Properties", {}).get("operatingsystem", "Unknown OS")
                print(f"   • {name} - {os_name}")
            if limit != ':' and len(filtered_obsolete) > int(limit):
                print(f"  ... ({len(filtered_obsolete) - int(limit)} more)")
        else:
            print("   (none)")
    else:
        print("   (none)")
    print_entities("Disabled admins", disabled_admins)
    print_entities("Users with passwords that never expire", pwd_never_expire)

    # Filter relationships according to filter options
    filtered_rel = []
    for rel in relaciones:
        right = rel.get("derecho", "")
        dest_sid = rel.get("destino_sid", "")
        dest_entity = sid_map.get(dest_sid)
        origin_name = rel.get("origen_nombre", "")
        origin_type = rel.get("origen_tipo", "")
        dest_name = dest_entity.get("Properties", {}).get("name", "") if dest_entity else dest_sid
        dest_type = dest_entity.get("_tipo", "") if dest_entity else rel.get("destino_tipo", "")

        # Filter out admins if requested
        if filter_admin and dest_entity and is_admin(dest_entity):
            continue

        # Apply name/type filter if provided
        if filter_name:
            if not (name_matches_filter(origin_name, origin_type, filter_name) or
                    name_matches_filter(dest_name, dest_type, filter_name)):
                continue

        filtered_rel.append(rel)

    print("\n=== DETECTED RELATIONSHIPS ===")
    print(f"- Total relationships: {len(filtered_rel)}")
    if filtered_rel:
        shown = get_display_items(filtered_rel, limit)
        for rel in shown:
            origin = f"{rel['origen_nombre']} ({rel['origen_tipo']})"
            dest_name = rel.get("destino_sid", "Unknown")
            dest_entity = sid_map.get(rel.get("destino_sid", ""))
            if dest_entity:
                dest_name = dest_entity.get("Properties", {}).get("name", dest_name)
                dest_type = dest_entity.get("_tipo", rel.get("destino_tipo", "Unknown"))
            else:
                dest_type = rel.get("destino_tipo", "Unknown")
            dest = f"{dest_name} ({dest_type})"
            print(f"  {dest} --[{rel['derecho']}]--> {origin}")
        if limit != ':' and len(filtered_rel) > int(limit):
            print(f"  ... ({len(filtered_rel) - int(limit)} more relationships)")
    else:
        print("   (none)")

if __name__ == "__main__":
    main()
