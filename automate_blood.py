#!/usr/local/bin/python3
# CREATOR: PatxaSec

import json
import zipfile
import sys
import os

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

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <path_to_bloodhound_zip> [limit]")
        sys.exit(1)

    zip_path = sys.argv[1]
    limit = sys.argv[2] if len(sys.argv) > 2 else ':'

    if limit != ':' and not limit.isdigit():
        print("[ERROR] The 'limit' must be an integer to show all results.")
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
        print(f"- {title}: {len(entities)}")
        if entities:
            shown = get_display_items(entities, limit)
            for u in shown:
                name = u.get("Properties", {}).get("name", "Unknown")
                tipo = u.get("_tipo", "Unknown")
                print(f"   • {name} ({tipo})")
            if limit != ':' and len(entities) > int(limit):
                print(f"  ... ({len(entities) - int(limit)} more)")
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
        shown = get_display_items(obsolete_computers, limit)
        for u in shown:
            name = u.get("Properties", {}).get("name", "Unknown")
            os_name = u.get("Properties", {}).get("operatingsystem", "Unknown OS")
            print(f"   • {name} - {os_name}")
        if limit != ':' and len(obsolete_computers) > int(limit):
            print(f"  ... ({len(obsolete_computers) - int(limit)} more)")
    else:
        print("   (none)")
    print_entities("Disabled admins", disabled_admins)
    print_entities("Users with passwords that never expire", pwd_never_expire)

    levels = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }

    permission_levels = {
        "critical": {
            "AdminTo", "GenericAll", "GenericWrite", "WriteOwner",
            "WriteDacl", "AddMember", "ForceChangePassword", "AllExtendedRights"
        },
        "high": {"MemberOf", "AllowedToDelegate", "AllowedToAct"},
        "medium": {"HasSession", "Contains"},
        "low": {"Owns"}
    }

    for rel in relaciones:
        right = rel.get("derecho", "")
        dest_sid = rel.get("destino_sid", "")
        dest_entity = sid_map.get(dest_sid)
        if dest_entity and is_admin(dest_entity):
            continue

        found_level = next((lvl for lvl, perms in permission_levels.items() if right in perms), "low")
        levels[found_level].append(rel)

    print("\n=== DETECTED RELATIONSHIPS BY LEVEL ===")
    for level in ["critical", "high", "medium", "low"]:
        rels_level = levels[level]
        print(f"\n[+] Level: {level.upper()} ({len(rels_level)} relationships)")
        if rels_level:
            shown = get_display_items(rels_level, limit)
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
            if limit != ':' and len(rels_level) > int(limit):
                print(f"  ... ({len(rels_level) - int(limit)} more relationships)")

if __name__ == "__main__":
    main()
