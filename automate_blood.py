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
    os_name = props.get("operatingsystem", "")
    if os_name:
        if any(ver in os_name.lower() for ver in ["xp", "vista", "2003", "2008"]):
            return True
    return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <path_to_bloodhound_zip>")
        sys.exit(1)

    zip_path = sys.argv[1]

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

    print("\n=== DETECTED ENTITIES ===")
    print(f"- Total entities: {len(sid_map)}")

    print("\n=== 🔥 POTENTIALLY CRITICAL USERS ===")
    print(f"- Kerberoastable accounts: {len(kerberoastables)}")
    if kerberoastables:
        for u in kerberoastables:
            name = u.get("Properties", {}).get("name", "Unknown")
            tipo = u.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

    print(f"- AS-REP Roastable accounts: {len(asrep_roastables)}")
    if asrep_roastables:
        for u in asrep_roastables:
            name = u.get("Properties", {}).get("name", "Unknown")
            tipo = u.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

    print(f"- AdminCount=true accounts: {len(admins)}")
    if admins:
        for u in admins:
            name = u.get("Properties", {}).get("name", "Unknown")
            tipo = u.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

    print(f"- Computers with obsolete OS: {len(obsolete_computers)}")
    if obsolete_computers:
        for c in obsolete_computers:
            name = c.get("Properties", {}).get("name", "Unknown")
            tipo = c.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

    print(f"- Disabled admins: {len(disabled_admins)}")
    if disabled_admins:
        for u in disabled_admins:
            name = u.get("Properties", {}).get("name", "Unknown")
            tipo = u.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

    print(f"- Users with passwords that never expire: {len(pwd_never_expire)}")
    if pwd_never_expire:
        for u in pwd_never_expire:
            name = u.get("Properties", {}).get("name", "Unknown")
            tipo = u.get("_tipo", "Unknown")
            print(f"   • {name} ({tipo})")
    else:
        print("   (none)")

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
        # Exclude relations whose destination is admincount=true
        if dest_entity and is_admin(dest_entity):
            continue

        found_level = None
        for level, perms in permission_levels.items():
            if right in perms:
                found_level = level
                break
        if not found_level:
            found_level = "low"

        levels[found_level].append(rel)

    print("\n=== 🔐 DETECTED RELATIONSHIPS BY LEVEL ===")
    for level in ["critical", "high", "medium", "low"]:
        rels_level = levels[level]
        print(f"\n[+] Level: {level.upper()} ({len(rels_level)} relationships)")
        if rels_level:
            limit = 10
            for rel in rels_level[:limit]:
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
            if len(rels_level) > limit:
                print(f"  ... ({len(rels_level) - limit} more relationships)")

if __name__ == "__main__":
    main()
