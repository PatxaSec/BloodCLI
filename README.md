# BloodHound JSON Analyzer

This Python script parses a BloodHound JSON ZIP file and analyzes Active Directory entities and their relationships to identify potential security risks.

---

## Features

- Parses BloodHound data from a ZIP file containing JSON exports.
- Detects important entity categories:
  - AdminCount=true accounts
  - Kerberoastable accounts
  - AS-REP Roastable accounts
  - Disabled admins
  - Computers with obsolete operating systems
  - Users with passwords that never expire
- Displays access relationships (ACLs) between entities.
- Optional filtering of relationships and entities by name (user, computer, group, container, OU, domain, GPO).
- Optionally excludes relationships where the destination entity is an admin.
- Limit output count per category.
 
---

## Usage

```bash
python3 automate_blood.py <path_to_bloodhound_zip> [limit] [-f FILTER] [-a]
```

```bash
usage: automate_blood.py [-h] [-f FILTER_NAME] [-a] zip_path [limit]

Process BloodHound ZIP files and analyze relationships.

positional arguments:
  zip_path              Path to the BloodHound ZIP file
  limit                 Limit output number per category (default: all)

options:
  -h, --help            show this help message and exit
  -f, --filter FILTER_NAME
                        Filter by user, computer, group, container, OU, domain or GPO name (case insensitive)
  -a, --filter-admin    Exclude relationships where entity is admin.
```

- limit can be any integer.

- WITH DEFAULT Full data

![imagen](https://github.com/user-attachments/assets/c9c67301-24b4-4b12-a4e7-45cd244e58a4)

- With 5 relationships

![imagen](https://github.com/user-attachments/assets/9212cea0-3e4f-4bd4-a7dd-772df61b9ebf)

- Excluding relationships where the entity is an admin.

![imagen](https://github.com/user-attachments/assets/d11f9c6b-1736-4c18-8ba3-33a42bf7c7b7)

- Filtering

![imagen](https://github.com/user-attachments/assets/315f7877-f934-4b4e-8c28-c9ab8bea6f8c)
![imagen](https://github.com/user-attachments/assets/31c86d20-7b16-4628-b326-acf57209f083)




