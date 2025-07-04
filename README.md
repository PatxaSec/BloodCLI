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
  zip_path             Path to BloodHound ZIP file
  limit                Limit number of displayed items per category (integer or ':')

options:
  -h, --help           show this help message and exit
  -f, --filter FILTER  Filter string for users/computers/groups/containers/OUs/domains/GPOs/rights
  -a, --filter-admin   Exclude relationships where entity is admin
```

- limit can be any integer.

- WITH DEFAULT Full data

![imagen](https://github.com/user-attachments/assets/6459384a-dd84-4f7b-b657-91fdc9812fa9)

- With 5 relationships

![imagen](https://github.com/user-attachments/assets/c0191212-cdc6-4702-b152-bd87e90ef049)

- Excluding relationships where the entity is an admin.

![imagen](https://github.com/user-attachments/assets/c688d5b9-4eb2-457f-b8d6-fd9b50237227)

- Filtering

![imagen](https://github.com/user-attachments/assets/adabcbb5-64d1-4c65-821c-a880544bf253)

![imagen](https://github.com/user-attachments/assets/6be8701f-4d5a-4584-b20a-07c15aed8a45)





