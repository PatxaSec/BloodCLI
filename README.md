# BloodHound JSON Analyzer

This Python script parses a BloodHound JSON ZIP file and analyzes Active Directory entities and their relationships to identify potential security risks.

---

## Features

- Parses BloodHound JSON data from a ZIP file.
- Identifies critical entities such as:
  - AdminCount=true accounts
  - Kerberoastable accounts
  - AS-REP roastable accounts
  - Disabled admins
  - Users with passwords that never expire
  - Computers running obsolete operating systems
- Analyzes permissions and relationships by severity levels:
  - Critical
  - High
  - Medium
  - Low
 
> [!WARNING]  
> RELATIONSHIPS are limited to full data on default.
---

## Usage

```bash
python automate_blood.py <path_to_bloodhound_zip> [limit]
```

- limit can be any integer.

- WITH DEFAULT LIMIT OF 10 RELATIONSHIPS

![imagen](https://github.com/user-attachments/assets/a33d5a4b-ab06-4a3d-891e-1f033eab670e)

- WITH FULL DATA RELATIONSHIP

![imagen](https://github.com/user-attachments/assets/45b10fd7-5883-4ac3-becf-96f435216d70)


