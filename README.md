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

- WITH DEFAULT Full data

![imagen](https://github.com/user-attachments/assets/d4df3c2a-a07b-4f75-9233-b51fd45857fb)

- WITH 5 RELATIONSHIP

![imagen](https://github.com/user-attachments/assets/02517ebe-4610-4074-831a-69f8b2c77430)



