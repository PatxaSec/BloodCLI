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
> RELATIONSHIPS ARE LIMITED TO 10.
> GO TO LINE 210 IN ORDER TO CHANGE IT.
---

## Usage

```bash
python automate_blood.py <path_to_bloodhound_zip>
```

![imagen](https://github.com/user-attachments/assets/02bfa021-621e-47ef-b343-6209b1065473)

