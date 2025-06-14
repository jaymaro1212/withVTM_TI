#!/bin/bash

echo "[$(date)] Starting data update..."

# Python interpreter path
PYTHON=/home/admin/withTI-venv/bin/python

# Execute update scripts
$PYTHON /home/admin/withTI/ti_db/update_db_cisa_kev.py
$PYTHON /home/admin/withTI/ti_db/update_db_epss_scores.py

$PYTHON /home/admin/withTI/ti_db/update_db_metasploit.py
$PYTHON /home/admin/withTI/ti_db/update_db_nuclei.py
$PYTHON /home/admin/withTI/ti_db/update_db_poc_github.py
$PYTHON /home/admin/withTI/ti_db/update_db_exploitdb.py
$PYTHON /home/admin/withTI/ti_db/update_db_nvd_cve_nvd_cpe.py

# Add risk score scripts at the end
/home/admin/withTI/dist/update_risk_score
/home/admin/withTI/dist/update_z_score

echo "[$(date)] Data update completed successfully."

