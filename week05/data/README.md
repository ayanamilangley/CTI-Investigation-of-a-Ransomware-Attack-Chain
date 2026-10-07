# Datasets

From **OTRF Security-Datasets** — https://github.com/OTRF/Security-Datasets (MIT License, © 2021 Open Threat Research Forge), folder `datasets/atomic/windows/`.

| File | Original path |
|---|---|
| empire_psexec_dcerpc_tcp_svcctl.zip | lateral_movement/host/ |
| cmd_bitsadmin_download_psh_script.zip | defense_evasion/host/ |
| psh_lsass_memory_dump_comsvcs.zip | credential_access/host/ |
| cmd_dumping_ntds_dit_file_volume_shadow_copy.zip | credential_access/host/ |
| psh_python_webserver.zip | execution/host/ |

Each zip has one JSON file, one Windows event per line (Sysmon, Security, PowerShell logs). The scripts read the zips directly; no need to unzip.
