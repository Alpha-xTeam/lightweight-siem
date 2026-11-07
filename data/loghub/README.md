# LogHub datasets

Supported: place LogHub log files in this directory and point
`config/siem.config.yaml -> collector.auth_log_path` to the file.

Sources:

- LogHub (logpai): https://github.com/logpai/loghub
- SSH dataset example: `LogHub/SSH/ssh_2k.log`

Example (PowerShell):

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/logpai/loghub/master/SSH/ssh_2k.log" `
  -OutFile "data/loghub/ssh_2k.log"
```

Then set `collector.auth_log_path: data/loghub/ssh_2k.log`.
