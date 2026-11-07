# Lightweight SIEM

A lightweight Security Information and Event Management (SIEM) system in
Python for real-time threat detection and security event correlation.

## Features

- Log collection: tail `auth.log` + Syslog (UDP) listener
- Normalization: raw log lines -> unified JSON events
- Rule engine: detection rules defined in `rules/rules.yaml` (no code changes needed)
- Correlation: multi-event patterns over time (e.g. failures -> success)
- Alerting: console + log file (Telegram/email pluggable later)
- Storage: SQLite (events + alerts)
- Dashboard: simple Flask UI with a chart
- Evaluation: precision/false-positive, throughput and latency scripts

## Run instructions

Step-by-step instructions are added in the final step of the setup.
