# sb2mqtt — SB8200 → MQTT (Home Assistant Auto‑Discovery)

`sb2mqtt` is a small C daemon for Linux that polls an Arris **SB8200** cable modem status page using `lynx --dump`, parses:

- **Startup Procedure** (especially *Connectivity State*)
- **Downstream Bonded Channels**
- **Upstream Bonded Channels**

…and publishes the parsed values to an MQTT broker. It also publishes **Home Assistant MQTT Discovery** config so sensors appear automatically in Home Assistant.

Designed to run 24/7 on Debian (including Debian 13).

---

## How it works

Every `interval_sec` seconds, `sb2mqtt`:

1. Runs:
   ```bash
   lynx --dump -nolist --width=200 <url>
   ```
2. Parses the text output into structured rows for Startup / Downstream / Upstream.
3. Publishes:
   - `base_topic/availability` (`online` / `offline`)
   - Parsed values under `base_topic/...` (retained by default)
4. Publishes **Home Assistant discovery** config (retained):
   - On first successful poll
   - Whenever relevant config changes are detected
   - Every **30 minutes** (rediscovery refresh)

It also watches the INI file (by mtime) and **hot‑reloads** it:
- If MQTT settings change → reconnects to broker
- If HA identity/topic/channel filters change → republishes discovery
- If log path changes → reopens the log file

---

## Features

- ✅ Polls SB8200 status via `lynx` (no HTML parsing libs required)
- ✅ Parses **full upstream + downstream rows**
- ✅ Publishes MQTT topics for each metric (optional channel filtering)
- ✅ Home Assistant MQTT Discovery (auto sensors)
- ✅ Retained discovery (so HA can restart and keep sensors)
- ✅ Retained state (so HA sees last values immediately)
- ✅ Hot INI reload + reconnect as needed
- ✅ HA discovery republish every 30 minutes
- ✅ File logging + systemd journal logging

---

## Requirements

### Build dependencies
- `build-essential`
- `lynx`
- `libmosquitto-dev`

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential lynx libmosquitto-dev
```

### Runtime dependencies
- `lynx`
- `libmosquitto` runtime library (installed automatically by `libmosquitto-dev`)
- An MQTT broker (Mosquitto recommended)
- Home Assistant with MQTT integration enabled (optional, but this is the point 🙂)

---

## Build

From the repo directory:

```bash
gcc -O2 -Wall -Wextra -o sb2mqtt sb2mqtt.c -lmosquitto
```

Install the binary:
```bash
sudo install -m 0755 sb2mqtt /usr/local/bin/sb2mqtt
```

---

## Quick test (before systemd)

### Confirm SB8200 page is reachable
```bash
lynx --dump -nolist --width=200 http://192.168.100.1/
```

### Run sb2mqtt manually
```bash
sudo /usr/local/bin/sb2mqtt --ini /etc/sb2mqtt.ini
```

### Watch MQTT output
(Replace broker host if not local.)
```bash
mosquitto_sub -h 127.0.0.1 -v -t 'sb2mqtt/#'
mosquitto_sub -h 127.0.0.1 -v -t 'homeassistant/#'
```

---

## Configuration

`sb2mqtt` reads an INI file.

- Default path: **`/etc/sb2mqtt.ini`**
- Override: `sb2mqtt --ini /path/to/sb2mqtt.ini`

Create it:
```bash
sudo nano /etc/sb2mqtt.ini
sudo chmod 600 /etc/sb2mqtt.ini
sudo chown root:root /etc/sb2mqtt.ini
```

### Example `/etc/sb2mqtt.ini`

```ini
[poll]
# SB8200 local status page
url = http://192.168.100.1/
# The SB8200 page can be slow. These defaults are intentionally generous.
interval_sec = 90
timeout_sec  = 60

[mqtt]
host = 127.0.0.1
port = 1883
username =
password =
client_id = sb2mqtt
qos = 1
retain_state = true

[ha]
discovery_prefix = homeassistant
device_name = SB8200 Modem
device_id = sb8200
# base topic for state publishing
base_topic = sb2mqtt

[channels]
# Optional filters (comma-separated). If empty/missing => publish ALL channels found.
# downstream_ids = 1,2,3,4,5,6,7,8
# upstream_ids   = 1,2,3,4

[log]
path = /var/log/sb2mqtt.log

[ini]
# How often to check INI for changes (seconds)
check_sec = 15
```

### Notes on timing
- `timeout_sec` is how long we let `lynx` run before killing it.
- `interval_sec` is the sleep time between polls.
- If `timeout_sec >= interval_sec`, the app will clamp `timeout_sec` slightly below `interval_sec` to avoid overlap.

---

## MQTT topics published

Assuming defaults:
- `base_topic = sb2mqtt`
- `device_id = sb8200`

### Availability / basic status
- `sb2mqtt/availability` → `online` / `offline`
- `sb2mqtt/connectivity_state` → typically `OK` (or `unknown`)

### Downstream (per Channel ID)
For each downstream channel `<id>`:
- `sb2mqtt/ds/<id>/lock_status` *(string)*
- `sb2mqtt/ds/<id>/modulation` *(string, e.g. `QAM256`)*
- `sb2mqtt/ds/<id>/frequency_hz` *(integer Hz)*
- `sb2mqtt/ds/<id>/power_dbmv` *(float dBmV)*
- `sb2mqtt/ds/<id>/snr_db` *(float dB)*
- `sb2mqtt/ds/<id>/corrected` *(integer)*
- `sb2mqtt/ds/<id>/uncorrectables` *(integer)*

Totals:
- `sb2mqtt/downstream_corrected_total`
- `sb2mqtt/downstream_uncorrectables_total`

### Upstream (per Channel ID)
For each upstream channel `<id>`:
- `sb2mqtt/us/<id>/channel` *(the “Channel” column, integer)*
- `sb2mqtt/us/<id>/lock_status` *(string)*
- `sb2mqtt/us/<id>/type` *(string, e.g. `SC-QAM`)*
- `sb2mqtt/us/<id>/frequency_hz` *(integer Hz)*
- `sb2mqtt/us/<id>/width_hz` *(integer Hz)*
- `sb2mqtt/us/<id>/power_dbmv` *(float dBmV)*

---

## Home Assistant MQTT Discovery details

Discovery config topics are published (retained) at:

- `<discovery_prefix>/sensor/<device_id>/<object_id>/config`

Defaults:
- `discovery_prefix = homeassistant`
- `device_id = sb8200`

So you’ll see config topics like:
- `homeassistant/sensor/sb8200/ds_1_power/config`
- `homeassistant/sensor/sb8200/us_3_freq/config`

Home Assistant will create sensors automatically when it receives those retained config topics.

Discovery is republished every **30 minutes** in case HA or MQTT was down during startup.

---

## Logging

By default:
- Log file: **`/var/log/sb2mqtt.log`**

View live:
```bash
sudo tail -f /var/log/sb2mqtt.log
```

If running under systemd, you can also see logs in the journal:
```bash
sudo journalctl -u sb2mqtt -f
```

---

## systemd service (recommended)

Create a dedicated user (optional but recommended):
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sb2mqtt || true
```

Make sure the log file is writable by the service user (or use journald only).
If you keep file logging at `/var/log/sb2mqtt.log`:
```bash
sudo touch /var/log/sb2mqtt.log
sudo chown sb2mqtt:sb2mqtt /var/log/sb2mqtt.log
sudo chmod 640 /var/log/sb2mqtt.log
```

### Create the service file

Save as: **`/etc/systemd/system/sb2mqtt.service`**

```ini
[Unit]
Description=sb2mqtt (SB8200 -> MQTT / Home Assistant Discovery)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sb2mqtt
Group=sb2mqtt
ExecStart=/usr/local/bin/sb2mqtt --ini /etc/sb2mqtt.ini
Restart=on-failure
RestartSec=5

# Hardening (safe defaults)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /etc/sb2mqtt.ini
AmbientCapabilities=
CapabilityBoundingSet=
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
```

Reload and enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sb2mqtt
```

Check status:
```bash
sudo systemctl status sb2mqtt --no-pager
```

Follow logs:
```bash
sudo journalctl -u sb2mqtt -f
```

---

## Troubleshooting

### 1) No sensors show up in Home Assistant
- Confirm discovery topics exist:
  ```bash
  mosquitto_sub -v -t 'homeassistant/#'
  ```
- Confirm state topics exist:
  ```bash
  mosquitto_sub -v -t 'sb2mqtt/#'
  ```
- Verify HA MQTT integration is connected to the same broker.
- Wait up to 30 minutes (rediscovery refresh), or restart the service:
  ```bash
  sudo systemctl restart sb2mqtt
  ```

### 2) Poll failures / empty output
- Confirm you can dump the page manually:
  ```bash
  lynx --dump -nolist --width=200 http://192.168.100.1/
  ```
- Increase `timeout_sec` if needed (SB8200 can take ~40s sometimes).

### 3) Too many sensors / you only care about some channels
Use channel filters:

```ini
[channels]
downstream_ids = 1,2,3,4,5,6,7,8
upstream_ids   = 1,2,3,4
```

### 4) MQTT auth errors
- Check credentials and broker logs.
- Test broker access:
  ```bash
  mosquitto_pub -h <host> -u <user> -P <pass> -t test -m hello
  ```

---

## Security notes

- MQTT credentials (if used) are stored in `/etc/sb2mqtt.ini`. Protect it:
  ```bash
  sudo chmod 600 /etc/sb2mqtt.ini
  sudo chown root:root /etc/sb2mqtt.ini
  ```
- The SB8200 status page (`192.168.100.1`) is typically local-only; don’t expose it publicly.

---

## Uninstall

```bash
sudo systemctl disable --now sb2mqtt || true
sudo rm -f /etc/systemd/system/sb2mqtt.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/sb2mqtt
sudo rm -f /etc/sb2mqtt.ini
sudo rm -f /var/log/sb2mqtt.log
sudo userdel sb2mqtt || true
```

---

