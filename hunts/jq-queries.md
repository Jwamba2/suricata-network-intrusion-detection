# Threat-hunting queries (Suricata EVE JSON + jq)

Author: Wamba José. Run on the Suricata sensor (Ubuntu). Live logs: `/var/log/suricata/eve.json`. PCAP run: `~/pcap-lab/output/eve.json`.

## Live lab

**1. Event types recorded**
```bash
sudo jq -r '.event_type' /var/log/suricata/eve.json | sort | uniq -c | sort -rn
```

**2. Custom-rule attack timeline (first hit per rule)**
```bash
sudo jq -r 'select(.event_type=="alert" and (.alert.signature|startswith("LOCAL"))) | [.timestamp[11:19], .src_ip, .dest_ip, .alert.signature] | @tsv' /var/log/suricata/eve.json | sort -k4 -u | sort
```

**3. Top 10 alerts**
```bash
sudo jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -n 10
```

**4. DNS names queried**
```bash
sudo jq -r 'select(.event_type=="dns") | .. | .rrname? // empty' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -n 15
```

**5. HTTP User-Agents (unmask scanners)**
```bash
sudo jq -r 'select(.event_type=="http") | .http.http_user_agent // "none"' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -n 10
```

**6. Files seen on the wire**
```bash
sudo jq -r 'select(.event_type=="fileinfo") | [.timestamp[11:19], .src_ip, .dest_ip, .fileinfo.filename, .fileinfo.size] | @tsv' /var/log/suricata/eve.json
```

**7. Community ID pivot (all events linked to one alert)**
```bash
CID=$(sudo jq -r 'select(.event_type=="alert" and .alert.signature_id==1000008) | .community_id' /var/log/suricata/eve.json | tail -n 1)
sudo jq -c --arg c "$CID" 'select(.community_id==$c) | {type: .event_type, time: .timestamp[11:19], src: .src_ip, dst: .dest_ip, url: .http.url, ua: .http.http_user_agent, status: .http.status, file: .fileinfo.filename, alert: .alert.signature}' /var/log/suricata/eve.json
```

## PCAP investigation (NetSupport RAT)

**Top alerts with severity**
```bash
sudo jq -r 'select(.event_type=="alert") | "\(.alert.severity) | \(.alert.signature)"' output/eve.json | sort | uniq -c | sort -rn | head -n 15
```

**Infected internal host**
```bash
sudo jq -r 'select(.event_type=="alert") | .src_ip, .dest_ip' output/eve.json | grep '^10\.11\.10\.' | sort | uniq -c | sort -rn
```

**Initial PowerShell download**
```bash
sudo jq -r 'select(.event_type=="http" and ((.http.http_user_agent // "") | test("PowerShell"))) | [.timestamp[11:19], .dest_ip, .http.hostname, .http.url, .http.status] | @tsv' output/eve.json
```

**C2 beacon timing**
```bash
sudo jq -r 'select(.event_type=="alert" and (.alert.signature|test("NetSupport Remote Admin Checkin"))) | [.timestamp[11:19], .dest_ip, .dest_port] | @tsv' output/eve.json | head -n 10
```

**Custom-rule false-positive check**
```bash
sudo jq -r 'select(.event_type=="alert" and .alert.signature_id==1000002) | [.timestamp[11:19], .src_ip, .dest_ip, .dest_port] | @tsv' output/eve.json
```

**Victim host and user (Kerberos)**
```bash
sudo jq -r 'select(.event_type=="krb5") | .krb5.cname // empty' output/eve.json | sort | uniq -c
```
