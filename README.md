# Wireshark-packet-investigation

# Wireshark SOC Investigation: Identifying an Infected Windows Client

## 📖 Investigation Background

This investigation is based on the [“First to Last” traffic-analysis exercise](https://www.malware-traffic-analysis.net/2026/08/09/index.html). While covering a SOC shift, I received a series of alerts labeled `ET MALWARE FormBook CnC Checkin (GET)`. The alerts identified several external IP addresses receiving HTTP traffic between approximately 02:13 and 02:16 UTC. My task was to use the packet capture to identify the infected Windows client and establish its MAC address, hostname, user account and the account’s full name. [malware-traffic-analysis](https://www.malware-traffic-analysis.net/2026/08/09/index.html)

The critical starting distinction was that the IP addresses in the alerts were **destinations**. I needed to determine which internal host initiated the requests, then build an evidence chain from that host to its device and account identities.

## ❓ Investigation Questions

1. What was the IP address of the infected Windows client?
2. What was its MAC address?
3. What was its hostname?
4. What Windows user account was associated with it?
5. What full name was associated with that account?

## 🧪 Investigation Method

I used Wireshark display filters to move from the most direct evidence—the alerted HTTP requests—to progressively more specific identity evidence. At each step, I checked whether the new value could be linked to the endpoint already identified, rather than treating any plausible-looking name in the capture as an answer.

The evidence chain was:

**Alerted destination → HTTP source IP → Ethernet source MAC → DHCP hostname → Kerberos account → SAMR full name**

The environment used the `172.16.8.0/24` LAN and the `firsttolast.tech` Active Directory domain. The alerts named these external destinations on TCP port 80: [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/48352591/3ab20d0d-d77b-485b-a7b0-424e79bdd1cc/2026-08-09-traffic-analysis-exercise-answers.pdf?AWSAccessKeyId=ASIA2F3EMEYEW4ZKADX6&Signature=Qti5HUSbRWhI978cByEYidzVOQg%3D&x-amz-security-token=IQoJb3JpZ2luX2VjECwaCXVzLWVhc3QtMSJHMEUCIQC5Hg0dUxM8gfgKaQIQDGES4mKPrOs8HhfsT%2FoF6iY0sgIgcH66J9BIisR6twf%2FORfZM3vZEC1aUKNiwGn8V1TKbWYqgwUI9P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARABGgw2OTk3NTMzMDk3MDUiDNExFNz05zcDKxUz7CrXBCURnGqunjk2rCkd4BUr35BMBFPc%2FZbkxTVzSRAIt61G3q5pXyBWrK0XqfbF3OPiA6i1rT4Ab0JPNgQrsmaedJbOFR5RctXF2ig7UWJTNqru7HoXxnAY0HquKg49PfulhMTf6kYtrkexyy5EBphQzWiEfyITFuOpZINtaV2agbHMT7uUrjuQnpqW1jXFKl1muL7xLwPqNi7vxppdGtJq49KJNuBQ80SqIhh52sisrqJJG44lHG3mXHElmFZPbKi05IJH%2FW0kU2aTGfDJUodiULLNb1apRtjc2uDaQEutSlprSsVHuZJzis%2BcxzeaqFowijnC5g00PGTql8zhWJ04DnN%2B%2Fn2ET9rdMfm1t0NjyHhD801quHgplgYHtGzkHp8HJOctWcfeY0LKgTY5tyvRlVaD4Lrystzxcjv77kQJZ%2BssKVaR3lEQlNJAN15bprT6asKowm0YWBnG986sOzA0epbp2Am3Tkj5mSdZA2wSK6Y6R%2BtdQTHKN5mTnBN0FFXO3ATt6se4VN5awpiwXwNfdsKM5hvMR%2FSRkw0lH2OJ7UB3%2BtRFWOjK3VfOpHGWFkJKpw7y394HQ%2F8u6Ixx9k%2F2xqrKwUVQg%2B0A4DeelljOmjGp180uetM3rw972br6dEqv3MWjnGiupn9Xk6ST%2BFiY1FMq5e7tnUWkIxxNLNzi7rhEaRQ5RjHxV7syOfRpnZ%2B6%2BW1%2BuUCzEKeLPLlU3f%2FZ%2BPJVdkmtB31WiNCqGMCeGchld0AacBC2LZp0%2FGbDBD2ibzx0vitK9JxhYYAH%2BOloBCuzA7WA80LmMJaT29UGOpgBvypbozUY%2BBNd4OW4GF58x7XsogbSF2aVj4dde8TH29Tpeb6z4P00RSjkzdRJBCWvYwKIkuOxbM9IyFk%2FOhZIjCF0ni8FVwzeiyWXem%2Bzoqbo2wltX2Fl3Dvqgu5Of8r1UwMOKNPS2IR9HxCVFUxSuPxdYJoV8GNonviD4jKCo7jW1T3YkdPyMO1bLbA3v%2Fu7XrWZawEi1ts%3D&Expires=1790367593)

| Alert time (UTC) | Destination |
|---|---|
| 02:13 | `172.64.155[.]76:80` |
| 02:14 | `146.59.71[.]167:80` |
| 02:14 | `38.182.168[.]246:80` |
| 02:15 | `45.130.41[.]161:80` |
| 02:15 | `172.67.162[.]153:80` |
| 02:16 | `121.54.163[.]148:80` |

***

## 🔎 Analysis and Results

### 1. Identifying the infected IP address

I started by filtering HTTP requests to one alerted destination:

```wireshark
http.request and ip.dst == 172.64.155.76
```

The matching request showed `172.16.8.49` in Wireshark’s **Source** column. That address was inside the stated LAN range. I repeated the destination-based check for other alert IPs and observed the same internal source.

This cross-check mattered: a single HTTP request could identify a candidate, but repeated requests to multiple alerted destinations provided a stronger basis for identifying the host associated with the alerts.

**Finding:** `172.16.8.49`

### 2. Mapping the IP address to a MAC address

I inspected an HTTP request to another alerted destination, `121.54.163.148`. In the packet details under **Ethernet II**, the source address was:

```text
Source: Intel_28:d4:34 (00:12:f0:28:d4:34)
```

The packet belonged to the traffic I had traced to `172.16.8.49`. I later found the same MAC in the DHCP client details, providing another point of correlation.

**Finding:** `00:12:f0:28:d4:34`

### 3. Establishing the hostname

I filtered DHCP packets using the MAC address:

```wireshark
dhcp and eth.addr == 00:12:f0:28:d4:34
```

In a matching packet, **Client MAC address** was `00:12:f0:28:d4:34`. Two DHCP fields then identified the machine:

```text
Option (12) Host Name: DESKTOP-5NLV63K
Option (81) Client name: DESKTOP-5NLV63K.firsttolast.tech
```

The MAC match tied the DHCP record to the endpoint identified in the HTTP traffic. Option 12 supplied the hostname, while Option 81 corroborated it as part of the computer’s fully qualified domain name. The “client name” in Option 81 referred to the DHCP client—not the Windows user—so I did not use it to answer the account question. [wireshark](https://www.wireshark.org/docs/dfref/d/dhcp.html)

**Finding:** `DESKTOP-5NLV63K`

### 4. Distinguishing the user from the computer account

An initial Kerberos search produced thousands of records. To reduce unrelated results, I narrowed the display to Kerberos AS-REQ packets sent from the identified IP:

```wireshark
ip.src == 172.16.8.49 and kerberos.msg_type == 10 and kerberos.CNameString
```

I observed two `CNameString` values:

```text
rvance
desktop-5nlv63k$
```

`desktop-5nlv63k$` matched the workstation name and used the trailing `$` convention for a computer account. I therefore did not mistake it for the person’s logon account. The relevant user principal was `rvance`. Wireshark exposes `CNameString` as a Kerberos field, making this a reproducible protocol-level pivot rather than an inference from the hostname. [wireshark](https://www.wireshark.org/docs/dfref/k/kerberos.html)

**Finding:** `rvance`

### 5. Mapping the account to a full name

My initial LDAP searches for `givenName` and `CN=...` did not return useful matches. An empty result did not prove the name was absent from the capture; it meant that search path had not located it. I changed tactics and filtered for a decoded SAMR full-name field:

```wireshark
samr.samr_UserInfo21.full_name
```

In a matching SAMR record, I observed:

```text
Account Name: rvance
Full Name: Raymond Vance
```

The packet ran from `172.16.8.8` to `172.16.8.4`, rather than directly to or from the infected client. I did **not** assume that `172.16.8.4` was the victim. The relevant link was the explicit `Account Name: rvance`, which matched the user principal found in Kerberos traffic from `172.16.8.49`. Wireshark defines separate SAMR UserInfo21 account-name and full-name fields. [wireshark](https://www.wireshark.org/docs/dfref/s/samr.html)

I then tested the first-name spelling with exact field filters:

```wireshark
samr.samr_UserInfo21.full_name == "Raymond Vance"
```

```wireshark
samr.samr_UserInfo21.full_name == "Ryamond Vance"
```

In my Wireshark session, the **Raymond** filter returned one record with the matching account name; the **Ryamond** filter returned none. The supplied exercise answer sheet, however, spells the name `Ryamond Vance`. I have preserved that discrepancy rather than changing what I observed in the decoded packet. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/48352591/3ab20d0d-d77b-485b-a7b0-424e79bdd1cc/2026-08-09-traffic-analysis-exercise-answers.pdf?AWSAccessKeyId=ASIA2F3EMEYEW4ZKADX6&Signature=Qti5HUSbRWhI978cByEYidzVOQg%3D&x-amz-security-token=IQoJb3JpZ2luX2VjECwaCXVzLWVhc3QtMSJHMEUCIQC5Hg0dUxM8gfgKaQIQDGES4mKPrOs8HhfsT%2FoF6iY0sgIgcH66J9BIisR6twf%2FORfZM3vZEC1aUKNiwGn8V1TKbWYqgwUI9P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARABGgw2OTk3NTMzMDk3MDUiDNExFNz05zcDKxUz7CrXBCURnGqunjk2rCkd4BUr35BMBFPc%2FZbkxTVzSRAIt61G3q5pXyBWrK0XqfbF3OPiA6i1rT4Ab0JPNgQrsmaedJbOFR5RctXF2ig7UWJTNqru7HoXxnAY0HquKg49PfulhMTf6kYtrkexyy5EBphQzWiEfyITFuOpZINtaV2agbHMT7uUrjuQnpqW1jXFKl1muL7xLwPqNi7vxppdGtJq49KJNuBQ80SqIhh52sisrqJJG44lHG3mXHElmFZPbKi05IJH%2FW0kU2aTGfDJUodiULLNb1apRtjc2uDaQEutSlprSsVHuZJzis%2BcxzeaqFowijnC5g00PGTql8zhWJ04DnN%2B%2Fn2ET9rdMfm1t0NjyHhD801quHgplgYHtGzkHp8HJOctWcfeY0LKgTY5tyvRlVaD4Lrystzxcjv77kQJZ%2BssKVaR3lEQlNJAN15bprT6asKowm0YWBnG986sOzA0epbp2Am3Tkj5mSdZA2wSK6Y6R%2BtdQTHKN5mTnBN0FFXO3ATt6se4VN5awpiwXwNfdsKM5hvMR%2FSRkw0lH2OJ7UB3%2BtRFWOjK3VfOpHGWFkJKpw7y394HQ%2F8u6Ixx9k%2F2xqrKwUVQg%2B0A4DeelljOmjGp180uetM3rw972br6dEqv3MWjnGiupn9Xk6ST%2BFiY1FMq5e7tnUWkIxxNLNzi7rhEaRQ5RjHxV7syOfRpnZ%2B6%2BW1%2BuUCzEKeLPLlU3f%2FZ%2BPJVdkmtB31WiNCqGMCeGchld0AacBC2LZp0%2FGbDBD2ibzx0vitK9JxhYYAH%2BOloBCuzA7WA80LmMJaT29UGOpgBvypbozUY%2BBNd4OW4GF58x7XsogbSF2aVj4dde8TH29Tpeb6z4P00RSjkzdRJBCWvYwKIkuOxbM9IyFk%2FOhZIjCF0ni8FVwzeiyWXem%2Bzoqbo2wltX2Fl3Dvqgu5Of8r1UwMOKNPS2IR9HxCVFUxSuPxdYJoV8GNonviD4jKCo7jW1T3YkdPyMO1bLbA3v%2Fu7XrWZawEi1ts%3D&Expires=1790367593)

**Finding observed in Wireshark:** `Raymond Vance`

***

## 📊 Evidence Summary

| Question | Result | Primary evidence used |
|---|---|---|
| Infected IP | `172.16.8.49` | Source of HTTP requests to multiple alerted destinations |
| MAC address | `00:12:f0:28:d4:34` | Ethernet II source, corroborated by DHCP client MAC |
| Hostname | `DESKTOP-5NLV63K` | DHCP Option 12; corroborated by Option 81 |
| Windows account | `rvance` | Kerberos `CNameString` in AS-REQ traffic from the infected IP |
| Full name | `Raymond Vance` in the inspected SAMR record | SAMR `Account Name: rvance` and `Full Name`; published answer sheet has a different spelling |

## ⚖️ Analytical Limitations

- **Alert name is not definitive malware attribution.** The detection label said FormBook. The supplied answer sheet suggests the traffic is likely XLoader, but I did not analyse a malware binary. I would report the alert label separately from any unverified family attribution. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/48352591/3ab20d0d-d77b-485b-a7b0-424e79bdd1cc/2026-08-09-traffic-analysis-exercise-answers.pdf?AWSAccessKeyId=ASIA2F3EMEYEW4ZKADX6&Signature=Qti5HUSbRWhI978cByEYidzVOQg%3D&x-amz-security-token=IQoJb3JpZ2luX2VjECwaCXVzLWVhc3QtMSJHMEUCIQC5Hg0dUxM8gfgKaQIQDGES4mKPrOs8HhfsT%2FoF6iY0sgIgcH66J9BIisR6twf%2FORfZM3vZEC1aUKNiwGn8V1TKbWYqgwUI9P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARABGgw2OTk3NTMzMDk3MDUiDNExFNz05zcDKxUz7CrXBCURnGqunjk2rCkd4BUr35BMBFPc%2FZbkxTVzSRAIt61G3q5pXyBWrK0XqfbF3OPiA6i1rT4Ab0JPNgQrsmaedJbOFR5RctXF2ig7UWJTNqru7HoXxnAY0HquKg49PfulhMTf6kYtrkexyy5EBphQzWiEfyITFuOpZINtaV2agbHMT7uUrjuQnpqW1jXFKl1muL7xLwPqNi7vxppdGtJq49KJNuBQ80SqIhh52sisrqJJG44lHG3mXHElmFZPbKi05IJH%2FW0kU2aTGfDJUodiULLNb1apRtjc2uDaQEutSlprSsVHuZJzis%2BcxzeaqFowijnC5g00PGTql8zhWJ04DnN%2B%2Fn2ET9rdMfm1t0NjyHhD801quHgplgYHtGzkHp8HJOctWcfeY0LKgTY5tyvRlVaD4Lrystzxcjv77kQJZ%2BssKVaR3lEQlNJAN15bprT6asKowm0YWBnG986sOzA0epbp2Am3Tkj5mSdZA2wSK6Y6R%2BtdQTHKN5mTnBN0FFXO3ATt6se4VN5awpiwXwNfdsKM5hvMR%2FSRkw0lH2OJ7UB3%2BtRFWOjK3VfOpHGWFkJKpw7y394HQ%2F8u6Ixx9k%2F2xqrKwUVQg%2B0A4DeelljOmjGp180uetM3rw972br6dEqv3MWjnGiupn9Xk6ST%2BFiY1FMq5e7tnUWkIxxNLNzi7rhEaRQ5RjHxV7syOfRpnZ%2B6%2BW1%2BuUCzEKeLPLlU3f%2FZ%2BPJVdkmtB31WiNCqGMCeGchld0AacBC2LZp0%2FGbDBD2ibzx0vitK9JxhYYAH%2BOloBCuzA7WA80LmMJaT29UGOpgBvypbozUY%2BBNd4OW4GF58x7XsogbSF2aVj4dde8TH29Tpeb6z4P00RSjkzdRJBCWvYwKIkuOxbM9IyFk%2FOhZIjCF0ni8FVwzeiyWXem%2Bzoqbo2wltX2Fl3Dvqgu5Of8r1UwMOKNPS2IR9HxCVFUxSuPxdYJoV8GNonviD4jKCo7jW1T3YkdPyMO1bLbA3v%2Fu7XrWZawEi1ts%3D&Expires=1790367593)
- **Account association does not prove individual action.** The network evidence associates `rvance` with the client and maps that account to a name. It does not prove that the named person knowingly ran malware.
- **Another Windows client was present.** The answer sheet notes a separate client at `172.16.8.53`. I selected `172.16.8.49` because it originated traffic to the alerted destinations, not merely because it appeared on the LAN. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/48352591/3ab20d0d-d77b-485b-a7b0-424e79bdd1cc/2026-08-09-traffic-analysis-exercise-answers.pdf?AWSAccessKeyId=ASIA2F3EMEYEW4ZKADX6&Signature=Qti5HUSbRWhI978cByEYidzVOQg%3D&x-amz-security-token=IQoJb3JpZ2luX2VjECwaCXVzLWVhc3QtMSJHMEUCIQC5Hg0dUxM8gfgKaQIQDGES4mKPrOs8HhfsT%2FoF6iY0sgIgcH66J9BIisR6twf%2FORfZM3vZEC1aUKNiwGn8V1TKbWYqgwUI9P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARABGgw2OTk3NTMzMDk3MDUiDNExFNz05zcDKxUz7CrXBCURnGqunjk2rCkd4BUr35BMBFPc%2FZbkxTVzSRAIt61G3q5pXyBWrK0XqfbF3OPiA6i1rT4Ab0JPNgQrsmaedJbOFR5RctXF2ig7UWJTNqru7HoXxnAY0HquKg49PfulhMTf6kYtrkexyy5EBphQzWiEfyITFuOpZINtaV2agbHMT7uUrjuQnpqW1jXFKl1muL7xLwPqNi7vxppdGtJq49KJNuBQ80SqIhh52sisrqJJG44lHG3mXHElmFZPbKi05IJH%2FW0kU2aTGfDJUodiULLNb1apRtjc2uDaQEutSlprSsVHuZJzis%2BcxzeaqFowijnC5g00PGTql8zhWJ04DnN%2B%2Fn2ET9rdMfm1t0NjyHhD801quHgplgYHtGzkHp8HJOctWcfeY0LKgTY5tyvRlVaD4Lrystzxcjv77kQJZ%2BssKVaR3lEQlNJAN15bprT6asKowm0YWBnG986sOzA0epbp2Am3Tkj5mSdZA2wSK6Y6R%2BtdQTHKN5mTnBN0FFXO3ATt6se4VN5awpiwXwNfdsKM5hvMR%2FSRkw0lH2OJ7UB3%2BtRFWOjK3VfOpHGWFkJKpw7y394HQ%2F8u6Ixx9k%2F2xqrKwUVQg%2B0A4DeelljOmjGp180uetM3rw972br6dEqv3MWjnGiupn9Xk6ST%2BFiY1FMq5e7tnUWkIxxNLNzi7rhEaRQ5RjHxV7syOfRpnZ%2B6%2BW1%2BuUCzEKeLPLlU3f%2FZ%2BPJVdkmtB31WiNCqGMCeGchld0AacBC2LZp0%2FGbDBD2ibzx0vitK9JxhYYAH%2BOloBCuzA7WA80LmMJaT29UGOpgBvypbozUY%2BBNd4OW4GF58x7XsogbSF2aVj4dde8TH29Tpeb6z4P00RSjkzdRJBCWvYwKIkuOxbM9IyFk%2FOhZIjCF0ni8FVwzeiyWXem%2Bzoqbo2wltX2Fl3Dvqgu5Of8r1UwMOKNPS2IR9HxCVFUxSuPxdYJoV8GNonviD4jKCo7jW1T3YkdPyMO1bLbA3v%2Fu7XrWZawEi1ts%3D&Expires=1790367593)
- **The stated domain-controller address conflicts across exercise materials.** The exercise webpage lists `172.16.8.2`, while the supplied answer PDF lists `172.16.8.8`. My analysis describes the packet endpoints I observed rather than forcing the two descriptions to agree. [malware-traffic-analysis](https://www.malware-traffic-analysis.net/2026/08/09/index.html)
- **The full-name spelling remains a documented discrepancy.** My exact SAMR field search matched `Raymond Vance`; the supplied answer sheet says `Ryamond Vance`. The cause has not been independently established. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/48352591/3ab20d0d-d77b-485b-a7b0-424e79bdd1cc/2026-08-09-traffic-analysis-exercise-answers.pdf?AWSAccessKeyId=ASIA2F3EMEYEW4ZKADX6&Signature=Qti5HUSbRWhI978cByEYidzVOQg%3D&x-amz-security-token=IQoJb3JpZ2luX2VjECwaCXVzLWVhc3QtMSJHMEUCIQC5Hg0dUxM8gfgKaQIQDGES4mKPrOs8HhfsT%2FoF6iY0sgIgcH66J9BIisR6twf%2FORfZM3vZEC1aUKNiwGn8V1TKbWYqgwUI9P%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FARABGgw2OTk3NTMzMDk3MDUiDNExFNz05zcDKxUz7CrXBCURnGqunjk2rCkd4BUr35BMBFPc%2FZbkxTVzSRAIt61G3q5pXyBWrK0XqfbF3OPiA6i1rT4Ab0JPNgQrsmaedJbOFR5RctXF2ig7UWJTNqru7HoXxnAY0HquKg49PfulhMTf6kYtrkexyy5EBphQzWiEfyITFuOpZINtaV2agbHMT7uUrjuQnpqW1jXFKl1muL7xLwPqNi7vxppdGtJq49KJNuBQ80SqIhh52sisrqJJG44lHG3mXHElmFZPbKi05IJH%2FW0kU2aTGfDJUodiULLNb1apRtjc2uDaQEutSlprSsVHuZJzis%2BcxzeaqFowijnC5g00PGTql8zhWJ04DnN%2B%2Fn2ET9rdMfm1t0NjyHhD801quHgplgYHtGzkHp8HJOctWcfeY0LKgTY5tyvRlVaD4Lrystzxcjv77kQJZ%2BssKVaR3lEQlNJAN15bprT6asKowm0YWBnG986sOzA0epbp2Am3Tkj5mSdZA2wSK6Y6R%2BtdQTHKN5mTnBN0FFXO3ATt6se4VN5awpiwXwNfdsKM5hvMR%2FSRkw0lH2OJ7UB3%2BtRFWOjK3VfOpHGWFkJKpw7y394HQ%2F8u6Ixx9k%2F2xqrKwUVQg%2B0A4DeelljOmjGp180uetM3rw972br6dEqv3MWjnGiupn9Xk6ST%2BFiY1FMq5e7tnUWkIxxNLNzi7rhEaRQ5RjHxV7syOfRpnZ%2B6%2BW1%2BuUCzEKeLPLlU3f%2FZ%2BPJVdkmtB31WiNCqGMCeGchld0AacBC2LZp0%2FGbDBD2ibzx0vitK9JxhYYAH%2BOloBCuzA7WA80LmMJaT29UGOpgBvypbozUY%2BBNd4OW4GF58x7XsogbSF2aVj4dde8TH29Tpeb6z4P00RSjkzdRJBCWvYwKIkuOxbM9IyFk%2FOhZIjCF0ni8FVwzeiyWXem%2Bzoqbo2wltX2Fl3Dvqgu5Of8r1UwMOKNPS2IR9HxCVFUxSuPxdYJoV8GNonviD4jKCo7jW1T3YkdPyMO1bLbA3v%2Fu7XrWZawEi1ts%3D&Expires=1790367593)
- **Some forensic artifacts were not recorded during this exercise.** I did not capture frame numbers, a pcap hash, or the Wireshark version for this write-up. I would add those, along with screenshots of the relevant decoded fields, before treating it as a formal evidence package.

## ✅ Conclusion

I identified the client associated with the C2 alerts by following packet evidence from the external destinations back to `172.16.8.49`, then correlating that IP with a MAC address, DHCP hostname and Kerberos user principal. A SAMR record mapped the principal `rvance` to the full name displayed in my Wireshark session.

The most important lesson from this exercise was methodological: **each identity claim needed an explicit link to the previous one**. Broad searches produced competing records, DHCP named a computer rather than a person, and a relevant SAMR response did not itself involve the infected IP. Narrowing filters, checking account fields and recording conflicts with the answer sheet produced a more defensible finding than simply copying five values.

## 📚 Exercise and Technical References

- [Malware-Traffic-Analysis.net — “First to Last” exercise](https://www.malware-traffic-analysis.net/2026/08/09/index.html)
- Supplied exercise answer PDF: `2026-08-09-traffic-analysis-exercise-answers.pdf`
- [Wireshark Kerberos display-filter reference](https://www.wireshark.org/docs/dfref/k/kerberos.html)
- [Wireshark SAMR display-filter reference](https://www.wireshark.org/docs/dfref/s/samr.html)
- [RFC 4702 — DHCP Client FQDN Option](https://datatracker.ietf.org/doc/html/rfc4702)
