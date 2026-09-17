---
layout: default
title: Upstream proxy
---

# Upstream proxy with per-phishlet routing

Feature #17. Some identity providers block datacenter IPs outright (Google flags AWS
exits); others risk-flag residential logins for corporate accounts (Microsoft Entra).
The fork lets each node configure **one upstream proxy with per-domain-suffix routing**:
matched traffic egresses through the proxy, everything else goes direct.

## Configuration

### Via the console

```text
eg> proxy
    current: off

eg> proxy set socks5 <user> <pass> <proxy-host> <proxy-port> google.com,gstatic.com,googleusercontent.com
eg> proxy on
eg> proxy route add mail.google.com        # hot-add a routed suffix
eg> proxy route del mail.google.com
eg> proxy off                              # disable without forgetting the config
```

Hot-applied — no service restart. Persisted in the node config.

### Via the mTLS API

`POST /proxy` (partial update — omitted keys keep their values):

```json
{
  "type": "socks5",
  "host": "<proxy-host>",
  "port": 48726,
  "username": "<user>",
  "password": "<pass>",
  "enabled": true,
  "routes": ["google.com", "gstatic.com", "googleusercontent.com"]
}
```

`GET /proxy` returns the state with the password masked. Note: a masked password echoed
back in a later POST **clobbers it** — send the real password when you intend to change
credentials.

## How routing works

The dialer matches the **destination domain suffix** against `routes`:

```
google phishlet fetch of accounts.google.com  → suffix match → SOCKS5 residential exit
ms365 phishlet fetch of login.live.com        → no match    → node IP (direct)
```

Both the proxy transport and the CONNECT path honor the selector (the HTTP client uses the
proxied dialer for CONNECT when a proxy is set).

## Field doctrine

| Target | Egress | Why |
|---|---|---|
| Google | residential SOCKS5 | datacenter exits are pre-flagged; residential passes the lookup |
| ms365 (corporate/work accounts) | **direct** | a residential login on a work account looks *more* suspicious to Entra Conditional Access |

Verify after configuring: render the phishlet's identifier page and check the egress IP
the identity provider would see (a routed fetch through a residential exit should show
the exit's IP, not the node's).
