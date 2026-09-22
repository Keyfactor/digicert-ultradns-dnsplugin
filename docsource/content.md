## Overview

The UltraDNS Provider plugin enables automated DNS-based domain validation for Keyfactor certificate lifecycle management through DigiCert UltraDNS. This plugin integrates with the UltraDNS REST API to automatically create, verify, and delete DNS TXT records required for domain validation during certificate issuance and renewal.

## Features

- OAuth2 password-grant authentication using an UltraDNS account username and password
- Automatic zone discovery across all zones visible to the account, matched by longest domain suffix
- Idempotent cleanup — a challenge record that no longer exists is treated as already cleaned up

## Requirements

- An UltraDNS account with one or more zones managed by UltraDNS
- An UltraDNS account username and password with permission to read, create, and delete resource record sets in the target zone(s)
