<h1 align="center" style="border-bottom: none">
    UltraDNS DNS Provider
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/digicert-ultradns-dnsplugin/actions/workflows/keyfactor-starter-workflow.yml"><img src="https://github.com/Keyfactor/digicert-ultradns-dnsplugin/actions/workflows/keyfactor-starter-workflow.yml/badge.svg" alt="Build" /></a>
<a href="https://github.com/Keyfactor/digicert-ultradns-dnsplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/digicert-ultradns-dnsplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/digicert-ultradns-dnsplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/digicert-ultradns-dnsplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=dnsplugin">
    <b>Related Integrations</b>
  </a>
</p>

## Overview

The UltraDNS Provider plugin enables automated DNS-based domain validation for Keyfactor certificate lifecycle management through DigiCert UltraDNS. This plugin integrates with the UltraDNS REST API to automatically create, verify, and delete DNS TXT records required for domain validation during certificate issuance and renewal.

## Features

- Automated DNS TXT record creation and deletion in UltraDNS
- OAuth2 password-grant authentication using an UltraDNS account username and password
- Automatic zone discovery across all zones visible to the account, matched by longest domain suffix
- Idempotent cleanup — a challenge record that no longer exists is treated as already cleaned up

## Requirements

### Keyfactor Platform
- Keyfactor AnyCA Gateway REST **26.2 or later** (DNS validation support was added in AnyCA Gateway 26.2)
- A gateway product that supports DNS-01 domain validation (ACME REST Gateway, DigiCert, Sectigo, etc.)

### UltraDNS Requirements

- An UltraDNS account with one or more zones managed by UltraDNS
- An UltraDNS account username and password with permission to read, create, and delete resource record sets in the target zone(s)

### Runtime Requirements
- .NET 10.0 runtime (provided by the gateway server)
- Network connectivity to api.ultradns.com (HTTPS/443)

## Installation

This plugin is installed alongside any Keyfactor gateway server that supports DNS-01 domain validation (ACME REST Gateway, DigiCert, Sectigo, etc.). The same DLL works with every supported gateway.

> See the official Keyfactor AnyCA Gateway REST installation documentation for the authoritative install instructions: **<TBD link from Sarah Duncan>**. The steps below are a general guide; defer to the official docs if they diverge.

### 1. Download the Plugin

Download the latest release from the [Releases](https://github.com/Keyfactor/digicert-ultradns-dnsplugin/releases) page.

### 2. Copy the plugin DLLs to the gateway's Extensions folder

On the server hosting your gateway, unzip the release and copy the contents of the `net10.0` directory into the gateway's `Extensions` folder.

**Windows** (example path — substitute the gateway product folder for your install):

```text
C:\Program Files\Keyfactor\<GatewayName>\AnyGatewayREST\net10.0\Extensions\
```

**Linux**:

```text
/opt/keyfactor/<gateway-name>/AnyGatewayREST/net10.0/Extensions/
```

Replace `<GatewayName>` (or `<gateway-name>` on Linux) with the gateway you are installing into (e.g. `AcmeGwDns`, `DigiCert`, `Sectigo`).

### 3. Restart the gateway service

Restart the AnyGatewayREST Windows service for the gateway you installed the plugin into so the Extensions folder is rescanned.

## Configuration

After installing the plugin DLL into the gateway's Extensions folder, configure a new DNS Provider entry in the AnyCA Gateway REST UI and select **UltraDNS** as the provider type. See the official Keyfactor AnyCA Gateway REST documentation for the canonical UI walkthrough: **<TBD link from Sarah Duncan>**.

### UltraDNS Setup

Use (or create) an UltraDNS account with permission to manage resource record sets in the zone(s) this plugin will validate against:

1. Log in to the UltraDNS portal, or coordinate with your DigiCert/Vercara account team to obtain API credentials
2. Confirm the account has read/create/delete permission on resource record sets for the target zone(s)

Provide the account's username and password as `UltraDns_Username` and `UltraDns_Password` in the plugin configuration below. The plugin exchanges these for a short-lived OAuth2 access token on each authentication and does not store the password beyond the lifetime of the validator instance.

### Configuration Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `UltraDns_Username` | UltraDNS account username used for OAuth2 password-grant authentication. | Yes | ` ` |
| `UltraDns_Password` | UltraDNS account password used for OAuth2 password-grant authentication. | Yes | ` ` |

### Example Configuration

**Standard configuration:**

```json
{
  "UltraDns_Username": "your-ultradns-username",
  "UltraDns_Password": "your-ultradns-password"
}
```

## Usage

### Automatic Domain Validation

Once configured, the plugin automatically handles DNS validation during certificate enrollment and renewal:

1. **Record Creation**: Plugin creates a DNS TXT record with the validation challenge
2. **Propagation Wait**: Plugin waits for DNS propagation
3. **Verification**: Plugin verifies the record exists on UltraDNS nameservers
4. **Cleanup**: Plugin deletes the validation record after successful validation

### Zone Discovery

The plugin discovers the appropriate UltraDNS zone for a record by querying the UltraDNS API for all zones visible to the account, then matching the record's domain against zone names from most specific (longest) to least specific.

### Testing Connectivity

Test UltraDNS connectivity using `curl` against the API. First obtain an access token:

```bash
curl -s -X POST https://api.ultradns.com/v1/authorization/token \
  -d "grant_type=password&username=$ULTRADNS_USERNAME&password=$ULTRADNS_PASSWORD"
```

Then list zones using the returned `accessToken`:

```bash
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" https://api.ultradns.com/v1/zones
```

## Troubleshooting

### Common Issues

**Authentication Failures**

Symptom: `401 Unauthorized` obtaining a token, or authenticating while listing zones

- Verify the configured username and password are correct and the account is active
- Confirm the account has not been locked out after repeated failed attempts

**Zone Not Found**

Symptom: `No UltraDNS zone found for _acme-challenge.example.com`

- Verify the zone exists and is active in the UltraDNS account
- Confirm the authenticated account has visibility into that zone

**Unverified API behaviors**

This plugin was built primarily from the UltraDNS REST API User Guide and the official Python REST API client, without a live UltraDNS account to validate every detail end-to-end. Two behaviors should be confirmed against a real (non-production-critical) zone before relying on this plugin in production:

- **TXT record value quoting**: whether the `rdata` value should be sent as a plain string or with embedded literal quote characters. Create a test record and confirm with `dig -t TXT` that the published value matches the ACME challenge value exactly.
- **"Already exists" / "not found" error codes**: the plugin currently detects these conditions from the HTTP status code (409/404) with a text fallback on the error message, since the exact UltraDNS error codes for TXT rrsets specifically were not confirmed during development. If the plugin logs an unexpected failure creating a record that already exists, or deleting one that's already gone, check the logged response body for the actual `errorCode` and update `UltraDnsProvider.ResponseIndicatesAlreadyExists` / `ResponseIndicatesNotFound` accordingly.

### Logging

Enable debug logging in the gateway's logging configuration:

```json
{
  "Logging": {
    "LogLevel": {
      "Keyfactor.Extensions.DomainValidator.UltraDns": "Debug"
    }
  }
}
```

### Service Status

Check UltraDNS service status: https://status.ultradns.com/

## Support

The UltraDNS DNS Provider plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com.

### Resources

- [UltraDNS Documentation](https://docs.ultradns.com/)
- [Report Issues](https://github.com/Keyfactor/digicert-ultradns-dnsplugin/issues)
- [Discussions](https://github.com/Keyfactor/digicert-ultradns-dnsplugin/discussions)

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor DNS Provider plugins](https://github.com/orgs/Keyfactor/repositories?q=dnsplugin).
