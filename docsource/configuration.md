### Provider Setup

Use (or create) an UltraDNS account with permission to manage resource record sets in the zone(s) this plugin will validate against:

1. Log in to the UltraDNS portal, or coordinate with your DigiCert/Vercara account team to obtain API credentials
2. Confirm the account has read/create/delete permission on resource record sets for the target zone(s)

Provide the account's username and password as `UltraDns_Username` and `UltraDns_Password` in the plugin configuration below. The plugin exchanges these for a short-lived OAuth2 access token on each authentication and does not store the password beyond the lifetime of the validator instance.

### Example Configurations

**Standard configuration:**

```json
{
  "UltraDns_Username": "your-ultradns-username",
  "UltraDns_Password": "your-ultradns-password"
}
```

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

### Troubleshooting

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
