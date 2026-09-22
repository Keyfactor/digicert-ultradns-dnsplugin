// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.DomainValidator.UltraDns
{
    internal class UltraDnsProvider
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<UltraDnsProvider>();

        // Bounds any UltraDNS zone-list pagination loop against a malformed/cyclic offset (API bug
        // or future change) so a broken pagination response can't hang StageValidation/
        // CleanupValidation forever. 5,000 pages at 1,000/page is 5,000,000 zones -- far beyond any
        // realistic account's zone count.
        private const int MaxPaginationPages = 5000;

        // UltraDNS access tokens are valid for up to ~1 hour per the REST API User Guide, which
        // recommends caching and reusing them rather than re-authenticating on every call. Refreshing
        // 60 seconds early avoids a request racing the exact expiry instant.
        private const int TokenExpiryBufferSeconds = 60;

        private readonly HttpClient _httpClient;
        private readonly string _username;
        private readonly string _password;

        // Guards _accessToken/_accessTokenExpiresAt so two concurrent calls (for different keys,
        // which DomainValidator allows to run in parallel) don't both decide the token is expired
        // and both re-authenticate at once. Never held across the outer HTTP call in SendAsync,
        // only around the authenticate-and-cache step itself.
        private readonly SemaphoreSlim _authLock = new(1, 1);
        private string _accessToken;
        private DateTimeOffset _accessTokenExpiresAt = DateTimeOffset.MinValue;

        private class TokenResponse
        {
            [JsonPropertyName("accessToken")]
            public string AccessToken { get; set; }

            [JsonPropertyName("expiresIn")]
            public int ExpiresIn { get; set; }
        }

        private class ZonePropertiesData
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }
        }

        private class ZoneData
        {
            [JsonPropertyName("properties")]
            public ZonePropertiesData Properties { get; set; }
        }

        private class ResultInfoData
        {
            [JsonPropertyName("totalCount")]
            public int TotalCount { get; set; }

            [JsonPropertyName("returnedCount")]
            public int ReturnedCount { get; set; }
        }

        // NOTE: the "zones" wrapper key and resultInfo shape mirror the documented RRSet list
        // response (rrsets/queryInfo/resultInfo) by analogy with the UltraDNS REST API's consistent
        // response conventions -- this specific wrapper was not found spelled out verbatim in the
        // REST API User Guide's zone-listing section during research. Verify against a live call
        // before relying on this in production; see docsource/configuration.md Troubleshooting.
        private class ZoneListResponse
        {
            [JsonPropertyName("zones")]
            public ZoneData[] Zones { get; set; }

            [JsonPropertyName("resultInfo")]
            public ResultInfoData ResultInfo { get; set; }
        }

        public UltraDnsProvider(string username, string password)
            : this(username, password, new HttpClientHandler())
        {
        }

        // Internal constructor to allow unit tests to inject a fake HttpMessageHandler.
        internal UltraDnsProvider(string username, string password, HttpMessageHandler handler)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("username must not be empty", nameof(username));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("password must not be empty", nameof(password));
            }

            _username = username;
            _password = password;

            _httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri("https://api.ultradns.com/v1/"),
                // UltraDnsDomainValidator holds a per-key lock across the entire Stage/Cleanup call,
                // including every HTTP request this class makes -- without an explicit bound, a
                // single stalled UltraDNS connection falls back to HttpClient's 100-second default,
                // and a Create/Delete can make 2-3 sequential requests (auth + zone list + rrset
                // call), so an unrelated legitimate operation for the SAME key could queue behind a
                // hung one for several minutes. 30 seconds is generous for a DNS record CRUD call
                // under normal conditions.
                Timeout = TimeSpan.FromSeconds(30)
            };

            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<bool> CreateRecordAsync(string recordName, string value, string recordType, CancellationToken cancellationToken = default)
        {
            recordName = StripControlCharacters(recordName);
            _logger.LogDebug("Creating {RecordType} record for {RecordName}", recordType, recordName);

            var zone = await FindZoneForRecordAsync(recordName, cancellationToken);
            var ownerName = FullyQualify(recordName);
            var uri = $"zones/{Uri.EscapeDataString(zone)}/rrsets/{recordType}/{Uri.EscapeDataString(ownerName)}";

            // rdata is sent unquoted here (a plain string, not a JSON string containing literal
            // quote characters). The REST API User Guide's own examples are inconsistent on this
            // point for TXT/SPF records -- see docsource/configuration.md Troubleshooting for the
            // recommended live verification (create a record, then `dig -t TXT` it) before shipping.
            var payload = new { ttl = 300, rdata = new[] { value } };
            var json = JsonSerializer.Serialize(payload);

            var response = await SendAsync(HttpMethod.Post, uri, () => new StringContent(json, Encoding.UTF8, "application/json"), cancellationToken);
            var body = StripControlCharacters(await response.Content.ReadAsStringAsync(cancellationToken));

            if (ResponseIndicatesAlreadyExists(response.StatusCode, body))
            {
                // The rrset already exists for this owner/type (e.g. a retried challenge) --
                // replace its rdata instead of failing. Idempotent upsert, not a distinct record.
                _logger.LogDebug("{RecordType} record '{OwnerName}' already exists in zone '{Zone}'; replacing rdata", recordType, ownerName, zone);
                response = await SendAsync(HttpMethod.Put, uri, () => new StringContent(json, Encoding.UTF8, "application/json"), cancellationToken);
                body = StripControlCharacters(await response.Content.ReadAsStringAsync(cancellationToken));
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError(
                    "UltraDNS API rejected creation of {RecordType} record '{OwnerName}' in zone '{Zone}'. Status: {StatusCode}. Response: {Response}",
                    recordType, ownerName, zone, (int)response.StatusCode, body);

                throw new InvalidOperationException(
                    $"UltraDNS API returned {(int)response.StatusCode} ({response.StatusCode}) creating {recordType} record '{ownerName}' in zone '{zone}': {body}");
            }

            _logger.LogInformation("Created {RecordType} record '{OwnerName}' in UltraDNS zone '{Zone}'", recordType, ownerName, zone);
            return true;
        }

        public async Task<bool> DeleteRecordAsync(string recordName, string recordType, CancellationToken cancellationToken = default)
        {
            recordName = StripControlCharacters(recordName);
            _logger.LogDebug("Deleting {RecordType} record for {RecordName}", recordType, recordName);

            var zone = await FindZoneForRecordAsync(recordName, cancellationToken);
            var ownerName = FullyQualify(recordName);
            var uri = $"zones/{Uri.EscapeDataString(zone)}/rrsets/{recordType}/{Uri.EscapeDataString(ownerName)}";

            var response = await SendAsync(HttpMethod.Delete, uri, contentFactory: null, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NoContent || response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Deleted {RecordType} record '{OwnerName}' in UltraDNS zone '{Zone}'", recordType, ownerName, zone);
                return true;
            }

            var body = StripControlCharacters(await response.Content.ReadAsStringAsync(cancellationToken));

            if (ResponseIndicatesNotFound(response.StatusCode, body))
            {
                // Nothing to clean up -- treat as success so cleanup is idempotent.
                _logger.LogInformation(
                    "No {RecordType} record '{OwnerName}' found in zone '{Zone}' to delete; treating cleanup as complete",
                    recordType, ownerName, zone);
                return true;
            }

            _logger.LogError(
                "UltraDNS API rejected deletion of {RecordType} record '{OwnerName}' in zone '{Zone}'. Status: {StatusCode}. Response: {Response}",
                recordType, ownerName, zone, (int)response.StatusCode, body);

            throw new InvalidOperationException(
                $"UltraDNS API returned {(int)response.StatusCode} ({response.StatusCode}) deleting {recordType} record '{ownerName}' in zone '{zone}': {body}");
        }

        /// <summary>
        /// Fetches all zones visible to the authenticated user, paging via offset/limit, and
        /// resolves the zone that owns the given record by longest matching name suffix, e.g. for
        /// "_acme-challenge.www.example.com" it prefers "example.com" over "com".
        /// </summary>
        private async Task<string> FindZoneForRecordAsync(string recordName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(recordName))
            {
                throw new ArgumentException("Record name must not be empty", nameof(recordName));
            }

            var zoneNames = new List<string>();
            var offset = 0;
            const int limit = 1000;
            var pageCount = 0;

            while (true)
            {
                pageCount++;
                if (pageCount > MaxPaginationPages)
                {
                    throw new InvalidOperationException(
                        $"UltraDNS zone list pagination exceeded {MaxPaginationPages} pages without terminating; aborting.");
                }

                var response = await SendAsync(HttpMethod.Get, $"zones?offset={offset}&limit={limit}", contentFactory: null, cancellationToken);
                var body = StripControlCharacters(await response.Content.ReadAsStringAsync(cancellationToken));

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError(
                        "UltraDNS zone list request failed. Status: {StatusCode}. Response: {Response}. " +
                        "This usually means the account username or password is invalid.",
                        (int)response.StatusCode, body);

                    throw new InvalidOperationException(
                        $"UltraDNS API returned {(int)response.StatusCode} ({response.StatusCode}) while listing zones: {body}. " +
                        "Verify the configured account username and password.");
                }

                var page = JsonSerializer.Deserialize<ZoneListResponse>(body);
                var zones = page?.Zones ?? Array.Empty<ZoneData>();
                zoneNames.AddRange(zones.Where(z => z.Properties?.Name != null).Select(z => z.Properties.Name));

                var returnedCount = page?.ResultInfo?.ReturnedCount ?? zones.Length;
                // When resultInfo is missing/malformed, there's no reliable signal that another
                // page exists -- assume this page is the last one (totalCount = offset just after
                // this page) rather than comparing against zoneNames.Count, which already includes
                // this page's entries and would make offset >= totalCount trivially true after
                // page 1 even when the real API (via a present resultInfo) has more pages to give.
                var totalCount = page?.ResultInfo?.TotalCount ?? (offset + returnedCount);
                offset += returnedCount;

                if (returnedCount <= 0 || offset >= totalCount)
                {
                    break;
                }
            }

            if (zoneNames.Count == 0)
            {
                throw new InvalidOperationException("UltraDNS returned an empty or invalid zones list. Aborting.");
            }

            var match = FindBestMatch(zoneNames.Select(z => z.TrimEnd('.')), recordName.TrimEnd('.'));

            if (match == null)
            {
                throw new InvalidOperationException(
                    $"No UltraDNS zone found for record '{recordName}'. Ensure the zone exists in this UltraDNS account.");
            }

            // Return the zone name as UltraDNS returned it (fully qualified, trailing dot) so it can
            // be used directly in the rrsets URI.
            return zoneNames.First(z => z.TrimEnd('.').Equals(match, StringComparison.OrdinalIgnoreCase));
        }

        private async Task AuthenticateAsync(CancellationToken cancellationToken)
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = _username,
                ["password"] = _password
            });

            var response = await _httpClient.PostAsync("authorization/token", form, cancellationToken);
            var body = StripControlCharacters(await response.Content.ReadAsStringAsync(cancellationToken));

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError(
                    "UltraDNS authentication failed. Status: {StatusCode}. Response: {Response}. " +
                    "This usually means the account username or password is invalid.",
                    (int)response.StatusCode, body);

                throw new InvalidOperationException(
                    $"UltraDNS API returned {(int)response.StatusCode} ({response.StatusCode}) authenticating: {body}. " +
                    "Verify the configured account username and password.");
            }

            var token = JsonSerializer.Deserialize<TokenResponse>(body);

            if (string.IsNullOrEmpty(token?.AccessToken))
            {
                throw new InvalidOperationException("UltraDNS authentication response did not include an access token.");
            }

            _accessToken = token.AccessToken;
            var expiresIn = Math.Max(token.ExpiresIn - TokenExpiryBufferSeconds, 30);
            _accessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
        }

        private async Task EnsureAuthenticatedAsync(CancellationToken cancellationToken)
        {
            if (_accessToken != null && DateTimeOffset.UtcNow < _accessTokenExpiresAt)
            {
                return;
            }

            await _authLock.WaitAsync(cancellationToken);
            try
            {
                if (_accessToken != null && DateTimeOffset.UtcNow < _accessTokenExpiresAt)
                {
                    return;
                }

                await AuthenticateAsync(cancellationToken);
            }
            finally
            {
                _authLock.Release();
            }
        }

        // contentFactory produces a fresh HttpContent per attempt (rather than accepting a single
        // HttpContent instance) because HttpRequestMessage takes ownership of its Content and
        // disposes it after the request completes -- reusing the same instance across a 401/429
        // retry would throw ObjectDisposedException on the second send.
        private async Task<HttpResponseMessage> SendAsync(
            HttpMethod method,
            string uri,
            Func<HttpContent> contentFactory,
            CancellationToken cancellationToken,
            bool isRetry = false)
        {
            await EnsureAuthenticatedAsync(cancellationToken);

            var request = new HttpRequestMessage(method, uri);
            if (contentFactory != null)
            {
                request.Content = contentFactory();
            }
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

            var response = await _httpClient.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized && !isRetry)
            {
                // The cached access token was rejected (expired or revoked server-side before our
                // local expiry estimate) -- force a fresh authentication and retry exactly once.
                await _authLock.WaitAsync(cancellationToken);
                try
                {
                    _accessToken = null;
                    _accessTokenExpiresAt = DateTimeOffset.MinValue;
                }
                finally
                {
                    _authLock.Release();
                }

                return await SendAsync(method, uri, contentFactory, cancellationToken, isRetry: true);
            }

            if (response.StatusCode == (HttpStatusCode)429 && !isRetry)
            {
                // Per the REST API User Guide, back off briefly and retry once on rate limiting.
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                return await SendAsync(method, uri, contentFactory, cancellationToken, isRetry: true);
            }

            return response;
        }

        /// <summary>
        /// The exact UltraDNS error code for "rrset already exists" was not confirmed against a
        /// live account during research (the REST API User Guide's examples for this case cover
        /// other record types, not TXT) -- this checks the conventional HTTP 409 status plus a
        /// text fallback on the error message. Verify against a live create-twice call before
        /// relying on this in production.
        /// </summary>
        internal static bool ResponseIndicatesAlreadyExists(HttpStatusCode status, string body)
        {
            return status == HttpStatusCode.Conflict ||
                   (body != null && body.Contains("already exists", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// The exact UltraDNS error code for "rrset not found" was not confirmed against a live
        /// account during research -- this checks the conventional HTTP 404 status plus a text
        /// fallback on the error message ("not found" / "does not exist"). Verify against a live
        /// delete-of-a-missing-record call before relying on this in production.
        /// </summary>
        internal static bool ResponseIndicatesNotFound(HttpStatusCode status, string body)
        {
            return status == HttpStatusCode.NotFound ||
                   (body != null &&
                    (body.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
                     body.Contains("does not exist", StringComparison.OrdinalIgnoreCase)));
        }

        /// <summary>
        /// Returns recordName as a fully-qualified, trailing-dot owner name, e.g. "example.com" or
        /// "example.com." both become "example.com.". UltraDNS treats a trailing dot as an absolute
        /// owner name, avoiding any ambiguity in how it would otherwise resolve a relative name
        /// against the zone.
        /// </summary>
        internal static string FullyQualify(string recordName)
        {
            return recordName.EndsWith(".", StringComparison.Ordinal) ? recordName : recordName + ".";
        }

        /// <summary>
        /// Strips control characters (including CR/LF) from a gateway-supplied record name before
        /// it can reach any log message or exception text. A legitimate hostname never contains
        /// these characters, so this only affects malformed/malicious input -- it prevents an
        /// unvalidated record name from forging log lines (CWE-117) via embedded CRLF.
        /// </summary>
        internal static string StripControlCharacters(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            return new string(value.Where(c => !char.IsControl(c)).ToArray());
        }

        /// <summary>
        /// Finds the zone whose name is the longest suffix match of the target domain, e.g. for
        /// domain "_acme-challenge.www.example.com" and zones {"example.com", "com"}, "example.com"
        /// wins because it's the more specific (longer) match.
        /// </summary>
        internal static string FindBestMatch(IEnumerable<string> zones, string domain)
        {
            string best = null;
            foreach (var zone in zones)
            {
                var isMatch = domain.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                              domain.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);

                if (isMatch && (best == null || zone.Length > best.Length))
                {
                    best = zone;
                }
            }
            return best;
        }
    }
}
