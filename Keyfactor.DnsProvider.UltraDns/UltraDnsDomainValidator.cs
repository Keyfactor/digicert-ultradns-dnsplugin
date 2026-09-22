// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.DomainValidator.UltraDns
{
    /// <summary>
    /// UltraDNS domain validator for ACME DNS-01 challenges. Publishes TXT records in
    /// UltraDNS-hosted zones. Authenticates via an UltraDNS account username and password
    /// (OAuth2 password grant).
    /// </summary>
    public class UltraDnsDomainValidator : IDomainValidator
    {
        private static readonly ILogger _logger = LogHandler.GetClassLogger<UltraDnsDomainValidator>();

        private const string ValidationTypeName = "dns-01";
        private const string RecordTypeName = "TXT";

        private UltraDnsProvider _provider;
        private Dictionary<string, object> _configuration;

        // Tracks the value staged for each key so CleanupValidation can disambiguate between
        // multiple TXT records sharing the same name (e.g. an apex + wildcard SAN both challenging
        // at the same _acme-challenge FQDN). CleanupValidation's own signature (key only, no value)
        // can't tell us which record to delete, so this queue records staging order per key on a
        // best-effort FIFO basis: cleanup for a key removes the oldest still-pending value staged
        // for it. Keyed case-insensitively since DNS names are inherently case-insensitive.
        private readonly Dictionary<string, Queue<string>> _stagedValues = new(StringComparer.OrdinalIgnoreCase);

        // Serializes ALL Stage/Cleanup calls for the SAME key end-to-end, including the network
        // round-trip -- not just the queue peek/dequeue. Different keys still run fully in
        // parallel; only same-key operations are serialized. Guarded by `_locksLock`, a separate,
        // short-lived lock used only to get-or-create a key's semaphore -- never held across an
        // await.
        //
        // Neither this dictionary nor `_stagedValues` ever evicts an entry, so both grow for the
        // life of the validator instance, one entry per distinct FQDN ever staged/cleaned up.
        // Accepted: per-entry cost is small, a validator instance's lifetime is bounded by the
        // hosting gateway process, and `key` values are domain names from certificates this account
        // is actually enrolling, not attacker-supplied input from an untrusted boundary.
        private readonly Dictionary<string, SemaphoreSlim> _keyLocks = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _locksLock = new();

        public UltraDnsDomainValidator()
        {
        }

        // Internal constructor to allow unit tests to inject a fake provider without going through
        // Initialize (which requires a real IDomainValidatorConfigProvider and constructs its own
        // UltraDnsProvider from config-supplied credentials).
        internal UltraDnsDomainValidator(UltraDnsProvider provider)
        {
            _provider = provider;
        }

        public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>()
            {
                ["UltraDns_Username"] = new PropertyConfigInfo()
                {
                    Comments = "UltraDNS account username (Required)",
                    Hidden = false,
                    DefaultValue = "",
                    Type = "String"
                },
                ["UltraDns_Password"] = new PropertyConfigInfo()
                {
                    Comments = "UltraDNS account password (Required)",
                    Hidden = true,
                    DefaultValue = "",
                    Type = "Secret"
                }
            };
        }

        public string GetValidationType() => ValidationTypeName;

        public void Initialize(IDomainValidatorConfigProvider configProvider)
        {
            _configuration = configProvider.DomainValidationConfiguration;

            var username = GetConfigValue("UltraDns_Username");
            var password = GetConfigValue("UltraDns_Password");

            if (string.IsNullOrWhiteSpace(username))
            {
                _logger.LogWarning("UltraDns_Username is missing or empty; plugin initialization cannot proceed");
                throw new ArgumentException("UltraDns_Username is required");
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                _logger.LogWarning("UltraDns_Password is missing or empty; plugin initialization cannot proceed");
                throw new ArgumentException("UltraDns_Password is required");
            }

            _provider = new UltraDnsProvider(username, password);
        }

        public async Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            SemaphoreSlim keyLock = null;
            var lockAcquired = false;
            try
            {
                keyLock = GetKeyLock(key);
                await keyLock.WaitAsync(cancellationToken);
                lockAcquired = true;

                var success = await _provider.CreateRecordAsync(key, value, RecordTypeName, cancellationToken);

                if (success)
                {
                    GetQueue(key, createIfMissing: true).Enqueue(value);
                }

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to create DNS {RecordTypeName} record for {SafeForLog(key)}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UltraDNS StageValidation failed for {RecordType} record '{Key}'", RecordTypeName, SafeForLog(key));
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to create {RecordTypeName} record for {SafeForLog(key)}: {ex.Message}"
                };
            }
            finally
            {
                if (lockAcquired)
                {
                    keyLock.Release();
                }
            }
        }

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            SemaphoreSlim keyLock = null;
            var lockAcquired = false;
            try
            {
                keyLock = GetKeyLock(key);
                await keyLock.WaitAsync(cancellationToken);
                lockAcquired = true;

                // Peek (don't remove) the oldest still-pending staged value. It is only actually
                // dequeued below once DeleteRecordAsync confirms success -- removing it up front
                // would permanently lose it if the delete failed/was retried, corrupting the queue
                // for any later retry or sibling cleanup call on this key.
                var queue = GetQueue(key, createIfMissing: false);
                var outstandingCount = queue?.Count ?? 0;

                if (outstandingCount > 1)
                {
                    // CleanupValidation's own contract gives us no challenge value to match against
                    // (only `key`), and UltraDNS's rrset API is keyed by owner name + type only (no
                    // per-value delete) -- when more than one value is outstanding for the same key
                    // (e.g. an apex + wildcard SAN sharing one _acme-challenge FQDN), a single
                    // delete call removes the whole rrset regardless of which value this specific
                    // cleanup call was for. Surfaced here so it's operationally visible rather than
                    // a silent, unverifiable assumption.
                    _logger.LogWarning(
                        "{Count} {RecordType} values are still staged for '{Key}'; UltraDNS deletes the entire rrset for this owner, so this cleanup call will remove all of them",
                        outstandingCount, RecordTypeName, SafeForLog(key));
                }

                var success = await _provider.DeleteRecordAsync(key, RecordTypeName, cancellationToken);

                if (success && outstandingCount > 0)
                {
                    queue.Dequeue();
                }

                return new DomainValidationResult
                {
                    Success = success,
                    ErrorMessage = success ? null : $"Failed to delete DNS {RecordTypeName} record for {SafeForLog(key)}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UltraDNS CleanupValidation failed for {RecordType} record '{Key}'", RecordTypeName, SafeForLog(key));
                return new DomainValidationResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to delete {RecordTypeName} record for {SafeForLog(key)}: {ex.Message}"
                };
            }
            finally
            {
                if (lockAcquired)
                {
                    keyLock.Release();
                }
            }
        }

        public async Task ValidateConfiguration(Dictionary<string, object> configuration)
        {
            _configuration = configuration;

            var username = GetConfigValue("UltraDns_Username");
            if (string.IsNullOrWhiteSpace(username))
            {
                _logger.LogWarning("UltraDns_Username is missing or empty; configuration validation failed");
                throw new ArgumentException("UltraDns_Username is required");
            }

            var password = GetConfigValue("UltraDns_Password");
            if (string.IsNullOrWhiteSpace(password))
            {
                _logger.LogWarning("UltraDns_Password is missing or empty; configuration validation failed");
                throw new ArgumentException("UltraDns_Password is required");
            }

            await Task.CompletedTask;
        }

        private string GetConfigValue(string key)
        {
            if (_configuration != null && _configuration.TryGetValue(key, out var value))
            {
                return value?.ToString() ?? string.Empty;
            }
            return string.Empty;
        }

        // UltraDnsProvider sanitizes recordName before using it in ITS OWN log/exception messages,
        // but that sanitized copy never crosses back into this class's `key` parameter (strings are
        // immutable/passed by value) -- this class has its own independent log and ErrorMessage
        // call sites that log/embed the raw `key`, so it needs its own sanitization pass to close
        // the same CWE-117 CRLF log-forging gap at this layer.
        private static string SafeForLog(string key) => UltraDnsProvider.StripControlCharacters(key);

        private SemaphoreSlim GetKeyLock(string key)
        {
            lock (_locksLock)
            {
                if (!_keyLocks.TryGetValue(key, out var keyLock))
                {
                    keyLock = new SemaphoreSlim(1, 1);
                    _keyLocks[key] = keyLock;
                }
                return keyLock;
            }
        }

        // Only ever called while holding that key's semaphore (see GetKeyLock), so the returned
        // Queue<string> is never accessed by more than one caller at a time and needs no further
        // locking around Enqueue/Peek/Dequeue -- only the lookup/creation in the shared dictionary
        // itself needs the brief `_locksLock` (reused here rather than adding a third lock, since it
        // is already the lock guarding shared-dictionary structural changes for this class).
        private Queue<string> GetQueue(string key, bool createIfMissing)
        {
            lock (_locksLock)
            {
                if (_stagedValues.TryGetValue(key, out var queue))
                {
                    return queue;
                }
                if (!createIfMissing)
                {
                    return null;
                }
                queue = new Queue<string>();
                _stagedValues[key] = queue;
                return queue;
            }
        }
    }
}
