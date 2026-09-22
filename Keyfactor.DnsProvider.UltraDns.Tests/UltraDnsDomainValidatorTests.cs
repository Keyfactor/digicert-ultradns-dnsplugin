using System.Net;
using Keyfactor.AnyGateway.Extensions;
using Xunit;

namespace Keyfactor.Extensions.DomainValidator.UltraDns.Tests
{
    public class UltraDnsDomainValidatorTests
    {
        private const string TokenResponseJson = "{\"accessToken\":\"token-1\",\"refreshToken\":\"refresh-1\",\"expiresIn\":3600}";
        private const string ZoneListResponseJson =
            "{\"zones\":[{\"properties\":{\"name\":\"example.com.\"}}],\"resultInfo\":{\"totalCount\":1,\"returnedCount\":1}}";

        private class FakeConfigProvider : IDomainValidatorConfigProvider
        {
            public Dictionary<string, object> DomainValidationConfiguration { get; set; } = new();
        }

        private static UltraDnsProvider CreateProvider(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            return new UltraDnsProvider("user", "pass", new FakeHttpMessageHandler(responder));
        }

        [Fact]
        public void GetDomainValidatorAnnotations_DeclaresUsernameAndSecretPassword()
        {
            var validator = new UltraDnsDomainValidator();
            var annotations = validator.GetDomainValidatorAnnotations();

            Assert.True(annotations.ContainsKey("UltraDns_Username"));
            Assert.True(annotations.ContainsKey("UltraDns_Password"));
            Assert.Equal("Secret", annotations["UltraDns_Password"].Type);
            Assert.True(annotations["UltraDns_Password"].Hidden);
        }

        [Fact]
        public void GetValidationType_ReturnsDns01()
        {
            var validator = new UltraDnsDomainValidator();
            Assert.Equal("dns-01", validator.GetValidationType());
        }

        [Fact]
        public void Initialize_ThrowsWhenUsernameMissing()
        {
            var validator = new UltraDnsDomainValidator();
            var config = new FakeConfigProvider
            {
                DomainValidationConfiguration = new Dictionary<string, object> { ["UltraDns_Password"] = "pass" }
            };

            Assert.Throws<ArgumentException>(() => validator.Initialize(config));
        }

        [Fact]
        public void Initialize_ThrowsWhenPasswordMissing()
        {
            var validator = new UltraDnsDomainValidator();
            var config = new FakeConfigProvider
            {
                DomainValidationConfiguration = new Dictionary<string, object> { ["UltraDns_Username"] = "user" }
            };

            Assert.Throws<ArgumentException>(() => validator.Initialize(config));
        }

        [Fact]
        public async Task ValidateConfiguration_ThrowsWhenPasswordMissing()
        {
            var validator = new UltraDnsDomainValidator();
            var config = new Dictionary<string, object> { ["UltraDns_Username"] = "user" };

            await Assert.ThrowsAsync<ArgumentException>(() => validator.ValidateConfiguration(config));
        }

        [Fact]
        public async Task StageValidation_Success_ReturnsSuccessResult()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Post)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.Created, "{}");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            });

            var validator = new UltraDnsDomainValidator(provider);
            var result = await validator.StageValidation("_acme-challenge.example.com", "challenge-value", CancellationToken.None);

            Assert.True(result.Success);
            Assert.Null(result.ErrorMessage);
        }

        [Fact]
        public async Task StageValidation_ProviderThrows_ReturnsFailureResultWithoutThrowing()
        {
            var provider = CreateProvider(request =>
                FakeHttpMessageHandler.Json(HttpStatusCode.Unauthorized, "[{\"errorCode\":0,\"errorMessage\":\"bad creds\"}]"));

            var validator = new UltraDnsDomainValidator(provider);
            var result = await validator.StageValidation("_acme-challenge.example.com", "challenge-value", CancellationToken.None);

            Assert.False(result.Success);
            Assert.NotNull(result.ErrorMessage);
        }

        [Fact]
        public async Task CleanupValidation_Success_ReturnsSuccessResult()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            });

            var validator = new UltraDnsDomainValidator(provider);
            var result = await validator.CleanupValidation("_acme-challenge.example.com", CancellationToken.None);

            Assert.True(result.Success);
        }

        [Fact]
        public async Task CleanupValidation_RecordAlreadyGone_IsIdempotentSuccess()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.NotFound, "[{\"errorCode\":70002,\"errorMessage\":\"Data not found.\"}]");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            });

            var validator = new UltraDnsDomainValidator(provider);
            var result = await validator.CleanupValidation("_acme-challenge.example.com", CancellationToken.None);

            Assert.True(result.Success);
        }

        [Fact]
        public async Task StageThenCleanup_SameKey_RunsSerializedWithoutDeadlock()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Post)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.Created, "{}");
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            });

            var validator = new UltraDnsDomainValidator(provider);
            var stageResult = await validator.StageValidation("_acme-challenge.example.com", "value-1", CancellationToken.None);
            var cleanupResult = await validator.CleanupValidation("_acme-challenge.example.com", CancellationToken.None);

            Assert.True(stageResult.Success);
            Assert.True(cleanupResult.Success);
        }
    }
}
