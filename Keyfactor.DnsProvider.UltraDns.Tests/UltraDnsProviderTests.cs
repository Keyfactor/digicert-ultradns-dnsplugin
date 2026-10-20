using System.Net;
using Xunit;

namespace Keyfactor.Extensions.DomainValidator.UltraDns.Tests
{
    public class UltraDnsProviderTests
    {
        private const string TokenResponseJson = "{\"accessToken\":\"token-1\",\"refreshToken\":\"refresh-1\",\"expiresIn\":\"3600\"}";
        private const string ZoneListResponseJson =
            "{\"zones\":[{\"properties\":{\"name\":\"example.com.\"}},{\"properties\":{\"name\":\"com.\"}}]," +
            "\"resultInfo\":{\"totalCount\":2,\"returnedCount\":2}}";

        private static UltraDnsProvider CreateProvider(Func<HttpRequestMessage, HttpResponseMessage> responder, out FakeHttpMessageHandler handler)
        {
            handler = new FakeHttpMessageHandler(responder);
            return new UltraDnsProvider("user", "pass", handler);
        }

        [Fact]
        public void Constructor_ThrowsOnEmptyUsername()
        {
            Assert.Throws<ArgumentException>(() => new UltraDnsProvider("", "pass", new FakeHttpMessageHandler(_ => null)));
        }

        [Fact]
        public void Constructor_ThrowsOnEmptyPassword()
        {
            Assert.Throws<ArgumentException>(() => new UltraDnsProvider("user", "", new FakeHttpMessageHandler(_ => null)));
        }

        [Fact]
        public async Task CreateRecordAsync_Success_PostsRrsetToMatchedZone()
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
                if (request.RequestUri.AbsolutePath.Contains("/rrsets/TXT/") && request.Method == HttpMethod.Post)
                {
                    Assert.Contains("example.com./rrsets/TXT/_acme-challenge.example.com.", Uri.UnescapeDataString(request.RequestUri.AbsolutePath));
                    return FakeHttpMessageHandler.Json(HttpStatusCode.Created, "{}");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var result = await provider.CreateRecordAsync("_acme-challenge.example.com", "challenge-value", "TXT");

            Assert.True(result);
        }

        [Fact]
        public async Task CreateRecordAsync_AlreadyExists_FallsBackToPut()
        {
            var putCalled = false;

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
                    return FakeHttpMessageHandler.Json(HttpStatusCode.Conflict, "[{\"errorCode\":2111,\"errorMessage\":\"Resource Record of type TXT and name _acme-challenge.example.com. already exists in the zone example.com.\"}]");
                }
                if (request.Method == HttpMethod.Put)
                {
                    putCalled = true;
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{}");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var result = await provider.CreateRecordAsync("_acme-challenge.example.com", "challenge-value", "TXT");

            Assert.True(result);
            Assert.True(putCalled);
        }

        [Fact]
        public async Task DeleteRecordAsync_Success_ReturnsTrue()
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
            }, out var handler);

            var result = await provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT");

            Assert.True(result);
        }

        [Fact]
        public async Task DeleteRecordAsync_RecordMissing_IsIdempotentSuccess()
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
            }, out var handler);

            var result = await provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT");

            Assert.True(result);
        }

        [Fact]
        public async Task CreateRecordAsync_ZoneNotFound_Throws()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"zones\":[{\"properties\":{\"name\":\"other.com.\"}}],\"resultInfo\":{\"totalCount\":1,\"returnedCount\":1}}");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                provider.CreateRecordAsync("_acme-challenge.example.com", "value", "TXT"));

            Assert.Contains("No UltraDNS zone found", ex.Message);
        }

        [Fact]
        public async Task CreateRecordAsync_AuthenticationFailure_SurfacesLikelyCause()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.Unauthorized, "[{\"errorCode\":0,\"errorMessage\":\"Invalid username or password\"}]");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                provider.CreateRecordAsync("_acme-challenge.example.com", "value", "TXT"));

            Assert.Contains("Verify the configured account username and password", ex.Message);
        }

        [Fact]
        public async Task SendAsync_TokenRejectedMidSession_ReAuthenticatesAndRetries()
        {
            var tokenCallCount = 0;
            var sawUnauthorizedOnce = false;

            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    tokenCallCount++;
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    if (!sawUnauthorizedOnce)
                    {
                        sawUnauthorizedOnce = true;
                        return FakeHttpMessageHandler.Json(HttpStatusCode.Unauthorized, "[{\"errorCode\":60001,\"errorMessage\":\"Invalid or expired token\"}]");
                    }
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var result = await provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT");

            Assert.True(result);
            Assert.Equal(2, tokenCallCount);
        }

        [Fact]
        public async Task FindZoneForRecordAsync_PagesAcrossMultipleResponses()
        {
            var zonePage1 = "{\"zones\":[{\"properties\":{\"name\":\"other.com.\"}}],\"resultInfo\":{\"totalCount\":2,\"returnedCount\":1}}";
            var zonePage2 = "{\"zones\":[{\"properties\":{\"name\":\"example.com.\"}}],\"resultInfo\":{\"totalCount\":2,\"returnedCount\":1}}";
            var zoneRequestCount = 0;

            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    zoneRequestCount++;
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, zoneRequestCount == 1 ? zonePage1 : zonePage2);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var result = await provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT");

            Assert.True(result);
            Assert.Equal(2, zoneRequestCount);
        }

        [Fact]
        public async Task FindZoneForRecordAsync_EmptyZoneList_Throws()
        {
            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, "{\"zones\":[],\"resultInfo\":{\"totalCount\":0,\"returnedCount\":0}}");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                provider.CreateRecordAsync("_acme-challenge.example.com", "value", "TXT"));

            Assert.Contains("empty or invalid zones list", ex.Message);
        }

        [Fact]
        public async Task CreateRecordAsync_UnexpectedFailure_Throws()
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
                    return FakeHttpMessageHandler.Json(HttpStatusCode.InternalServerError, "[{\"errorCode\":9999,\"errorMessage\":\"Unexpected server error\"}]");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                provider.CreateRecordAsync("_acme-challenge.example.com", "value", "TXT"));

            Assert.Contains("500", ex.Message);
        }

        [Fact]
        public async Task DeleteRecordAsync_UnexpectedFailure_Throws()
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
                    return FakeHttpMessageHandler.Json(HttpStatusCode.InternalServerError, "[{\"errorCode\":9999,\"errorMessage\":\"Unexpected server error\"}]");
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT"));

            Assert.Contains("500", ex.Message);
        }

        [Fact]
        public async Task SendAsync_RateLimited_RetriesOnceAfterDelay()
        {
            var zoneRequestCount = 0;

            var provider = CreateProvider(request =>
            {
                if (request.RequestUri.AbsolutePath.EndsWith("authorization/token"))
                {
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, TokenResponseJson);
                }
                if (request.RequestUri.AbsolutePath.Contains("/zones") && request.Method == HttpMethod.Get)
                {
                    zoneRequestCount++;
                    if (zoneRequestCount == 1)
                    {
                        return FakeHttpMessageHandler.Json((HttpStatusCode)429, "[{\"errorCode\":429,\"errorMessage\":\"Too many requests\"}]");
                    }
                    return FakeHttpMessageHandler.Json(HttpStatusCode.OK, ZoneListResponseJson);
                }
                if (request.Method == HttpMethod.Delete)
                {
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                }
                throw new InvalidOperationException($"Unexpected request: {request.Method} {request.RequestUri}");
            }, out var handler);

            var result = await provider.DeleteRecordAsync("_acme-challenge.example.com", "TXT");

            Assert.True(result);
            Assert.Equal(2, zoneRequestCount);
        }

        [Theory]
        [InlineData("example.com", "example.com.")]
        [InlineData("example.com.", "example.com.")]
        public void FullyQualify_AddsTrailingDotOnlyWhenMissing(string input, string expected)
        {
            Assert.Equal(expected, UltraDnsProvider.FullyQualify(input));
        }

        [Fact]
        public void FindBestMatch_PrefersLongestSuffix()
        {
            var zones = new[] { "com", "example.com" };
            var result = UltraDnsProvider.FindBestMatch(zones, "_acme-challenge.www.example.com");
            Assert.Equal("example.com", result);
        }

        [Fact]
        public void FindBestMatch_ReturnsNullWhenNoZoneMatches()
        {
            var zones = new[] { "other.com" };
            var result = UltraDnsProvider.FindBestMatch(zones, "example.com");
            Assert.Null(result);
        }

        [Fact]
        public void StripControlCharacters_RemovesCrLf()
        {
            var result = UltraDnsProvider.StripControlCharacters("example.com\r\nInjected-Header: evil");
            Assert.DoesNotContain("\r", result);
            Assert.DoesNotContain("\n", result);
        }

        [Fact]
        public void ResponseIndicatesAlreadyExists_TrueOnConflictStatus()
        {
            Assert.True(UltraDnsProvider.ResponseIndicatesAlreadyExists(HttpStatusCode.Conflict, "{}"));
        }

        [Fact]
        public void ResponseIndicatesNotFound_TrueOnNotFoundStatus()
        {
            Assert.True(UltraDnsProvider.ResponseIndicatesNotFound(HttpStatusCode.NotFound, "{}"));
        }
    }
}
