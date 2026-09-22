using System.Net;
using System.Net.Http;

namespace Keyfactor.Extensions.DomainValidator.UltraDns.Tests
{
    /// <summary>
    /// Routes requests to a caller-supplied responder so UltraDnsProvider can be exercised
    /// end-to-end without touching the real UltraDNS API.
    /// </summary>
    internal class FakeHttpMessageHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();

        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

        public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        {
            _responder = responder;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Real HttpMessageHandlers honor the token before doing any work; matching that here
            // lets tests verify a caller's CancellationToken actually reaches the HTTP layer.
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);

            // Run the responder on a background thread rather than returning an already-completed
            // Task.FromResult(...). A synchronously-completed task lets `await` continue inline on
            // the calling thread with no real suspension -- so a responder that blocks (simulating
            // slow I/O) blocks the CALLER's thread too, and a "fire without awaiting" call in a test
            // doesn't actually run concurrently with the rest of that test method. Task.Run gives
            // tests genuine interleaving to exercise real concurrency (e.g. two calls contending for
            // the same lock).
            return Task.Run(() => _responder(request), cancellationToken);
        }

        public static HttpResponseMessage Json(HttpStatusCode status, string body)
        {
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
            };
        }
    }
}
