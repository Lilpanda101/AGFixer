#Requires -Version 5.1
function Test-AGTls13 {
    [CmdletBinding()]
    param(
        [ValidateRange(100,60000)][int]$TimeoutMs = 5000,
        [System.Net.IPAddress]$ConnectAddress,
        [uri]$ProxyUri,
        [switch]$AllowTls12
    )
    if ($ProxyUri -and $ConnectAddress) { throw 'ProxyUri и ConnectAddress взаимоисключающие: прокси должен получить исходное имя назначения.' }
    if ($ProxyUri -and ($ProxyUri.Scheme -notin @('http','socks5') -or -not $ProxyUri.Host -or $ProxyUri.Port -lt 1 -or $ProxyUri.UserInfo -or $ProxyUri.Query -or $ProxyUri.Fragment -or $ProxyUri.AbsolutePath -notin @('','/'))) {
        throw 'Нужен http://host:port или socks5://host:port без логина, пароля, пути и query. Используйте локальный прокси Unlocker; credentials сюда не передаются.'
    }
    if (-not ('AGOptimizer.CommunityTlsProbe' -as [type])) {
        Add-Type -TypeDefinition @'
﻿using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AGOptimizer {
    public sealed class CommunityTlsResult {
        public bool Success { get; set; }
        public string Status { get; set; }
        public string FailedStage { get; set; }
        public string FailureKind { get; set; }
        public int RequestedProtocols { get; set; }
        public string DnsStatus { get; set; }
        public string TcpStatus { get; set; }
        public string ProxyStatus { get; set; }
        public string TlsStatus { get; set; }
        public string Sni { get; set; }
        public string Path { get; set; }
        public string RemoteEndpoint { get; set; }
        public string ConnectedAddress { get; set; }
        public string ConnectedEndpointRole { get; set; }
        public string ResolutionTarget { get; set; }
        public string[] ResolvedAddresses { get; set; }
        public string[] DestinationAddresses { get; set; }
        public string Protocol { get; set; }
        public string CipherSuite { get; set; }
        public double DnsMs { get; set; }
        public double TcpConnectMs { get; set; }
        public double ProxyNegotiationMs { get; set; }
        public double TlsHandshakeMs { get; set; }
        public bool IsTls13 { get; set; }
        public string Note { get; set; }
    }
    public sealed class CommunityTlsException : InvalidOperationException {
        public CommunityTlsResult Result { get; private set; }
        public CommunityTlsException(CommunityTlsResult result, Exception inner)
            : base(result.FailedStage + " failed: " + result.FailureKind + ".", inner) { Result = result; }
    }
    public static class CommunityTlsProbe {
        private const string Host = "daily-cloudcode-pa.googleapis.com";
        private static int pendingOperations;
        public static int PendingOperations { get { return Volatile.Read(ref pendingOperations); } }

        private static SslProtocols GetProtocols(bool allowTls12) {
            return allowTls12 ? SslProtocols.Tls12 | (SslProtocols)12288 : (SslProtocols)12288;
        }

        private static string UnsupportedKind(Exception error) {
            if (error is ArgumentException || error is NotSupportedException) return "RuntimeUnsupported";
            var native = error as System.ComponentModel.Win32Exception;
            if (native != null && native.NativeErrorCode == unchecked((int)0x80090302)) return "RuntimeUnsupported";
            return error.InnerException == null ? null : UnsupportedKind(error.InnerException);
        }

        private static void Observe(Task task) {
            Interlocked.Increment(ref pendingOperations);
            task.ContinueWith(completed => {
                if (completed.IsFaulted) { var observed = completed.Exception; }
                Interlocked.Decrement(ref pendingOperations);
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }

        private static async Task WithTimeout(Task task, int timeoutMs, CancellationToken token) {
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                var delayTask = Task.Delay(timeoutMs, cts.Token);
                try {
                    var completed = await Task.WhenAny(task, delayTask).ConfigureAwait(false);
                    if (completed == delayTask) {
                        Observe(task);
                        token.ThrowIfCancellationRequested();
                        throw new TimeoutException("The operation has timed out.");
                    }
                    await task.ConfigureAwait(false);
                } finally {
                    cts.Cancel();
                }
            }
        }

        private static async Task<T> WithTimeout<T>(Task<T> task, int timeoutMs, CancellationToken token) {
            await WithTimeout((Task)task, timeoutMs, token).ConfigureAwait(false);
            return await task.ConfigureAwait(false);
        }

        private static Task<IPAddress[]> Resolve(Task<IPAddress[]> task, int timeoutMs, CancellationToken token) {
            return WithTimeout(task, timeoutMs, token);
        }

        private static async Task Connect(TcpClient tcp, Task task, int timeoutMs, CancellationToken token) {
            try { await WithTimeout(task, timeoutMs, token).ConfigureAwait(false); }
            catch { tcp.Close(); throw; }
        }

        private static async Task Authenticate(SslStream tls, int timeoutMs, bool allowTls12, CancellationToken token) {
            try {
                await WithTimeout(tls.AuthenticateAsClientAsync(Host, null, GetProtocols(allowTls12), true), timeoutMs, token).ConfigureAwait(false);
                if (!tls.IsAuthenticated || !tls.IsEncrypted ||
                    (!allowTls12 && (int)tls.SslProtocol != 12288) ||
                    (allowTls12 && tls.SslProtocol != SslProtocols.Tls12 && (int)tls.SslProtocol != 12288))
                    throw new AuthenticationException("Requested TLS protocol was not authenticated and encrypted.");
            } catch { tls.Dispose(); throw; }
        }

        private static async Task<byte[]> ReadExactly(Stream stream, int count, CancellationToken token, int timeoutMs) {
            byte[] buffer = new byte[count]; int offset = 0;
            while (offset < count) {
                var readTask = stream.ReadAsync(buffer, offset, count - offset, token);
                int n = await WithTimeout(readTask, timeoutMs, token).ConfigureAwait(false);
                if (n == 0) throw new IOException("Proxy closed the connection.");
                offset += n;
            }
            return buffer;
        }

        private static async Task HttpConnect(Stream stream, CancellationToken token, int timeoutMs) {
            byte[] request = Encoding.ASCII.GetBytes("CONNECT " + Host + ":443 HTTP/1.1\r\nHost: " + Host + ":443\r\n\r\n");
            var writeTask = stream.WriteAsync(request, 0, request.Length, token);
            await WithTimeout(writeTask, timeoutMs, token).ConfigureAwait(false);
            var response = new StringBuilder();
            while (response.Length < 8192) {
                byte[] b = await ReadExactly(stream, 1, token, timeoutMs).ConfigureAwait(false);
                response.Append((char)b[0]);
                if (response.Length >= 4 && response.ToString(response.Length-4,4) == "\r\n\r\n") {
                    string first = response.ToString().Split(new[]{"\r\n"}, StringSplitOptions.None)[0];
                    var parts = first.Split(' ');
                    if (parts.Length < 2 || (parts[0] != "HTTP/1.0" && parts[0] != "HTTP/1.1") || parts[1] != "200")
                        throw new IOException("HTTP CONNECT rejected (non-200 or malformed status). No credentials were sent.");
                    return;
                }
            }
            throw new IOException("HTTP CONNECT headers exceed 8 KiB.");
        }

        private static async Task SocksConnect(Stream stream, CancellationToken token, int timeoutMs) {
            byte[] greeting = {5,1,0};
            var writeGreeting = stream.WriteAsync(greeting, 0, greeting.Length, token);
            await WithTimeout(writeGreeting, timeoutMs, token).ConfigureAwait(false);
            byte[] answer = await ReadExactly(stream, 2, token, timeoutMs).ConfigureAwait(false);
            if (answer[0] != 5 || answer[1] != 0) throw new IOException("SOCKS5 requires unsupported authentication or version.");
            byte[] host = Encoding.ASCII.GetBytes(Host);
            byte[] request = new byte[7 + host.Length];
            request[0] = 5; request[1] = 1; request[2] = 0; request[3] = 3; request[4] = (byte)host.Length;
            Buffer.BlockCopy(host, 0, request, 5, host.Length);
            request[request.Length - 2] = 1; request[request.Length - 1] = 187;
            var writeReq = stream.WriteAsync(request, 0, request.Length, token);
            await WithTimeout(writeReq, timeoutMs, token).ConfigureAwait(false);
            byte[] head = await ReadExactly(stream, 4, token, timeoutMs).ConfigureAwait(false);
            if (head[0] != 5 || head[1] != 0 || head[2] != 0) throw new IOException("SOCKS5 CONNECT failed.");
            int length;
            if (head[3] == 1) length = 4;
            else if (head[3] == 4) length = 16;
            else if (head[3] == 3) length = (await ReadExactly(stream, 1, token, timeoutMs).ConfigureAwait(false))[0];
            else throw new IOException("Malformed SOCKS5 address type.");
            if (length == 0) throw new IOException("Empty SOCKS5 bound address.");
            await ReadExactly(stream, length + 2, token, timeoutMs).ConfigureAwait(false);
        }

        public static Task<CommunityTlsResult> RunAsync(int timeoutMs, IPAddress connectAddress, Uri proxy) {
            return RunAsync(timeoutMs, connectAddress, proxy, false);
        }

        public static async Task<CommunityTlsResult> RunAsync(int timeoutMs, IPAddress connectAddress, Uri proxy, bool allowTls12) {
            string stage = "DNS"; var watch = new Stopwatch();
            var result = new CommunityTlsResult {
                Success = false, Status = "Failed", FailedStage = "", FailureKind = "",
                RequestedProtocols = (int)GetProtocols(allowTls12), Sni = Host,
                Path = proxy == null ? "system/direct" : proxy.Scheme + " proxy tunnel",
                ConnectedEndpointRole = proxy == null ? "Destination" : "Proxy",
                ResolutionTarget = proxy == null ? Host : proxy.Host,
                ResolvedAddresses = new string[0], DestinationAddresses = new string[0],
                DnsStatus = "NotTested", TcpStatus = "NotTested",
                ProxyStatus = proxy == null ? "NotUsed" : "NotTested", TlsStatus = "NotTested"
            };
            if (!allowTls12 && Environment.OSVersion.Platform == PlatformID.Win32NT && Environment.OSVersion.Version.Build < 20348) {
                result.Status = "Unsupported"; result.FailedStage = "Runtime";
                result.FailureKind = "OSUnsupported"; result.TlsStatus = "Blocked";
                throw new CommunityTlsException(result, null);
            }
            try {
                using (var cts = new CancellationTokenSource(timeoutMs * 4)) {
                    IPAddress[] addresses; double dnsMs = 0;
                    string targetHost = proxy == null ? Host : proxy.Host;
                    int targetPort = proxy == null ? 443 : proxy.Port;
                    if (connectAddress != null) {
                        addresses = new[] { connectAddress };
                        result.DnsStatus = "NotUsed";
                    } else {
                        watch.Restart();
                        IPAddress literal;
                        if (IPAddress.TryParse(targetHost, out literal)) {
                            addresses = new[] { literal }; result.DnsStatus = "NotUsed";
                        } else {
                            addresses = await Resolve(Dns.GetHostAddressesAsync(targetHost), timeoutMs, cts.Token).ConfigureAwait(false);
                            result.DnsStatus = "Passed";
                        }
                        watch.Stop(); dnsMs = watch.Elapsed.TotalMilliseconds;
                    }
                    result.DnsMs = dnsMs;
                    result.ResolvedAddresses = Array.ConvertAll(addresses, address => address.ToString());
                    if (proxy == null) result.DestinationAddresses = result.ResolvedAddresses;
                    using (var tcp = new TcpClient()) {
                        tcp.NoDelay = true; stage = "TCP connect"; watch.Restart();
                        var connectTask = tcp.ConnectAsync(addresses, targetPort);
                        await Connect(tcp, connectTask, timeoutMs, cts.Token).ConfigureAwait(false);
                        watch.Stop(); double tcpMs = watch.Elapsed.TotalMilliseconds;
                        result.TcpConnectMs = tcpMs; result.TcpStatus = "Passed";
                        string endpoint = tcp.Client.RemoteEndPoint.ToString(); double proxyMs = 0;
                        result.RemoteEndpoint = endpoint;
                        var peerAddress = ((IPEndPoint)tcp.Client.RemoteEndPoint).Address;
                        result.ConnectedAddress = (peerAddress.IsIPv4MappedToIPv6 ? peerAddress.MapToIPv4() : peerAddress).ToString();
                        using (var stream = tcp.GetStream()) {
                            if (proxy != null) {
                                stage = proxy.Scheme == "http" ? "HTTP CONNECT" : "SOCKS5 CONNECT";
                                watch.Restart();
                                var negotiation = proxy.Scheme == "http" ? HttpConnect(stream, cts.Token, timeoutMs) : SocksConnect(stream, cts.Token, timeoutMs);
                                try { await WithTimeout(negotiation, timeoutMs, cts.Token).ConfigureAwait(false); }
                                catch { stream.Dispose(); throw; }
                                watch.Stop(); proxyMs = watch.Elapsed.TotalMilliseconds;
                                result.ProxyNegotiationMs = proxyMs; result.ProxyStatus = "Passed";
                            }
                            using (var tls = new SslStream(stream, false)) {
                                stage = allowTls12 ? "TLS handshake" : "TLS 1.3 handshake"; watch.Restart();
                                await Authenticate(tls, timeoutMs, allowTls12, cts.Token).ConfigureAwait(false);
                                watch.Stop(); double tlsMs = watch.Elapsed.TotalMilliseconds;
                                bool isTls13 = (int)tls.SslProtocol == 12288 || tls.SslProtocol.ToString() == "Tls13";
                                string cipher = tls.CipherAlgorithm + " " + tls.CipherStrength + " bit";
                                string protocolName = isTls13 ? "TLS 1.3" : (tls.SslProtocol == SslProtocols.Tls12 ? "TLS 1.2" : tls.SslProtocol.ToString());
                                string note = isTls13 ? "" : "Согласован " + protocolName + ". Это не подтверждение TLS 1.3: системный TLS 1.3 в Windows 10 обычно недоступен.";
                                result.Success = true; result.Status = "Succeeded"; result.TlsStatus = "Passed";
                                result.Protocol = protocolName; result.CipherSuite = cipher;
                                result.TlsHandshakeMs = tlsMs; result.IsTls13 = isTls13; result.Note = note;
                                return result;
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                watch.Stop(); result.FailedStage = stage;
                bool tlsStage = stage == "TLS handshake" || stage == "TLS 1.3 handshake";
                string unsupportedKind = tlsStage ? UnsupportedKind(ex) : null;
                bool unsupported = unsupportedKind != null;
                result.FailureKind = unsupported ? unsupportedKind :
                    ex is TimeoutException || ex is OperationCanceledException ? "Timeout" :
                    ex is AuthenticationException ? "Authentication" : tlsStage ? "Tls" :
                    stage == "DNS" ? "Dns" : stage == "TCP connect" ? "Tcp" : "ProxyRejected";
                if (unsupported) { result.Status = "Unsupported"; result.FailedStage = "Runtime"; }
                if (stage == "DNS") { result.DnsStatus = "Failed"; result.DnsMs = watch.Elapsed.TotalMilliseconds; }
                else if (stage == "TCP connect") { result.TcpStatus = "Failed"; result.TcpConnectMs = watch.Elapsed.TotalMilliseconds; }
                else if (tlsStage) { result.TlsStatus = unsupported ? "Blocked" : "Failed"; result.TlsHandshakeMs = watch.Elapsed.TotalMilliseconds; }
                else { result.ProxyStatus = "Failed"; result.ProxyNegotiationMs = watch.Elapsed.TotalMilliseconds; }
                throw new CommunityTlsException(result, ex);
            }
        }
    }
}

'@ -ErrorAction Stop
    }
    if($AllowTls12){[AGOptimizer.CommunityTlsProbe]::RunAsync($TimeoutMs,$ConnectAddress,$ProxyUri,$true).GetAwaiter().GetResult()}
    else{[AGOptimizer.CommunityTlsProbe]::RunAsync($TimeoutMs,$ConnectAddress,$ProxyUri).GetAwaiter().GetResult()}
}
