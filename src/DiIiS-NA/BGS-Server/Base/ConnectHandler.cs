using DiIiS_NA.Core.Logging;
using DiIiS_NA.LoginServer.Battle;
using DotNetty.Codecs;
using DotNetty.Codecs.Http;
using DotNetty.Handlers.Tls;
using DotNetty.Transport.Channels;
using DotNetty.Transport.Channels.Sockets;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;


using DotNetty.Buffers;
using DotNetty.Common.Utilities;
using System.Threading.Tasks;
using DotNetty.Codecs.Http.WebSockets;

namespace DiIiS_NA.LoginServer.Base
{
    public class ConnectHandler : ChannelInitializer<ISocketChannel>
    {
        private static readonly Logger Logger = LogManager.CreateLogger("BlizzLess.Net System");
        protected override void InitChannel(ISocketChannel socketChannel)
        {
            Logger.Info("Request of new Client - IP: - {0}", socketChannel.RemoteAddress);
            IChannelPipeline p = socketChannel.Pipeline;

            var Certificate = new X509Certificate2("bnetserver.p12", "123");
            TlsHandler TLS = TlsHandler.Server(Certificate);

            p.AddLast(new PreTlsLogger());
            p.AddLast(TLS);
            p.AddLast(new RawDataLogger());
            p.AddLast(new HttpServerCodec());
            p.AddLast(new HttpObjectAggregator(8192));
            //p.AddLast(new WebSocketServerProtocolHandler("/", "jsonrpc.aurora.v1.30.battle.net", true));
            p.AddLast(new HandshakeHandler("/", "v1.rpc.battle.net", true, 65536, false, true));

            p.AddLast(new BNetCodec());
            p.AddLast(new BattleClient(socketChannel, TLS));
        }
        private static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
    public class HandshakeHandler : WebSocketProtocolHandler
    {
        public sealed class HandshakeComplete
        {
            private readonly string requestUri;

            private readonly HttpHeaders requestHeaders;

            private readonly string selectedSubprotocol;

            public string RequestUri => requestUri;

            public HttpHeaders RequestHeaders => requestHeaders;

            public string SelectedSubprotocol => selectedSubprotocol;

            internal HandshakeComplete(string requestUri, HttpHeaders requestHeaders, string selectedSubprotocol)
            {
                this.requestUri = requestUri;
                this.requestHeaders = requestHeaders;
                this.selectedSubprotocol = selectedSubprotocol;
            }
        }

        private sealed class ForbiddenResponseHandler : ChannelHandlerAdapter
        {
            public override void ChannelRead(IChannelHandlerContext ctx, object msg)
            {
                IFullHttpRequest fullHttpRequest;
                if ((fullHttpRequest = (msg as IFullHttpRequest)) != null)
                {
                    fullHttpRequest.Release();
                    DefaultFullHttpResponse message = new DefaultFullHttpResponse(HttpVersion.Http11, HttpResponseStatus.Forbidden);
                    ctx.Channel.WriteAndFlushAsync(message);
                }
                else
                {
                    ctx.FireChannelRead(msg);
                }
            }
        }

        private static readonly AttributeKey<WebSocketServerHandshaker> HandshakerAttrKey = AttributeKey<WebSocketServerHandshaker>.ValueOf("HANDSHAKER");

        private readonly string websocketPath;

        private readonly string subprotocols;

        private readonly bool allowExtensions;

        private readonly int maxFramePayloadLength;

        private readonly bool allowMaskMismatch;

        private readonly bool checkStartsWith;

        public HandshakeHandler(string websocketPath)
            : this(websocketPath, null, allowExtensions: false)
        {
        }

        public HandshakeHandler(string websocketPath, bool checkStartsWith)
            : this(websocketPath, null, allowExtensions: false, 65536, allowMaskMismatch: false, checkStartsWith)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols)
            : this(websocketPath, subprotocols, allowExtensions: false)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions)
            : this(websocketPath, subprotocols, allowExtensions, 65536)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize)
            : this(websocketPath, subprotocols, allowExtensions, maxFrameSize, allowMaskMismatch: false)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize, bool allowMaskMismatch)
            : this(websocketPath, subprotocols, allowExtensions, maxFrameSize, allowMaskMismatch, checkStartsWith: false)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize, bool allowMaskMismatch, bool checkStartsWith)
            : this(websocketPath, subprotocols, allowExtensions, maxFrameSize, allowMaskMismatch, checkStartsWith, dropPongFrames: true)
        {
        }

        public HandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize, bool allowMaskMismatch, bool checkStartsWith, bool dropPongFrames)
            : base()// : base(dropPongFrames)
        {
            this.websocketPath = websocketPath;
            this.subprotocols = subprotocols;
            this.allowExtensions = allowExtensions;
            maxFramePayloadLength = maxFrameSize;
            this.allowMaskMismatch = allowMaskMismatch;
            this.checkStartsWith = checkStartsWith;
        }

        public override void HandlerAdded(IChannelHandlerContext ctx)
        {
            IChannelPipeline pipeline = ctx.Channel.Pipeline;
            if (pipeline.Get<WebSocketServerProtocolHandshakeHandler>() == null)
            {
                ctx.Channel.Pipeline.AddBefore(ctx.Name, "WebSocketServerProtocolHandshakeHandler", new WebSocketServerProtocolHandshakeHandler(websocketPath, subprotocols, allowExtensions, maxFramePayloadLength, allowMaskMismatch, checkStartsWith));
            }

            if (pipeline.Get<Utf8FrameValidator>() == null)
            {
                ctx.Channel.Pipeline.AddBefore(ctx.Name, "Utf8FrameValidator", new Utf8FrameValidator());
            }
        }

        protected override void Decode(IChannelHandlerContext ctx, WebSocketFrame frame, List<object> output)
        {
            CloseWebSocketFrame frame2;
            if ((frame2 = (frame as CloseWebSocketFrame)) != null)
            {
                WebSocketServerHandshaker handshaker = GetHandshaker(ctx.Channel);
                if (handshaker != null)
                {
                    frame.Retain();
                    handshaker.CloseAsync(ctx.Channel, frame2);
                }
                else
                {
                    ctx.WriteAndFlushAsync(Unpooled.Empty).ContinueWith((Task t, object c) => ((IChannelHandlerContext)c).CloseAsync(), ctx, TaskContinuationOptions.ExecuteSynchronously);
                }
            }
            else
            {
                base.Decode(ctx, frame, output);
            }
        }

        public override void ExceptionCaught(IChannelHandlerContext ctx, Exception cause)
        {
            if (cause is WebSocketHandshakeException)
            {
                DefaultFullHttpResponse message = new DefaultFullHttpResponse(HttpVersion.Http11, HttpResponseStatus.BadRequest, Unpooled.WrappedBuffer(Encoding.ASCII.GetBytes(cause.Message)));
                ctx.Channel.WriteAndFlushAsync(message).ContinueWith((Task t, object c) => ((IChannelHandlerContext)c).CloseAsync(), ctx, TaskContinuationOptions.ExecuteSynchronously);
            }
            else
            {
                ctx.FireExceptionCaught(cause);
                ctx.CloseAsync();
            }
        }

        internal static WebSocketServerHandshaker GetHandshaker(IChannel channel)
        {
            return channel.GetAttribute(HandshakerAttrKey).Get();
        }

        internal static void SetHandshaker(IChannel channel, WebSocketServerHandshaker handshaker)
        {
            channel.GetAttribute(HandshakerAttrKey).Set(handshaker);
        }

        internal static IChannelHandler ForbiddenHttpRequestResponder()
        {
            return new ForbiddenResponseHandler();
        }
    }

    public abstract class WebSocketProtocolHandler : MessageToMessageDecoder<WebSocketFrame>
    {
        private readonly bool dropPongFrames;

        internal WebSocketProtocolHandler()
            : this(dropPongFrames: true)
        {
        }

        internal WebSocketProtocolHandler(bool dropPongFrames)
        {
            this.dropPongFrames = dropPongFrames;
        }

        protected override void Decode(IChannelHandlerContext ctx, WebSocketFrame frame, List<object> output)
        {
            if (frame is PingWebSocketFrame)
            {
                frame.Content.Retain();
                ctx.Channel.WriteAndFlushAsync(new PongWebSocketFrame(frame.Content));
            }
            else if (!(frame is PongWebSocketFrame) || !dropPongFrames)
            {
                output.Add(frame.Retain());
            }
        }

        public override void ExceptionCaught(IChannelHandlerContext ctx, Exception cause)
        {
            ctx.FireExceptionCaught(cause);
            ctx.CloseAsync();
        }
    }
    internal class WebSocketServerProtocolHandshakeHandler : ChannelHandlerAdapter
    {
        
        static readonly Logger _logger = LogManager.CreateLogger();
        private readonly string websocketPath;

        private readonly string subprotocols;

        private readonly bool allowExtensions;

        private readonly int maxFramePayloadSize;

        private readonly bool allowMaskMismatch;

        private readonly bool checkStartsWith;

        internal WebSocketServerProtocolHandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize, bool allowMaskMismatch)
            : this(websocketPath, subprotocols, allowExtensions, maxFrameSize, allowMaskMismatch, checkStartsWith: false)
        {
        }

        internal WebSocketServerProtocolHandshakeHandler(string websocketPath, string subprotocols, bool allowExtensions, int maxFrameSize, bool allowMaskMismatch, bool checkStartsWith)
        {
            this.websocketPath = websocketPath;
            this.subprotocols = subprotocols;
            this.allowExtensions = allowExtensions;
            maxFramePayloadSize = maxFrameSize;
            this.allowMaskMismatch = allowMaskMismatch;
            this.checkStartsWith = checkStartsWith;
        }

        public override void ChannelRead(IChannelHandlerContext ctx, object msg)
        {
            IFullHttpRequest req = (IFullHttpRequest)msg;
            _logger.Info("WebSocket upgrade request: Method={0}, URI={1}, Protocol={2}", req.Method, req.Uri, req.Headers.TryGet(DotNetty.Codecs.Http.HttpHeaderNames.SecWebsocketProtocol, out var proto) ? proto.ToString() : "(none)");
            if (IsNotWebSocketPath(req))
            {
                _logger.Warn("WebSocket path rejected: URI={0}, expected={1}", req.Uri, websocketPath);
                ctx.FireChannelRead(msg);
                return;
            }

            try
            {
                if (!object.Equals(req.Method, HttpMethod.Get))
                {
                    SendHttpResponse(ctx, req,
                        new DefaultFullHttpResponse(HttpVersion.Http11, HttpResponseStatus.Forbidden));
                    return;
                }

                //v1.rpc.battle.net
                //
                WebSocketServerHandshakerFactory webSocketServerHandshakerFactory =
                    new WebSocketServerHandshakerFactory(GetWebSocketLocation(ctx.Channel.Pipeline, req, websocketPath),
                        subprotocols, allowExtensions, maxFramePayloadSize, allowMaskMismatch);
                WebSocketServerHandshaker handshaker = webSocketServerHandshakerFactory.NewHandshaker(req);
                if (handshaker == null)
                {
                    WebSocketServerHandshakerFactory.SendUnsupportedVersionResponse(ctx.Channel);
                    return;
                }

                handshaker.HandshakeAsync(ctx.Channel, req).ContinueWith(delegate(Task t)
                {
                    if (t.Status != TaskStatus.RanToCompletion)
                    {
                        ctx.FireExceptionCaught(t.Exception);
                    }
                    else
                    {
                        ctx.FireUserEventTriggered(new HandshakeHandler.HandshakeComplete(req.Uri, req.Headers,
                            handshaker.SelectedSubprotocol));
                    }
                }, TaskContinuationOptions.ExecuteSynchronously);
                HandshakeHandler.SetHandshaker(ctx.Channel, handshaker);
                ctx.Channel.Pipeline.Replace(this, "WS403Responder", HandshakeHandler.ForbiddenHttpRequestResponder());
            }
            catch (Exception ex)
            {
                _logger.ErrorException(ex, "Handshake failure");
            }
            finally
            {
                req.Release();
            }
        }

        private bool IsNotWebSocketPath(IFullHttpRequest req)
        {
            if (!checkStartsWith)
            {
                return !req.Uri.Equals(websocketPath);
            }

            return !req.Uri.StartsWith(websocketPath);
        }

        private static void SendHttpResponse(IChannelHandlerContext ctx, IHttpRequest req, IHttpResponse res)
        {
            Task task = ctx.Channel.WriteAndFlushAsync(res);
            if (!HttpUtil.IsKeepAlive(req) || res.Status.Code != 200)
            {
                task.ContinueWith((Task t, object c) => ((IChannel)c).CloseAsync(), ctx.Channel, TaskContinuationOptions.ExecuteSynchronously);
            }
        }

        private static string GetWebSocketLocation(IChannelPipeline cp, IHttpRequest req, string path)
        {
            string protocol = cp.Get<TlsHandler>() != null ? "wss" : "ws";

            // Ignore the Host header and default to a placeholder or IP address
            string host = "192.168.1.100"; // Replace with your desired default host, e.g., the server's IP or DNS.

            return $"{protocol}://{host}{path}";
        }
    }

    public class RawDataLogger : ChannelHandlerAdapter
    {
        public override void HandlerAdded(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PostTLS] handler added");
            base.HandlerAdded(context);
        }

        public override void ChannelActive(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PostTLS] channel ACTIVE");
            base.ChannelActive(context);
        }

        public override void ChannelInactive(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PostTLS] channel INACTIVE");
            base.ChannelInactive(context);
        }

        public override void UserEventTriggered(IChannelHandlerContext context, object evt)
        {
            Console.Error.WriteLine($"[DIAG-PostTLS] UserEvent: {evt.GetType().Name} = {evt}");
            base.UserEventTriggered(context, evt);
        }

        public override void ChannelRead(IChannelHandlerContext context, object message)
        {
            if (message is IByteBuffer buf)
            {
                int readable = buf.ReadableBytes;
                int toDump = Math.Min(readable, 256);
                byte[] bytes = new byte[toDump];
                buf.GetBytes(buf.ReaderIndex, bytes, 0, toDump);
                var hex = BitConverter.ToString(bytes).Replace("-", " ");
                Console.Error.WriteLine($"[DIAG-PostTLS] DATA ({readable} bytes): {hex}");
            }
            else
            {
                Console.Error.WriteLine($"[DIAG-PostTLS] DATA type={message.GetType().FullName}");
            }
            context.FireChannelRead(message);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception)
        {
            Console.Error.WriteLine($"[DIAG-PostTLS] EXCEPTION: {exception}");
            context.FireExceptionCaught(exception);
        }
    }

    public class PreTlsLogger : ChannelHandlerAdapter
    {
        public override void HandlerAdded(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PreTLS] handler added");
            base.HandlerAdded(context);
        }

        public override void ChannelActive(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PreTLS] channel ACTIVE");
            base.ChannelActive(context);
        }

        public override void ChannelInactive(IChannelHandlerContext context)
        {
            Console.Error.WriteLine("[DIAG-PreTLS] channel INACTIVE");
            base.ChannelInactive(context);
        }

        public override void ChannelRead(IChannelHandlerContext context, object message)
        {
            if (message is IByteBuffer buf)
            {
                int readable = buf.ReadableBytes;
                int toDump = Math.Min(readable, 512);
                byte[] bytes = new byte[toDump];
                buf.GetBytes(buf.ReaderIndex, bytes, 0, toDump);
                var hex = BitConverter.ToString(bytes).Replace("-", " ");
                Console.Error.WriteLine($"[DIAG-PreTLS] RAW TCP ({readable} bytes): {hex}");
            }
            context.FireChannelRead(message);
        }

        public override void ExceptionCaught(IChannelHandlerContext context, Exception exception)
        {
            Console.Error.WriteLine($"[DIAG-PreTLS] EXCEPTION: {exception}");
            context.FireExceptionCaught(exception);
        }
    }
}
