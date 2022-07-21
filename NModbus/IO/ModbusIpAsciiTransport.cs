using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using NModbus.Logging;
using NModbus.Message;
using NModbus.Unme.Common;

namespace NModbus.IO
{
    /// <summary>
    ///     Transport for Internet protocols.
    ///     Refined Abstraction - http://en.wikipedia.org/wiki/Bridge_Pattern
    /// </summary>
    internal class ModbusIpAsciiTransport : ModbusTransport
    {
        private static readonly object _transactionIdLock = new object();
        private ushort _transactionId;

        internal ModbusIpAsciiTransport(IStreamResource streamResource, IModbusFactory modbusFactory, IModbusLogger logger)
            : base(streamResource, modbusFactory, logger)
        {
            if (streamResource == null) throw new ArgumentNullException(nameof(streamResource));
        }

        internal static byte[] ReadRequestResponse(IStreamResource streamResource, IModbusLogger logger)
        {
            if (streamResource == null) throw new ArgumentNullException(nameof(streamResource));
            if (logger == null) throw new ArgumentNullException(nameof(logger));

            // read header
            var mbapHeaderChars = new byte[12];
            int numBytesRead = 0;

            while (numBytesRead != 12)
            {
                int bRead = streamResource.Read(mbapHeaderChars, numBytesRead, 12 - numBytesRead);

                if (bRead == 0)
                {
                    throw new IOException("Read resulted in 0 bytes returned.");
                }

                numBytesRead += bRead;
            }

            var mbapHeaderStr = Encoding.Default.GetString(mbapHeaderChars);
            logger.Debug($"MBAP header: {mbapHeaderStr}");

            var mbapHeader = HexStringToByteArray(mbapHeaderStr);

            var frameLength = (ushort)IPAddress.HostToNetworkOrder(BitConverter.ToInt16(mbapHeader, 4));
            logger.Debug($"{frameLength} bytes in PDU.");

            // read message
            var messageFrameChars = new byte[frameLength * 2];
            numBytesRead = 0;

            while (numBytesRead != frameLength * 2)
            {
                int bRead = streamResource.Read(messageFrameChars, numBytesRead, frameLength * 2 - numBytesRead);

                if (bRead == 0)
                {
                    throw new IOException("Read resulted in 0 bytes returned.");
                }

                numBytesRead += bRead;
            }

            logger.Debug($"PDU: {frameLength}");
            var messageFrameStr = Encoding.Default.GetString(messageFrameChars);
            var messageFrame = HexStringToByteArray(messageFrameStr);
            var frame = mbapHeader.Concat(messageFrame).ToArray();
            logger.LogFrameRx(frame);

            return frame;
        }

        internal static byte[] GetMbapHeader(IModbusMessage message)
        {
            byte[] transactionId = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)message.TransactionId));
            byte[] length = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)(message.ProtocolDataUnit.Length + 1)));

            var stream = new MemoryStream(7);
            stream.Write(transactionId, 0, transactionId.Length);
            stream.WriteByte(0);
            stream.WriteByte(0);
            stream.Write(length, 0, length.Length);
            stream.WriteByte(message.SlaveAddress);

            return stream.ToArray();
        }

        /// <summary>
        ///     Create a new transaction ID.
        /// </summary>
        internal virtual ushort GetNewTransactionId()
        {
            lock (_transactionIdLock)
            {
                _transactionId = _transactionId == ushort.MaxValue ? (ushort)1 : ++_transactionId;
            }

            return _transactionId;
        }

        internal IModbusMessage CreateMessageAndInitializeTransactionId<T>(byte[] fullFrame)
            where T : IModbusMessage, new()
        {
            byte[] mbapHeader = fullFrame.Slice(0, 6).ToArray();
            byte[] messageFrame = fullFrame.Slice(6, fullFrame.Length - 6).ToArray();

            IModbusMessage response = CreateResponse<T>(messageFrame);
            response.TransactionId = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(mbapHeader, 0));

            return response;
        }

        private static string ByteArrayToHexString(byte[] data)
        {
            if (data is null)
                return string.Empty;

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                builder.Append(data[i].ToString("X02"));
            }

            return builder.ToString();
        }

        private static byte[] HexStringToByteArray(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                return new byte[0];

            if (data.Length % 2 != 0)
            {
                data = data.PadLeft(1, '0');
            }

            byte[] returnBytes = new byte[data.Length / 2];

            int i = 0;
            int j = 0;
            for (; i < data.Length; i += 2, j++)
            {
                string chars = data.Substring(i, 2);
                returnBytes[j] = Convert.ToByte(chars, 16);
            }

            return returnBytes;
        }

        public override byte[] BuildMessageFrame(IModbusMessage message)
        {
            byte[] header = GetMbapHeader(message);
            byte[] pdu = message.ProtocolDataUnit;
            var messageBody = new MemoryStream(header.Length + pdu.Length);

            messageBody.Write(header, 0, header.Length);
            messageBody.Write(pdu, 0, pdu.Length);

            var hexString = ByteArrayToHexString(messageBody.ToArray());

            var returnBytes = Encoding.Default.GetBytes(hexString);

            return returnBytes;
        }

        public override void Write(IModbusMessage message)
        {
            message.TransactionId = GetNewTransactionId();
            byte[] frame = BuildMessageFrame(message);

            Logger.LogFrameTx(frame);

            StreamResource.Write(frame, 0, frame.Length);
        }

        public override byte[] ReadRequest()
        {
            return ReadRequestResponse(StreamResource, Logger);
        }

        public override IModbusMessage ReadResponse<T>()
        {
            return CreateMessageAndInitializeTransactionId<T>(ReadRequestResponse(StreamResource, Logger));
        }

        internal override void OnValidateResponse(IModbusMessage request, IModbusMessage response)
        {
            if (request.TransactionId != response.TransactionId)
            {
                string msg = $"Response was not of expected transaction ID. Expected {request.TransactionId}, received {response.TransactionId}.";
                throw new IOException(msg);
            }
        }

        public override bool OnShouldRetryResponse(IModbusMessage request, IModbusMessage response)
        {
            if (request.TransactionId > response.TransactionId && request.TransactionId - response.TransactionId < RetryOnOldResponseThreshold)
            {
                // This response was from a previous request
                return true;
            }

            return base.OnShouldRetryResponse(request, response);
        }
    }
}
