using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignEngineLibrary.Models
{
    public class UsbTokenInfo
    {
        public string SlotDescription { get; set; }
        public string ManufacturerId { get; set; }
        public ulong SlotId { get; set; }
        public TokenInfo Token { get; set; }

        public class TokenInfo
        {
            public string Label { get; set; }
            public string ManufacturerId { get; set; }
            public string Model { get; set; }
            public string SerialNumber { get; set; }
            public ulong MaxSessionCount { get; set; }
            public ulong SessionCount { get; set; }
            public ulong MaxRwSessionCount { get; set; }
            public ulong RwSessionCount { get; set; }
            public ulong MaxPinLen { get; set; }
            public ulong MinPinLen { get; set; }
            public ulong TotalPublicMemory { get; set; }
            public ulong FreePublicMemory { get; set; }
            public ulong TotalPrivateMemory { get; set; }
            public ulong FreePrivateMemory { get; set; }
            public string HardwareVersion { get; set; }
            public string FirmwareVersion { get; set; }
            public string UtcTime { get; set; }
        }
    }
}
