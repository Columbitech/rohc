#pragma once

namespace ROHC {
    
    // RFC 4996, 6.3.4
    namespace ReservedTableIndexs {
        enum _ReservedTableIndex {
            OPT_NOP = 0,                // NOP
            OPT_EOL = 1,                // EndOfOptionList
            OPT_MSS = 2,                // MaximumSegmentSize
            OPT_WINDOW_SCALE = 3,       // WSOPT_WindowScale
            OPT_TIMESTAMP = 4,          // TSOPT
            OPT_SACK_PERMITTED = 5,     // SACK_permitted
            OPT_SACK = 6                // SACK
        };
    }
    
    namespace TCPOptions {
        enum TCPOption {
            EndOfOptionList                     = 0,
            NOP                                 = 1,
            MaximumSegmentSize                  = 2,
            WSOPT_WindowScale                   = 3,
            SACK_permitted                      = 4,
            SACK                                = 5,
            Echo                                = 6,
            EchoReply                           = 7,
            TSOPT                               = 8
            
        };
    }
}