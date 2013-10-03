#include "lsb.h"

namespace ROHC
{
    int
    LSBWindowPForReordering(Reordering_t reorder_ratio, size_t width)
    {
		size_t two_k = 1 << width;
        switch (reorder_ratio)
        {
            case REORDERING_NONE:
                return 1;
                break;
            case REORDERING_QUARTER:
                return static_cast<int>((two_k >> 2) - 1); //((2^k) / 4) - 1)
                break;
            case REORDERING_HALF:
                return static_cast<int>((two_k >> 1) -1); //32767; //((2^k) / 2) - 1);
                break;
            case REORDERING_THREEQUARTERS:
                return static_cast<int>(3*two_k / 4 - 1);//49151; //(((2^k) * 3) / 4) - 1);
                break;
            default:
                RASSERT(false);
                break;
        }
        return 0;
        
    }

} // ns ROHC