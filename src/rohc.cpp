#include <rohc/rohc.h>
#include <algorithm>
#include <functional>
#include <numeric>
#include <iostream>

#include <ctime>

using namespace std;

namespace ROHC 
{
    void 
    PrintState(uint16_t msn, Reordering_t rr, IPIDBehaviour_t ipbehav)
    {
        cout << "MSN: " << msn << endl;
        cout << "Reorder ratio: ";
        switch (rr)
        {
            case REORDERING_NONE:
                cout << "REORDERING_NONE";
                break;
            case REORDERING_QUARTER:
                cout << "REORDERING_QUARTER";
                break;
            case REORDERING_HALF:
                cout << "REORDERING_HALF";
                break;
            case REORDERING_THREEQUARTERS:
                cout << "REORDERING_THREEQUARTERS";
                break;
            default:
                cout << "Unknown";
                break;
        }
        
        cout << endl << "IP ID Behaviour: ";
        switch (ipbehav)
        {
            case IP_ID_BEHAVIOUR_SEQUENTIAL:
                cout << "IP_ID_BEHAVIOUR_SEQUENTIAL";
                break;
            case IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED:
                cout << "IP_ID_BEHAVIOUR_SEQUENTIAL_SWAPPED";
                break;
            case IP_ID_BEHAVIOUR_RANDOM:
                cout << "IP_ID_BEHAVIOUR_RANDOM";
                break;
            case IP_ID_BEHAVIOUR_ZERO:
                cout << "IP_ID_BEHAVIOUR_ZERO";
                break;
            default:
                cout << "Unknown";
                break;                
        }
        
        cout << endl;

    }
    
    
    void
    PrintData(const_data_iterator begin, const_data_iterator end)
    {
        unsigned int idx = 0;
        for (const_data_iterator i = begin; end != i; ++i, ++idx)
        {
            cout.width(2);
            cout << hex << static_cast<unsigned int>(*i);
            if (idx > 0 && !(idx % 16))
                cout << endl;
            else
                cout << ", ";
        }
        cout << dec << endl;
    }
    
    void
    PrintCompareData(const_data_iterator begin1, const_data_iterator end1, const_data_iterator begin2)
    {
        const_data_iterator i1 = begin1;
        const_data_iterator i2 = begin2;
        unsigned idx = 0;
        for (; end1 != i1; ++i1, ++i2, ++idx)
        {
            cout.width(10);
            cout << dec << idx;
            cout.width(4);
            cout << hex << (unsigned) *i1;
            cout.width(4);
            cout << hex << (unsigned) *i2;
            cout << dec << endl;
        }
    }
    
    
    /**
     * CRC functions
     */
    namespace {
        struct CRCCalc : public binary_function<uint8_t, uint8_t, uint8_t>
        {
            CRCCalc(const uint8_t* table, uint8_t mask) : _table(table), _mask(mask) {}
            
            uint8_t operator()(uint8_t crc, uint8_t byte)
            {
                return _table[byte ^ (crc&_mask)];
            }
            
            const uint8_t* _table;
            uint8_t _mask;
        };
        
    } // anon NS
    
    /*
     module Main
     
     where
     
     import Data.Word
     import Data.Bits
     import Control.Monad
     
     
     crc_inner :: Word8 -> Word8 -> Word8
     crc_inner poly crcInit =
     foldl (\c _ -> crc c) crcInit [1..8] 
     where
     
     crc c = 
     let 
     cs = shiftR c 1
     codd = c .&. 1
     in  
     if codd == 1 then 
     xor cs poly
     else                      
     cs
     
     crc_outer :: Word8 -> [(Integer, Word8)]
     crc_outer poly =
     map (\i -> (i, crc_inner poly (fromIntegral i))) [0..255]
     
     
     endl :: Integer -> String
     endl 0 = ""
     endl idx =
     if idx `mod` 16 == 0 then "\n"
     else ""
     
     
     
     table :: String -> [(Integer, Word8)] -> String
     table name t =
     "unsigned char " ++ name ++ "[256] = {\n" ++ 
     foldl (\str (i,v) -> str ++ (show v) ++ ", " ++ endl i) "" t
     ++ "};\n\n"
     
     main = do
     let t3 = crc_outer 6
     t7 = crc_outer 121
     t8 = crc_outer 224
     
     putStrLn $ table "crc3" t3
     putStrLn $ table "crc7" t7
     putStrLn $ table "crc8" t8
    
     */
      
    unsigned char crc3[256] = {
        0, 6, 1, 7, 2, 4, 3, 5, 4, 2, 5, 3, 6, 0, 7, 1, 5, 
        3, 4, 2, 7, 1, 6, 0, 1, 7, 0, 6, 3, 5, 2, 4, 7, 
        1, 6, 0, 5, 3, 4, 2, 3, 5, 2, 4, 1, 7, 0, 6, 2, 
        4, 3, 5, 0, 6, 1, 7, 6, 0, 7, 1, 4, 2, 5, 3, 3, 
        5, 2, 4, 1, 7, 0, 6, 7, 1, 6, 0, 5, 3, 4, 2, 6, 
        0, 7, 1, 4, 2, 5, 3, 2, 4, 3, 5, 0, 6, 1, 7, 4, 
        2, 5, 3, 6, 0, 7, 1, 0, 6, 1, 7, 2, 4, 3, 5, 1, 
        7, 0, 6, 3, 5, 2, 4, 5, 3, 4, 2, 7, 1, 6, 0, 6, 
        0, 7, 1, 4, 2, 5, 3, 2, 4, 3, 5, 0, 6, 1, 7, 3, 
        5, 2, 4, 1, 7, 0, 6, 7, 1, 6, 0, 5, 3, 4, 2, 1, 
        7, 0, 6, 3, 5, 2, 4, 5, 3, 4, 2, 7, 1, 6, 0, 4, 
        2, 5, 3, 6, 0, 7, 1, 0, 6, 1, 7, 2, 4, 3, 5, 5, 
        3, 4, 2, 7, 1, 6, 0, 1, 7, 0, 6, 3, 5, 2, 4, 0, 
        6, 1, 7, 2, 4, 3, 5, 4, 2, 5, 3, 6, 0, 7, 1, 2, 
        4, 3, 5, 0, 6, 1, 7, 6, 0, 7, 1, 4, 2, 5, 3, 7, 
        1, 6, 0, 5, 3, 4, 2, 3, 5, 2, 4, 1, 7, 0, 6, };
    
    
    unsigned char crc7[256] = {
        0, 64, 115, 51, 21, 85, 102, 38, 42, 106, 89, 25, 63, 127, 76, 12, 84, 
        20, 39, 103, 65, 1, 50, 114, 126, 62, 13, 77, 107, 43, 24, 88, 91, 
        27, 40, 104, 78, 14, 61, 125, 113, 49, 2, 66, 100, 36, 23, 87, 15, 
        79, 124, 60, 26, 90, 105, 41, 37, 101, 86, 22, 48, 112, 67, 3, 69, 
        5, 54, 118, 80, 16, 35, 99, 111, 47, 28, 92, 122, 58, 9, 73, 17, 
        81, 98, 34, 4, 68, 119, 55, 59, 123, 72, 8, 46, 110, 93, 29, 30, 
        94, 109, 45, 11, 75, 120, 56, 52, 116, 71, 7, 33, 97, 82, 18, 74, 
        10, 57, 121, 95, 31, 44, 108, 96, 32, 19, 83, 117, 53, 6, 70, 121, 
        57, 10, 74, 108, 44, 31, 95, 83, 19, 32, 96, 70, 6, 53, 117, 45, 
        109, 94, 30, 56, 120, 75, 11, 7, 71, 116, 52, 18, 82, 97, 33, 34, 
        98, 81, 17, 55, 119, 68, 4, 8, 72, 123, 59, 29, 93, 110, 46, 118, 
        54, 5, 69, 99, 35, 16, 80, 92, 28, 47, 111, 73, 9, 58, 122, 60, 
        124, 79, 15, 41, 105, 90, 26, 22, 86, 101, 37, 3, 67, 112, 48, 104, 
        40, 27, 91, 125, 61, 14, 78, 66, 2, 49, 113, 87, 23, 36, 100, 103, 
        39, 20, 84, 114, 50, 1, 65, 77, 13, 62, 126, 88, 24, 43, 107, 51, 
        115, 64, 0, 38, 102, 85, 21, 25, 89, 106, 42, 12, 76, 127, 63, };
    
    
    unsigned char crc8[256] = {
        0, 145, 227, 114, 7, 150, 228, 117, 14, 159, 237, 124, 9, 152, 234, 123, 28, 
        141, 255, 110, 27, 138, 248, 105, 18, 131, 241, 96, 21, 132, 246, 103, 56, 
        169, 219, 74, 63, 174, 220, 77, 54, 167, 213, 68, 49, 160, 210, 67, 36, 
        181, 199, 86, 35, 178, 192, 81, 42, 187, 201, 88, 45, 188, 206, 95, 112, 
        225, 147, 2, 119, 230, 148, 5, 126, 239, 157, 12, 121, 232, 154, 11, 108, 
        253, 143, 30, 107, 250, 136, 25, 98, 243, 129, 16, 101, 244, 134, 23, 72, 
        217, 171, 58, 79, 222, 172, 61, 70, 215, 165, 52, 65, 208, 162, 51, 84, 
        197, 183, 38, 83, 194, 176, 33, 90, 203, 185, 40, 93, 204, 190, 47, 224, 
        113, 3, 146, 231, 118, 4, 149, 238, 127, 13, 156, 233, 120, 10, 155, 252, 
        109, 31, 142, 251, 106, 24, 137, 242, 99, 17, 128, 245, 100, 22, 135, 216, 
        73, 59, 170, 223, 78, 60, 173, 214, 71, 53, 164, 209, 64, 50, 163, 196, 
        85, 39, 182, 195, 82, 32, 177, 202, 91, 41, 184, 205, 92, 46, 191, 144, 
        1, 115, 226, 151, 6, 116, 229, 158, 15, 125, 236, 153, 8, 122, 235, 140, 
        29, 111, 254, 139, 26, 104, 249, 130, 19, 97, 240, 133, 20, 102, 247, 168, 
        57, 75, 218, 175, 62, 76, 221, 166, 55, 69, 212, 161, 48, 66, 211, 180, 
        37, 87, 198, 179, 34, 80, 193, 186, 43, 89, 200, 189, 44, 94, 207, }; 
    
    uint8_t
    CRC3(const_data_iterator begin, const_data_iterator end)
    {
        return accumulate(begin, end, 0x7, CRCCalc(crc3, 7));
    }

	uint8_t 
	CRC3(const uint8_t* begin, const uint8_t* end)
	{
        return accumulate(begin, end, 0x7, CRCCalc(crc3, 7));
	}
    
    uint8_t
    CRC7(const_data_iterator begin, const_data_iterator end)
    {
        return accumulate(begin, end, 0x7f, CRCCalc(crc7, 127));
    }

	uint8_t 
	CRC7(const uint8_t* begin, const uint8_t* end)
    {
        return accumulate(begin, end, 0x7f, CRCCalc(crc7, 127));
    }
    
    uint8_t
    CRC8(const_data_iterator begin, const_data_iterator end)
    {
        return accumulate(begin, end, 0xff, CRCCalc(crc8, 0xff));
    }
    
    time_t
    millisSinceEpoch()
    {
        return time(0);
        /*
        timeval tv;
        gettimeofday(&tv, 0);
        return tv.tv_sec * 1000 + tv.tv_usec / 1000;
        */
    }

} // namespace ROHC
