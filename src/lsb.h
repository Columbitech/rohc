#pragma once

#include <vector>
#include <limits>
#include <rohc/rohc.h>

namespace ROHC
{
    int LSBWindowPForReordering(Reordering_t reorder_ratio, size_t width);
    
    
    /**
     * function returns p given a reorder ratio
     */
    //    int ReorderRatioToP(Reordering_t reorder_ratio, unsigned int k);
    
    /**
     * Returns min and max such that:
     * min = v_ref - p
     * max = v_ref + (2^k -1 ) - p
     *
     * See RFC 3095 - 4.5.1
     */
    template<typename T>
    void f(T v_ref, T k, int p, T& min, T& max)
    {
        min = static_cast<int>(v_ref) - p;
        max = static_cast<int>(v_ref) + ((1 << k) - 1) - p;
    }
    
    /**
     * Returns a k such that
     * f_min(v_ref, k, p) <= v <= f_max(v_ref, k, p)
     */
    template<typename T>
    unsigned int g(T v, T v_ref, unsigned int maxbits, int p)
    {
        unsigned int k = 0;
        for (; k < maxbits; ++k)
        {
            T min, max;
            f<T>(v_ref, k, p, min, max);
            if ( (min <= v) && (v <= max))
                break;
            
        }
        return k;
    }        

    template <typename T>
    class WLSB
    {
        struct LSB
        {
            LSB() : v_ref(0), msn(0) {}
            
            T v_ref;
            uint16_t msn;
        };
        
        typedef typename std::vector<LSB > window_t;
        typedef typename window_t::iterator window_iterator;
        typedef typename window_t::const_iterator const_window_iterator;
        
    public:   
        WLSB(size_t windowSize, unsigned int maxWidth, int p)
        : window(windowSize)
        , windowSize(windowSize)
        , first(0)
        , next(0)
        , p(p)
        , maxWidth(maxWidth) {}
        
        void setP(int p)
        {
            this->p = p;
        }
        
        /**
         * returns the number of bits needed to encode a value
         */
        unsigned int width(T value) const {
            T v_min = std::numeric_limits<T>::max();
            T v_max = std::numeric_limits<T>::min();
            
            // No values in the window
            if (first == next) {
                return maxWidth;
            }
            
            for (size_t i = first; i != next; ++i) {
                T vr = window[i % windowSize].v_ref;
                
                if (vr < v_min)
                    v_min = vr;
                
                if (vr > v_max)
                    v_max = vr;
            }
            
            
            unsigned int min_bits = g(value, v_min, maxWidth, p);
            unsigned int max_bits = g(value, v_max, maxWidth, p);
            return std::max(min_bits, max_bits);
        }
    
        void add(uint16_t msn, T v_ref)
        {
            size_t idx = next % windowSize;
            window[idx].v_ref = v_ref;
            window[idx].msn = msn;
            
            ++next;
            if ((next - first) > windowSize) {
                ++first;
            }
            
        }
        
        void ackMSN(uint16_t msn) {
            // Don't ever empty the window
            if ((next - first) < 2) return;
            
            while(first != next) {
                if (window[first % windowSize].msn < msn) {
                    ++first;
                }
                else {
                    break;
                }
            }
        }

    private:
        window_t window;
        size_t windowSize;
        size_t first, next;
        
        int p;
        unsigned int maxWidth;
    };
    
} // ns ROHC