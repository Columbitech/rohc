#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>

namespace ROHC {
    void* allocMutex() {
        pthread_mutex_t* m = new pthread_mutex_t;
        pthread_mutex_init(m, 0);
        return m;
    }
    
    void freeMutex(void* pm) {
        delete reinterpret_cast<pthread_mutex_t*>(pm);
    }
    
    void lockMutex(void* pm) {
        pthread_mutex_lock(reinterpret_cast<pthread_mutex_t*>(pm));
    }

    void unlockMutex(void* pm) {
        pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t*>(pm));
    }
    
    void error(const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    
    void info(const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        
        vfprintf(stdout, fmt, ap);
        va_end(ap);
    }
}