#pragma once

/**
 * These functions have to be implemented by the app using the library
 */
namespace ROHC {
    void info(const char* format, ...);
    void warn(const char* format, ...);
    void error(const char* format, ...);
}