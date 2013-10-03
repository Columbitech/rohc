#pragma once

/**
 * These functions have to be implemented by the app using the library
 */
namespace ROHC {

	void* allocMutex();

	void freeMutex(void* mutex);

	void lockMutex(void* mutex);

	void unlockMutex(void* mutex);

	class ScopedLock {
	public:
		ScopedLock(void* mutex) : mutex(mutex) {lockMutex(mutex);}
		~ScopedLock() {unlockMutex(mutex);}
	private:
		void* mutex;
	};
} // ns ROHC
