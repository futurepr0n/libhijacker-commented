#include "kernel.hpp"
#include "util.hpp"

// External C header
extern "C" {
	#include <ps5/kernel.h>
}

// Function to retrieve a kernel string from a given address
String getKernelString(uintptr_t addr) {
	String res{};   // Initialize an empty string
	char buf[0x10];   // Buffer to hold the copied data

	while (true) {
		kernel_copyout(addr + res.length(), buf, sizeof(buf));   // Copy data from kernel memory to 'buf'
		size_t read = strnlen(buf, sizeof(buf));   // Get the length of the copied data
		res += StringView{buf, read};   // Append the copied data to the result string

		if (read < sizeof(buf)) {
			return res;   // Return the result string if the copied data is less than the buffer size
		}
	}
}

// Function to get a KProc (Kernel Process) instance for a given process ID (pid)
UniquePtr<KProc> getProc(int pid) {
	// Iterate through all KProc instances
	for (auto p : getAllProcs()) {
		if (pid == p->pid()) {
			return p.release();   // Return the KProc instance if the pid matches
		}
	}
	return nullptr;   // Return nullptr if no matching KProc instance is found
}
