#include "hijacker.hpp"
#include "offsets.hpp"
#include "util.hpp"
#include <ps5/kernel.h>

// External C headers
extern "C" {
#include <stdint.h>
#include <stdio.h>
}

// Get a Hijacker instance for a specific process
UniquePtr<Hijacker> Hijacker::getHijacker(const StringView &processName) {
	UniquePtr<SharedObject> obj = nullptr;

	// Iterate through the list of processes
	for (dbg::ProcessInfo info : dbg::getProcesses()) {
		if (info.name() == processName) {
			auto p = ::getProc(info.pid());
			obj = p->getSharedObject();
		}
	}

	// Return a Hijacker instance if the SharedObject is found, otherwise nullptr
	return obj ? new Hijacker(obj.release()) : nullptr;
}

// Get the main thread ID of the process
int Hijacker::getMainThreadId() {
	if (mainThreadId == -1) {
		// Iterate through the list of threads in the process
		for (dbg::ThreadInfo info : dbg::getThreads(obj->pid)) {
			StringView name = info.name();

			// Check if the thread name contains "Main" or "."
			if (name.contains("Main") || name.contains(".")) {
				// Set the main thread ID and break the loop
				mainThreadId = info.tid();
				break;
			}
		}
	}

	return mainThreadId;
}

// Get the TrapFrame of the main thread
UniquePtr<TrapFrame> Hijacker::getTrapFrame() {
	// Get the main thread ID
	int tid = getMainThreadId();

	auto p = ::getProc(obj->pid);
	if (p == nullptr) {
		return nullptr;
	}

	// Get the ThreadData for the main thread
	auto td = p->getThread(tid);
	if (td == nullptr) {
		return nullptr;
	}

	// Return the TrapFrame for the main thread
	return td->getFrame();
}

// Inline function to copy data from userspace to kernel memory
static inline void copyin(uintptr_t kdst, const void *src, size_t length) {
	kernel_copyin(const_cast<void *>(src), kdst, length);
}

// Jailbreak the process
void Hijacker::jailbreak() const {
	auto p = getProc();

	// Get the ucred and fd addresses
	uintptr_t ucred = p->p_ucred();
	uintptr_t fd = p->p_fd();

	// Allocate memory for storing the root vnode area
	UniquePtr<uint8_t[]> rootvnode_area_store{new uint8_t[0x100]};

	// Copy the root vnode area from kernel memory to userspace
	kernel_copyout(kernel_base + offsets::root_vnode(), rootvnode_area_store.get(), 0x100);

	uint32_t uid_store = 0;
	uint32_t ngroups_store = 0;
	uint64_t authid_store = 0x4801000000000013l;
	int64_t caps_store = -1;
	uint8_t attr_store[] = {0x80, 0, 0, 0, 0, 0, 0, 0};

	// Copy data into specific addresses in userspace

	// Copy uid values to userspace
	copyin(ucred + 0x04, &uid_store, 0x4);		  // cr_uid
	copyin(ucred + 0x08, &uid_store, 0x4);		  // cr_ruid
	copyin(ucred + 0x0C, &uid_store, 0x4);		  // cr_svuid
	copyin(ucred + 0x10, &ngroups_store, 0x4);	  // cr_ngroups
	copyin(ucred + 0x14, &uid_store, 0x4);		  // cr_rgid

	// Escape sandbox by setting root directory and jail directory
	copyin(fd + 0x10, rootvnode_area_store.get(), 0x8);  // fd_rdir
	copyin(fd + 0x18, rootvnode_area_store.get(), 0x8);  // fd_jdir

	// Escalate Sony privileges
	copyin(ucred + 0x58, &authid_store, 0x8);	 // cr_sceAuthID
	copyin(ucred + 0x60, &caps_store, 0x8);		 // cr_sceCaps[0]
	copyin(ucred + 0x68, &caps_store, 0x8);		 // cr_sceCaps[1]
	copyin(ucred + 0x83, attr_store, 0x1);		 // cr_sceAttr[0]
}

// Get the address of a function in a shared library using the NID
uintptr_t Hijacker::getFunctionAddress(SharedLib *lib, const Nid &fname) const {
	RtldMeta *meta = lib->getMetaData();
	rtld::ElfSymbol sym = meta->getSymbolTable()[fname];

	#ifdef DEBUG
	// Check if the symbol exists (debug mode)
	if (!sym) [[unlikely]] {
		fatalf("failed to get symbol for %s %s\n", lib->getPath().c_str(), fname.str);
	}
	#endif

	// Return the virtual address of the symbol, or 0 if it doesn't exist
	return sym ? sym.vaddr() : 0;
}
