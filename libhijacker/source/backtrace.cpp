#include "backtrace.hpp"

// Function to retrieve the frame pointer of the current function
const Frame * __attribute__((naked)) getFramePointer() {
	__asm__ volatile(
		"push %rbp\n"   // Save the value of the rbp register by pushing it onto the stack
		"pop %rax\n"    // Move the value from the stack to the rax register
		"ret\n"         // Return from the function
	);
}

// Declaration of the external function 'puts'
extern "C" int puts(const char*);

// Function to get the start address of the text segment (code)
static uintptr_t __attribute__((naked, noinline)) getTextStart() {
	asm volatile(
		"lea __text_start(%rip), %rax\n"   // Load the address of the symbol '__text_start' into rax
		"ret\n"                            // Return from the function
	);
}

// Function to get the end address of the text segment (code)
static uintptr_t __attribute__((naked, noinline)) getTextEnd() {
	asm volatile(
		"lea __text_stop(%rip), %rax\n"    // Load the address of the symbol '__text_stop' into rax
		"ret\n"                            // Return from the function
	);
}

// Function to print the backtrace
void printBacktrace() {
	const uintptr_t start = getTextStart();   // Get the start address of the text segment
	const uintptr_t stop = getTextEnd();      // Get the end address of the text segment
	__builtin_printf(".text: 0x%08llx\n", start);   // Print the start address

	puts("---backtrace start---");

	// Loop through the call frames
	for (const Frame *__restrict frame = getFramePointer(); frame != nullptr; frame = frame->next) {
		if (frame->addr != 0) [[likely]] {   // Check if the frame address is not zero
			if (frame->addr >= start && frame->addr <= stop) {   // Check if the frame address is within the text segment
				__builtin_printf("0x%llx\n", frame->addr - start);   // Print the relative address within the text segment
			}
		}
	}

	puts("---backtrace end---");
}
