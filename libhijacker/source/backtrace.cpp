#include "backtrace.hpp"

// Declaration of the function `getFramePointer()`
const Frame * __attribute__((naked)) getFramePointer() {
    // Inline assembly code using AT&T syntax
    __asm__ volatile(
        "push %rbp\n"   // Push the value of the base pointer onto the stack
        "pop %rax\n"    // Pop the value from the stack into the return register
        "ret\n"         // Return from the function
    );
}

// Declaration of the external function `puts()`
extern "C" int puts(const char*);

// Definition of the function `getTextStart()`
static uintptr_t __attribute__((naked, noinline)) getTextStart() {
    asm volatile(
        "lea __text_start(%rip), %rax\n"    // Load the address of __text_start into the return register
        "ret\n"                             // Return from the function
    );
}

// Definition of the function `getTextEnd()`
static uintptr_t __attribute__((naked, noinline)) getTextEnd() {
    asm volatile(
        "lea __text_stop(%rip), %rax\n"     // Load the address of __text_stop into the return register
        "ret\n"                             // Return from the function
    );
}

// Definition of the function `printBacktrace()`
void printBacktrace() {
    const uintptr_t start = getTextStart();   // Get the start address of the text section
    const uintptr_t stop = getTextEnd();      // Get the end address of the text section

    // Print the start address of the text section
    __builtin_printf(".text: 0x%08llx\n", start);

    // Print backtrace header
    puts("---backtrace start---");

    // Iterate over the frames of the backtrace
	for (const Frame *__restrict frame = getFramePointer(); frame != nullptr; frame = frame->next) {
		if (frame->addr != 0) [[likely]] {
			if (frame->addr >= start && frame->addr <= stop) {
				__builtin_printf("0x%llx\n", frame->addr - start);
			}
		}
	}
	puts("---backtrace end---");
}
