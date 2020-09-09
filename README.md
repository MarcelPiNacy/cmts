# cmts
## Overview
cmts is a C++ header-only library for cooperative multitasking.
#### Features
- The library relies on a lock-free ring buffer for queue operations that minimizes false sharing through a bitwise rotate on the read and write indices.
- All data structures are allocated at once at startup, with the exception of the fiber stacks.
- The library doesn't use exceptions and its API is compatible with C.
#### Usage
Like other C/C++ header-only libraries, you can `#include cmts.h` anywhere in your project, as long as you add the following *once*:
```C++
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
To begin using cmts, you must first call cmts_initialize, with the maximum number of tasks and CPU cores to use.
Once you are done using the library you must call cmts_signal_finalize, which will cause all worker threads to exit once they reach an idle state, followed by cmts_finalize, which will free the internal memory buffer.
#### Configuring
###### At runtime
Currently, cmts can only be configured at runtime using cmts_initialize, where you can specify the maximum number of tasks and CPU cores to use.
###### At compile-time
You can configure cmts by defining the following macros:
- CMTS_DEBUG: If defined, enables asserts and other run time checks. If _DEBUG is defined or NDEBUG is not defined it is enabled by default.
- CMTS_TASK_STACK_SIZE: Specifies the fiber stack size (64KiB by default).
- CMTS_QUEUE_PRIORITY_COUNT: By default, cmts only allocates 4 queues. This value must not exceed 256.
- CMTS_CALLING_CONVENTION: Sets the calling convention of all functions, except the fiber and thread entry point on Windows.
#### Example Code
```C++
#include <atomic>
#define CMTS_IMPLEMENTATION
#include <cmts.h>

std::atomic<size_t> counter;

void increment(void* index)
{
    counter.fetch_add((size_t)index, std::memory_order_release);
}

void entry(void* unused)
{
    auto counter = cmts_new_counter(10);
    for (size_t i = 0; i < 10; ++i)
        cmts_dispatch_with_counter(increment, (void*)i, 0, counter);
    cmts_await_counter_and_delete(counter);
    cmts_signal_finalize();
}

int main()
{
    auto ncpus = cmts_available_cpu_count();
    cmts_initialize(ncpus * 256, ncpus);
    cmts_dispatch(entry, nullptr, 0);
    cmts_finalize();
}
```
#### Issues
 - There is currently a bug that may lead to random crashes.
 - cmts can't be significantly configured at runtime. In the near future cmts_initialize will be subtituted by cmts_init, which will expect an optional pointer to a configuration struct.