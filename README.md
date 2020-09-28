# cmts
## About
cmts is a C++11 header-only library with a C-compatible API that implements a scheduler for cooperative multitasking.
## Usage
#### Adding cmts to your project
Like other C/C++ header-only libraries, you must explicitly include the cmts source code by defining `CMTS_IMPLEMENTATION` and then including `cmts.h`:
```cpp
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
This step must only be done *once* per project and preferably in its own separate .cpp source file. You can use a plain `#include <cmts.h>` everywhere else.
#### Library initialization
To initialize cmts you must call `cmts_init`, with either `nullptr` or a pointer to a `cmts_init_options_t` struct. If `nullptr` is passed, cmts will:
- Launch as many worker threads as CPU cores.
- Lock threads to cores with affinity.
- Set the size of the task, fence and counter pools to 256 * `cmts_thread_count()`.
- Set the worker thread stack size to 2^21.
- Set the task stack size to 2^16.
#### Launching tasks
The easiest way to submit a task to the cmts scheduler is by calling `cmts_dispatch` with a valid function pointer and `nullptr`.
However, you will not be able to wait for the task to finish
#### Library cleanup
When you are done using cmts, you must first call `cmts_signal_finalize()`.
This will signal to the worker threads to exit once they are done executing their current task. Then, you must call `cmts_finalize()`, which will block until all worker threads have quit.
If you need to forcibly terminate all cmts threads, you should call `cmts_terminate()`.
## Configuring
#### At runtime
Currently, cmts can only be configured at runtime during initialization with `cmts_init` and `cmts_init_options_t`.
#### At compile-time
You can configure cmts through the following macros:
- `CMTS_DEBUG`: If defined, enables asserts and other run time checks. Enabled by default if `_DEBUG` is defined and `NDEBUG` is not.
- `CMTS_EXPECTED_CACHE_LINE_SIZE`: Specifies the expected size of the L1 cache line size. Used to align several thread-shared data structures to minimize or eliminate false sharing.
- `CMTS_MAX_PRIORITY`: By default, cmts only allocates 3 queues. This value must not exceed 256.
- `CMTS_CALLING_CONVENTION`: Sets the calling convention of all library functions, with the exception of the fiber and thread entry points on Windows platforms.
## Example code
```cpp
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
    for (int i = 0; i < 10; ++i)
        cmts_dispatch_with_counter(increment, (void*)i, 0, counter);
    cmts_await_counter_and_delete(counter);
    cmts_signal_finalize();
}

int main()
{
    cmts_init(nullptr);
    cmts_dispatch(entry, nullptr);
    cmts_finalize();
}
```