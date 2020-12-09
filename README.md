# CMTS
## About
CMTS is a C++14/17 header-only library with a C-compatible API that implements a lock-free scheduler for cooperative multitasking.
## Warning
The library is work in progress. You should only use code from the release branch (and there's no release branch yet).
#### Operating System
Right now, only Windows (8 and over) is supported.
#### Compiler Support
MSVC is the only supported compiler for now. CMTS has not yet been tested on Clang and GCC, but it might work. However, it is extremely likely to cause crashes at runtime in release builds due to the task stacks being moved across threads.
To avoid this in release builds, you should enable the equivalent of MSVC's "Enable Fiber-Safe Optimizations" if your compiler supports it. In the future, a workaround will be supported via a macro.
## Usage
#### Adding CMTS to your project
Like other C/C++ header-only libraries, you must explicitly include the CMTS source code by defining `CMTS_IMPLEMENTATION` and then including `cmts.h`:
```cpp
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
This step must only be done *once* per project and preferably in its own separate .cpp source file. You can use a plain `#include <cmts.h>` everywhere else.
#### Library initialization
To initialize CMTS you must call `cmts_init`, with either `nullptr` or a pointer to a `cmts_init_options_t` struct. If `nullptr` is passed, the library will:
- Launch as many worker threads as CPU cores.
- Lock worker threads to CPU cores with affinity.
- Set the capacity of the task, fence and counter pools to 128 * CPU core count.
- Set the task and worker thread stack size to 2^16.
#### Launching tasks
The easiest way to submit a task to the CMTS scheduler is by calling `cmts_dispatch` with a valid function pointer and `nullptr`.
However, this way doesn't let you specify the function parameter and the scheduling priority. More importantly, it also doesn't let you wait for the task to finish.
By passing a pointer to a `cmts_dispatch_options_t` struct, you can do all of that.
#### Library cleanup
When you are done using CMTS, you must first call `cmts_signal_finalize()`.
This will signal to the worker threads to exit once they are done executing their current task. Then, you must call `cmts_finalize()`, which will block until all worker threads have quit.
If you need to forcibly terminate all CMTS threads, you should call `cmts_terminate()`.
## Configuring
#### At runtime
Currently, CMTS can only be configured at runtime during initialization and cleanup.
#### At compile-time
You can configure CMTS through the following macros:
- `CMTS_DEBUG`: If defined, enables asserts and other run time checks. Enabled by default if `_DEBUG` is defined and `NDEBUG` is not.
- `CMTS_FALSE_SHARING_THRESHOLD`: Specifies the expected size of the L1 cache line size. Used to align several thread-shared data structures to eliminate false sharing. By default, set to 64 if C++ 17 is not supported. Otherwise, the `<new>` header is included by the implementation and std::hardware_destructive_interference_size is used. (Note: some versions of MSVC incorrectly set the macro __cplusplus to the value of the C++98 standard. To fix that, use the "/Zc:__cplusplus" compiler switch.).
- `CMTS_DISABLE_QUEUE_FALSE_SHARING_COMPENSATION`: If defined, disables false sharing compensation by the scheduler queues. By default, the head and tail indices are modified to try to access only one element every cache line.
- `CMTS_MAX_PRIORITY`: Specifies the number of task queues, 3 by default. This value must not exceed 256.
- `CMTS_CALLING_CONVENTION`: Sets the calling convention of all library functions, with the exception of the fiber and thread functions on Windows platforms.
- `CMTS_NO_BUSY_WAIT`: If defined, the worker threads sleep while there are no tasks to run. Since this is implemented on Windows using WaitOnAddress/WakeByAddressSingle, either `Synchronization.lib` or `API-MS-Win-Core-Synch-l1-2-0.dll` must be linked.
## Examples
##### Hello World
```cpp
#include <cstdio>
#include <cmts.h>

void task_main(void* unused /* This will be nullptr */)
{
    printf("Worker thread #%i says:\nHello, World!", cmts_thread_index());

    // Signal to the scheduler's worker threads to quit.
    cmts_signal_finalize();
}

int main()
{
    // Initialize the scheduler with as many worker threads as CPU cores, and lock them with affinity.
    cmts_init(nullptr);

    // Launch task with task_main as its entry point.
    cmts_dispatch(task_main, nullptr);

    //Await worker threads.
    cmts_finalize(nullptr);
}

//Include implementation. This should be in its own .CPP file:
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
