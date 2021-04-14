# CMTS
```cpp
#include <cstdio>
#include <cmts.h>

static void task_main(void* unused)
{
    printf("\"Hello, World!\" - Worker Thread #%u", cmts_this_worker_thread_index());
    cmts_finalize_signal();
}

int main(int argc, char** argv)
{
    cmts_init(NULL);
    cmts_dispatch(task_main, NULL);
    cmts_finalize_await(NULL);
    return 0;
}

#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
## Overview
CMTS is a standalone C++ cooperative task scheduler with a C API*, based on Christian Gyrling's 2015 GDC talk.  
<sub>_* A C++ API is included separately._</sub>
### Quick Setup
##### Including the source code
CMTS is a header-only library, so you don't have to compile+include+link CMTS. `cmts.h` itself contains the source code `#ifdef`'d behind the flag `CMTS_IMPLEMENTATION`:
```cpp
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
To avoid mistakes this snippet should ideally be in its own .cpp file.
### Platform Support
##### Operating System
Currently only Windows (8 and over) is supported. Support for other OS will be added later.
##### Compiler Support
MSVC (with the /GT option on release builds) is the only supported compiler right now, mostly due to how TLS optimizations in other compilers assume no stack switching.
### Library Architecture
CMTS can be conceptually split into three parts:
- Worker Threads
- Task Pool
- Synchronization Primitives
##### Worker Threads
Each worker thread has its own MPSC concurrent queue. By randomly selecting a target worker thread, tasks can be submitted with lower contention than if a single global queue was used.
##### Task Pool
The task pool essentially boils down to a global object pool based on a concurrent stack + freelist.
While better than using a mutex, the pool's lock-free freelist is a major source of contention and will be replaced by another approach in the future.
##### Synchronization Primitives
CMTS implements the following synchronization objects:
- Mutexes
- Fences
- Events
- Counters
###### Mutexes  (`cmts_mutex_t`, `cmts::sync::mutex`)
Just a plain old mutex. However, like all other CMTS synchronization primitives, they can only be used within a task (with some minor exceptions).
###### Fences (`cmts_fence_t`, `cmts::sync::fence`)
Fences are the most lightweight primitive in the library.
Their use cases are limited in comparison to events and counters, since they are essentially a container for a single sleeping task.
Fences are useful mainly when implementing parallel for-loops.
###### Events (`cmts_event_t`, `cmts::sync::event`)
Events allow for 1 or more tasks to wait until a condition holds true.
Like condition variables, events are conceptually a queue (or list) of sleeping tasks.
Events can be attached to a task, which will signal the event once it runs to completion.
###### Counters (`cmts_counter_t`, `cmts::sync::counter`)
Like events, counters hold tasks that are waiting for a particular condition, in this case the counter's value reaching zero. Counters can also be attached to tasks.
