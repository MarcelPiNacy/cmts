# CMTS
CMTS is a header-only cooperative task scheduling library, based on Christian Gyrling's 2015 GDC talk.  
The core library is written in C, with a C++17 API available in a separate file.
### Example Code
```cpp
#include <cstdio>
#include <cmts.h>

static void task_main(void* unused)
{
    printf("\"Hello, World!\" - Worker Thread #%u", cmts_this_worker_thread_index());
    cmts_finalize_signal();
}

int main()
{
    cmts_init(NULL);
    cmts_dispatch(task_main, NULL);
    cmts_finalize_await(NULL);
    return 0;
}

// This should ideally be in its own source file:
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
### Implementation Details
#### Overview
![image](https://github.com/MarcelPiNacy/cmts/blob/master/overview.svg)  
On startup, CMTS will launch the specified number of worker threads and lock them to the corresponding CPU core.
Each thread keeps up to `CMTS_MAX_PRIORITY` (3 by default) wait-free MPSC task queues.
On task submission, a worker thread is chosen randomly and the index of the task is pushed to the corresponding queue.
Unless CMTS_NO_BUSY_WAIT is defined, threads will spin while there are no tasks to run.

#### Synchronization
CMTS implements the following synchronization primitives:

- Fence:  
  - Effectively a binary semaphore that can only hold one task.
    - `cmts_fence`, `CMTS::Fence`
- Events
  - A binary semaphore (pop-all only).
    - `cmts_event`, `CMTS::Event`
- Counters
  - A counting semaphore (pop-all only).
    - `cmts_counter`, `CMTS::Counter`
- Mutexes
  - Etc...
    - `cmts_mutex`, `CMTS::Mutex`

#### More implementation notes:
- Currently, worker threads use a variant of Daniel Bittman's excellent MPSC wait-free queue: https://github.com/dbittman/waitfree-mpsc-queue
- When pushing a task, the PRNG used to select a target worker thread is RomuDuoJr. It is reseeded every 2<sup>32</sup> ns with the CSPRNG of the target OS.
- The maximum size of the task pool is 2<sup>32</sup> - 1 to avoid the cost of 16-byte atomic operations.
### C++17 API Example
```cpp
#include <cstdio>
#include <cmts.hpp>

static void task_main(void* unused)
{
    printf("\"Hello, World!\" - Worker Thread #%u", CMTS::WorkerThreadIndex());
    CMTS::FinalizeSignal();
}

int main()
{
    CMTS::Init();
    CMTS::Dispatch(task_main);
    CMTS::FinalizeAwait();
}

// This should ideally be in its own source file:
#define CMTS_IMPLEMENTATION
#define CMTS_CPP_IMPLEMENTATION
#include <cmts.hpp>
```
