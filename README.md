# CMTS
```cpp
#include <cstdio>
#include <cmts.h>

static void task_main(void* unused)
{
    printf("\"Hello, World!\" - Worker Thread #%u", cmts_this_worker_thread_index());
    cmts_finalize_signal(); // Begin library cleanup
}

int main(int argc, char** argv)
{
    cmts_init(NULL);
    cmts_dispatch(task_main, NULL);
    cmts_finalize_await(NULL); // Wait for all worker threads to finish.
    return 0;
}

#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
## Overview
CMTS is a C++ 17 header-only library with a C API that implements a lock-free scheduler for cooperative multitasking.
## Quick Setup
#### Including the source code
Like any other header-only library, you don't have to compile+include+link CMTS. `cmts.h` itself contains the source code `#ifdef`'d behind the flag `CMTS_IMPLEMENTATION`:
```cpp
#define CMTS_IMPLEMENTATION
#include <cmts.h>
```
To avoid mistakes this snippet should ideally be in its own .cpp file.
## Platform Support
#### Operating System
Currently only Windows (8 and over) is supported. Support for other OS will be added once the library is sufficiently complete.
#### Compiler Support
MSVC (with the /GT option on release builds) is the only supported compiler for now, mostly due to how TLS optimizations in other compilers assume no stack switching.