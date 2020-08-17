# cmts
## Overview
cmts is a C++ header-only library for cooperative multitasking.
#### Features
- cmts relies on a lock-free ring buffer for queue operations that minimizes false sharing by performing a bitwise rotate on the head and tail indices.
- All the necessary data structures are allocated all at once at startup, with the exceptions of the fiber stacks.
#### Using cmts in your projects
Like other C/C++ header-only libraries, you can just include cmts.h anywhere in your project, provided that you have also defined CMTS_INCLUDE_IMPLEMENTATION *once* and then included the header in a .cpp file.
#### Configuring
###### At runtime
###### At compile-time
cmts can be configured by defining the following macros:
- CMTS_CALLING_CONVENTION: The calling convention to use inside cmts. By default this value is left blank.
- CMTS_QUEUE_PRIORITY_COUNT: By default, cmts allocates 4 queues. This value must not exceed 256.
- CMTS_DEBUG: If defined, enables asserts and other run time checks. Enabled by default if _DEBUG is defined or NDEBUG is undefined.
## Benchmarks
## Acknowledgements