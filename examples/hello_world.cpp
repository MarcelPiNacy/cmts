#include <cstdio>
#include <cmts.h>
#include <cassert>

void task_main(void* unused)
{
	puts("Hello, world!");
	cmts_signal_finalize();
}

int main()
{
	assert(cmts_init(nullptr) == CMTS_SUCCESS);
	assert(cmts_dispatch(task_main, nullptr) == CMTS_SUCCESS);
	assert(cmts_finalize(nullptr) == CMTS_SUCCESS);
	return 0;
}

// Ideally, this should be in its own .CPP file:
#define CMTS_IMPLEMENTATION
#include <cmts.h>