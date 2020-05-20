#pragma once
#include <cstdint>

typedef void(*cmts_function_pointer_t)(void*);
#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif
typedef uint32_t cmts_task_t;
typedef uint32_t cmts_fence_t;
typedef uint32_t cmts_counter_t;

enum
{
	CMTS_MAX_TASKS = 65536 * 256
};

extern "C"
{

	// Initializes CMTS with the specified maximum number of tasks
	void			cmts_initialize(uint32_t max_tasks);

	// Tells CMTS to finish execution: all threads will finish once all running tasks either yield or exit.
	void			cmts_signal_finalize();

	// Waits for all CMTS threads to exit and returns allocated memory to the OS.
	void			cmts_finalize();

	// Terminates all CMTS threads and calls cmts_finalize.
	void			cmts_terminate();

	// Returns whether CMTS is running.
	bool			cmts_is_running();

	// Submits a task to CMTS.
	void			cmts_dispatch(cmts_function_pointer_t task_function, void* param, uint8_t priority_level);

	// Halts execution of the current task.
	void			cmts_yield();

	// Finishes execution of the current task.
	void			cmts_exit();



	cmts_fence_t	cmts_new_fence();

	void			cmts_signal_fence(cmts_fence_t fence);

	void			cmts_await_fence(cmts_fence_t fence);

	void			cmts_await_fence_and_delete(cmts_fence_t fence);

	void			cmts_delete_fence(cmts_fence_t fence);



	cmts_counter_t	cmts_new_counter(uint32_t start_value);

	void			cmts_increment_counter(cmts_counter_t counter);

	void			cmts_decrement_counter(cmts_counter_t counter);

	void			cmts_await_counter(cmts_counter_t counter);

	void			cmts_await_counter_and_delete(cmts_counter_t counter);

	void			cmts_delete_counter(cmts_counter_t counter);



	void			cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);

	void			cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);



	uint32_t		cmts_processor_index();

	uint32_t		cmts_current_task_id();

	uint32_t		cmts_processor_count();

}