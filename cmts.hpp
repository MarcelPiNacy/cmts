#pragma once
#include "cmts.h"
#include <cstdint>

namespace cmts
{
	using function_pointer_t = void(*)(void*);
	
	enum class fence_t : uint32_t
	{
		nil = (uint32_t)-1
	};

	enum class counter_t : uint32_t
	{
		nil = (uint32_t)-1
	};

	enum class priority_level_t : uint8_t
	{
		high,
		medium,
		low,
		lowest
	};

	// Initializes CMTS with the specified maximum number of tasks
	inline void initialize(const uint32_t max_tasks)
	{
		cmts_initialize(max_tasks);
	}

	// Tells CMTS to finish execution: all threads will finish once all running tasks either yield or exit.
	inline void signal_finalize()
	{
		cmts_signal_finalize();
	}

	// Waits for all CMTS threads to exit and returns allocated memory to the OS.
	inline void finalize()
	{
		cmts_finalize();
	}

	// Terminates all CMTS threads and calls cmts_finalize.
	inline void terminate()
	{
		cmts_terminate();
	}

	// Returns whether CMTS is running.
	inline bool is_running()
	{
		cmts_is_running();
	}

	// Submits a task to CMTS.
	inline void dispatch(const function_pointer_t task_function, void* param, const priority_level_t priority_level)
	{
		cmts_dispatch(task_function, param, static_cast<uint8_t>(priority_level));
	}

	// Halts execution of the current task.
	inline void yield()
	{
		cmts_yield();
	}

	// Finishes execution of the current task.
	inline void exit()
	{
		cmts_exit();
	}



	inline fence_t new_fence()
	{
		return static_cast<fence_t>(cmts_new_fence());
	}

	inline void signal_fence(const fence_t fence)
	{
		cmts_signal_fence(static_cast<cmts_fence_t>(fence));
	}

	inline void await(const fence_t fence)
	{
		cmts_await_fence(static_cast<cmts_fence_t>(fence));
	}

	inline void await_and_delete(const fence_t fence)
	{
		cmts_await_fence_and_delete(static_cast<cmts_fence_t>(fence));
	}

	inline void delete_fence(const fence_t fence)
	{
		cmts_delete_fence(static_cast<cmts_fence_t>(fence));
	}



	inline counter_t new_counter()
	{
		return static_cast<counter_t>(cmts_new_counter());
	}

	inline void increment(const counter_t counter)
	{
		cmts_increment_counter(static_cast<cmts_counter_t>(counter));
	}

	inline void decrement(const counter_t counter)
	{
		cmts_increment_counter(static_cast<cmts_counter_t>(counter));
	}

	inline void await(const counter_t counter)
	{
		cmts_await_counter(static_cast<cmts_counter_t>(counter));
	}

	inline void await_and_delete(const counter_t counter)
	{
		cmts_await_counter_and_delete(static_cast<cmts_counter_t>(counter));
	}

	inline void delete_counter(const counter_t counter)
	{
		cmts_delete_counter(static_cast<cmts_counter_t>(counter));
	}



	inline void dispatch(const function_pointer_t task_function, void* param, const priority_level_t priority_level, const fence_t fence)
	{
		cmts_dispatch_with_fence(task_function, param, static_cast<uint8_t>(priority_level), static_cast<cmts_fence_t>(fence));
	}

	inline void dispatch(const function_pointer_t task_function, void* param, const priority_level_t priority_level, const counter_t counter)
	{
		cmts_dispatch_with_fence(task_function, param, static_cast<uint8_t>(priority_level), static_cast<cmts_counter_t>(counter));
	}



	inline uint32_t max_tasks()
	{
		return cmts_max_tasks();
	}

	inline uint32_t processor_count()
	{
		return cmts_processor_count();
	}

}