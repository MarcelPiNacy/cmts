/*
	BSD 2-Clause License
	
	Copyright (c) 2020, Marcel Pi Nacy
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice, this
	   list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation
	   and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/



#pragma once
#include "cmts.h"
#include <cstdint>

namespace cmts
{
	using function_pointer_t = void(*)(void*);
	
	enum class fence_t : cmts_fence_t
	{
		nil = (uint32_t)-1
	};

	enum class counter_t : cmts_counter_t
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



	inline counter_t new_counter(const uint32_t start_value)
	{
		return static_cast<counter_t>(cmts_new_counter(start_value));
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
		cmts_dispatch_with_counter(task_function, param, static_cast<uint8_t>(priority_level), static_cast<cmts_counter_t>(counter));
	}



	constexpr uint32_t max_tasks()
	{
		return CMTS_MAX_TASKS;
	}

	inline uint32_t processor_count()
	{
		return cmts_processor_count();
	}

}