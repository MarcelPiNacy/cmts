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

#ifndef CMTS_INCLUDED
#define CMTS_INCLUDED

#include <stdint.h>

typedef void(*cmts_function_pointer_t)(void*);
typedef uint64_t cmts_fence_t;
typedef uint64_t cmts_counter_t;

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

enum
{
	CMTS_MAX_TASKS = 1 << 24
};

#ifdef __cplusplus
extern "C"
{
#endif

	void			cmts_initialize(uint32_t max_tasks, uint32_t max_cpus);
	void			cmts_halt();
	void			cmts_resume();
	void			cmts_signal_finalize();
	void			cmts_finalize();
	void			cmts_terminate();
	cmts_boolean_t	cmts_is_running();
	void			cmts_dispatch(cmts_function_pointer_t task_function, void* param, uint8_t priority_level);
	void			cmts_yield();
	void			cmts_exit();

	cmts_fence_t	cmts_new_fence();
	cmts_boolean_t	cmts_is_fence_valid(cmts_fence_t fence);
	void			cmts_signal_fence(cmts_fence_t fence);
	void			cmts_await_fence(cmts_fence_t fence);
	void			cmts_await_fence_and_delete(cmts_fence_t fence);
	void			cmts_delete_fence(cmts_fence_t fence);

	cmts_counter_t	cmts_new_counter(uint32_t start_value);
	cmts_boolean_t	cmts_is_counter_valid(cmts_counter_t counter);
	void			cmts_increment_counter(cmts_counter_t counter);
	void			cmts_decrement_counter(cmts_counter_t counter);
	void			cmts_await_counter(cmts_counter_t counter);
	void			cmts_await_counter_and_delete(cmts_counter_t counter);
	void			cmts_delete_counter(cmts_counter_t counter);

	void			cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);
	void			cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);

	uint32_t		cmts_current_task_id();
	uint32_t		cmts_current_cpu();
	uint32_t		cmts_used_cpu_count();
	uint32_t		cmts_available_cpu_count();

#ifdef __cplusplus
}
#endif

#ifdef CMTS_IMPLEMENTATION_WINDOWS
#include "cmts_windows.inl"
#endif

#endif //CMTS_INCLUDED