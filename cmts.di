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

module cmts;
nothrow:
@nogc:

enum : uint
{
	CMTS_MAX_TASKS		= 1U << 24U,
	CMTS_NIL_HANDLE		= uint.max,
	CMTS_NIL_COUNTER	= CMTS_NIL_HANDLE,
	CMTS_NIL_FENCE		= CMTS_NIL_HANDLE,
}

alias cmts_function_pointer = void function(void*);
alias cmts_allocate_function_pointer = void* function(size_t);
alias cmts_deallocate_function_pointer = void function(void*, size_t);
alias cmts_handle = ulong;
alias cmts_fence = cmts_handle;
alias cmts_counter = cmts_handle;

struct cmts_allocation_callbacks
{
	cmts_allocate_function_pointer allocate;
	cmts_deallocate_function_pointer deallocate;
}

struct cmts_init_options
{
	uint max_tasks;
	uint max_threads;
	uint thread_stack_size;
	uint task_stack_size;
	union
	{
		uint first_core;
		uint* cpu_indices;
	}
	cmts_allocation_callbacks* allocator;
	bool use_affinity;
	bool use_manual_affinity;
}

enum cmts_synchronization_type : ubyte
{
	CMTS_SYNCHRONIZATION_TYPE_NONE,
	CMTS_SYNCHRONIZATION_TYPE_FENCE,
	CMTS_SYNCHRONIZATION_TYPE_COUNTER,
	CMTS_SYNCHRONIZATION_TYPE_MAX_ENUM,
}

struct cmts_dispatch_options
{
	void* parameter;
	cmts_handle sync_object;
	cmts_synchronization_type synchronization_type;
	ubyte priority;
}

extern (C)
{
	bool cmts_init(const(cmts_init_options)* options);
	bool cmts_break();
	bool cmts_continue();
	bool cmts_signal_finalize();
	void cmts_finalize();
	bool cmts_terminate();
	bool cmts_is_initialized();
	bool cmts_is_task();
	bool cmts_is_running();
	bool cmts_dispatch(cmts_function_pointer task_function, const(cmts_dispatch_options)* options);
	void cmts_yield();
	void cmts_exit();
	cmts_fence cmts_new_fence();
	bool cmts_is_fence_valid(cmts_fence fence);
	void cmts_signal_fence(cmts_fence fence);
	void cmts_await_fence(cmts_fence fence);
	void cmts_await_fence_and_delete(cmts_fence fence);
	void cmts_delete_fence(cmts_fence fence);
	cmts_counter cmts_new_counter(uint start_value);
	bool cmts_is_counter_valid(cmts_counter counter);
	void cmts_await_counter(cmts_counter counter);
	void cmts_await_counter_and_delete(cmts_counter counter);
	void cmts_delete_counter(cmts_counter counter);
	bool cmts_dispatch_with_fence(cmts_function_pointer task_function, void* param, ubyte priority_level, cmts_fence fence);
	bool cmts_dispatch_with_counter(cmts_function_pointer task_function, void* param, ubyte priority_level, cmts_counter counter);
	uint cmts_current_task_id();
	uint cmts_worker_thread_index();
	uint cmts_thread_count();
	uint cmts_available_cpu_count();
}