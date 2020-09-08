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

#ifndef CMTS_HEADER_INCLUDED
#define CMTS_HEADER_INCLUDED

#include <stdint.h>

#ifndef CMTS_QUEUE_PRIORITY_COUNT
#define CMTS_QUEUE_PRIORITY_COUNT 4
#endif

#if CMTS_QUEUE_PRIORITY_COUNT > 256
#error "Error, CMTS_QUEUE_PRIORITY_COUNT must not exceed 256"
#endif

#ifndef CMTS_TASK_STACK_SIZE
#define CMTS_TASK_STACK_SIZE 65536
#endif

#ifndef CMTS_CALLING_CONVENTION
#define CMTS_CALLING_CONVENTION
#endif

#ifdef __cplusplus
typedef bool cmts_boolean_t;
#else
typedef _Bool cmts_boolean_t;
#endif

typedef void(*cmts_function_pointer_t)(void*);
typedef uint64_t cmts_fence_t;
typedef uint64_t cmts_counter_t;

#ifdef CMTS_MAX_TASKS
#error "Error, attempted to redefine CMTS_MAX_TASKS."
#endif

#ifdef CMTS_NIL_COUNTER
#error "Error, attempted to redefine CMTS_NIL_COUNTER."
#endif

#ifdef CMTS_NIL_FENCE
#error "Error, attempted to redefine CMTS_NIL_FENCE."
#endif

#define CMTS_MAX_TASKS ((uint32_t)(1U << 24U))

#define CMTS_NIL_COUNTER (~(uint32_t)0)
#define CMTS_NIL_FENCE (~(uint32_t)0)

#ifdef __cplusplus
extern "C"
{
#endif

	/*
		Initializes the library.
		Parameters:
			- max_tasks specifies the maximum number of tasks.
			- max_cpus specifies the number of CPU cores to use.
		Notes:
			- The library currently locks worker threads to CPU cores using affinity, meaning that cores 0 - max_cpus will always be used.
			- Currently, the memory buffer used by most data structures in cmts can only be allocated using the operating system's allocator (VirtualAlloc/mmap).
	*/
	void CMTS_CALLING_CONVENTION cmts_initialize(uint32_t max_tasks, uint32_t max_cpus);

	/*
		Suspends all worker threads.
	*/
	void CMTS_CALLING_CONVENTION cmts_break();

	/*
		Resumes all worker threads.
	*/
	void CMTS_CALLING_CONVENTION cmts_resume();

	/*
		Signals to all worker threads to exit once they reach an idle state.
		Notes:
			- Calling this function from inside a task will not cause the current worker thread to immediately exit.
	*/
	void CMTS_CALLING_CONVENTION cmts_signal_finalize();

	/*
		Waits for all worker threads to finish, then deallocates the internal memory buffer.
	*/
	void CMTS_CALLING_CONVENTION cmts_finalize();

	/*
		Terminates all worker threads and deallocates the internal memory buffer.
	*/
	void CMTS_CALLING_CONVENTION cmts_terminate();

	/*
		Returns true if called from inside a task.
	*/
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task();

	/*
		Returns whether the library is initialized.
	*/
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_running();

	/*
		Submits a task to the corresponding queue.
		Parameters:
			- task_function: Specifies the entry point of the task.
			- param: Specifies the parameter that will be passed to task_function.
			- priority_level: Specifies the target queue.
	*/
	void CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t task_function, void* param, uint8_t priority_level);

	/*
		Suspend execution of the current task, which is then pushed to the end of its corresponding queue.
	*/
	void CMTS_CALLING_CONVENTION cmts_yield();

	/*
		Finishes execution of the current task.
	*/
	void CMTS_CALLING_CONVENTION cmts_exit();

	/*
		Returns a handle to a fence object. A fence is used for waiting for a single task to finish through cmts_await_fence or cmts_await_fence_and_delete.
	*/
	cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence();

	/*
		Returns whether the specified fence handle has expired.
	*/
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence);

	/*
		Sets the fence object's internal value to true.
	*/
	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence);

	/*
		Puts the current task to sleep until the specified fence is signaled.
	*/
	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence);

	/*
		Puts the current task to sleep until the specified fence is signaled. Once the task is resumed, the fence object is deleted.
	*/
	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence);

	/*
		Deletes the specified fence object.
	*/
	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence);

	/*
		Returns a handle to a counter object. A counter is used for waiting for multiple tasks to finish through cmts_await_counter or cmts_await_counter_and_delete.
		Internally, a counter object owns a 32-bit atomic variable that is decremented every time that an associated task finishes. Once this variable reaches zero, all waiting tasks are pushed to their corresponding queues.
		Parameters:
			- start_value: Sets the counter's internal value.
	*/
	cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value);

	/*
		Returns whether the specified counter handle has expired.
	*/
	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter);

	/*
		Sets the counter object's internal value.
	*/
	void CMTS_CALLING_CONVENTION cmts_set_counter(cmts_counter_t counter, uint32_t value);

	/*
		Increments the counter object's internal value.
	*/
	void CMTS_CALLING_CONVENTION cmts_increment_counter(cmts_counter_t counter);

	/*
		Decrements the counter object's internal value.
	*/
	void CMTS_CALLING_CONVENTION cmts_decrement_counter(cmts_counter_t counter);

	/*
		Puts the current task to sleep until the specified counter reaches zero.
	*/
	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter);

	/*
		Puts the current task to sleep until the specified counter's value reaches zero. Once the task is resumed, the counter object is deleted.
	*/
	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter);

	/*
		Deletes the specified counter object.
	*/
	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter);

	/*
		Submits a task to the corresponding queue with an associated fence.
		Parameters:
			- task_function: Specifies the entry point of the task.
			- param: Specifies the parameter that will be passed to task_function.
			- priority_level: Specifies the target queue.
			- fence: A valid handle to a fence object.
	*/
	void CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence);

	/*
		Submits a task to the corresponding queue with an associated counter.
		Parameters:
			- task_function: Specifies the entry point of the task.
			- param: Specifies the parameter that will be passed to task_function.
			- priority_level: Specifies the target queue.
			- counter: A valid handle to a counter object.
	*/
	void CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter);

	/*
		Returns the id of the current task.
	*/
	uint32_t CMTS_CALLING_CONVENTION cmts_current_task_id();

	/*
		Returns the current CPU core index.
	*/
	uint32_t CMTS_CALLING_CONVENTION cmts_current_cpu();

	/*
		Return the number of CPU cores used by cmts.
	*/
	uint32_t CMTS_CALLING_CONVENTION cmts_used_cpu_count();

	/*
		Return the number of available CPU cores.
	*/
	uint32_t CMTS_CALLING_CONVENTION cmts_available_cpu_count();

#ifdef __cplusplus
}
#endif

#ifdef CMTS_IMPLEMENTATION
#include "cmts_windows.cpp"
#endif

#endif //CMTS_HEADER_INCLUDED