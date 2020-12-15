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


#include <cmts.h>
#include <atomic>

#if (defined(DEBUG) || defined(_DEBUG) || !defined(NDEBUG)) && !defined(CMTS_DEBUG)
#define CMTS_DEBUG
#endif

#ifdef _WIN32
#define CMTS_OS_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define NOMINMAX
#include <Windows.h>
#define CMTS_OS_ALLOCATE(size) VirtualAlloc(nullptr, (size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
#error "CMTS: Unsupported operating system."
#endif

#ifdef __clang__

#if defined(__arm__) || defined(__aarch64__)
#define CMTS_YIELD_CPU __yield()
#elif defined(__i386__) || defined(__x86_64__)
#include <intrin.h>
#define CMTS_YIELD_CPU _mm_pause()
#else
#error "UNSUPPORTED PROCESSOR ARCHITECTURE"
#endif
#define CMTS_EXPECT(expression, value) __builtin_expect((expression), (value))
#define CMTS_ASSUME(expression) __builtin_assume((expression))
#define CMTS_UNREACHABLE __builtin_unreachable()
#define CMTS_ALLOCA(size) __builtin_alloca((size))
#define CMTS_POPCOUNT(value) __builtin_popcount((value))
#define CMTS_UNSIGNED_LOG2(value) __builtin_ffs((value))
#define CMTS_ROTATE_LEFT32(mask, count) _rotl((mask), (count))
#define CMTS_ROTATE_LEFT64(mask, count) _rotl64((mask), (count))
#define CMTS_ROTATE_RIGHT32(mask, count) _rotr((mask), (count))
#define CMTS_ROTATE_RIGHT64(mask, count) _rotr64((mask), (count))
#ifdef CMTS_DEBUG
#define CMTS_UNREACHABLE __builtin_trap()
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER __attribute__((noinline))
#else
#define CMTS_UNREACHABLE __builtin_unreachable()
#define CMTS_INLINE_ALWAYS __attribute__((always_inline))
#define CMTS_INLINE_NEVER __attribute__((noinline))
#endif
#elif defined(_MSC_VER) || defined(_MSVC_LANG)
#if defined(_M_ARM) || defined(_M_ARM64)
#define CMTS_YIELD_CPU __yield()
#elif defined(_M_IX86) || defined(_M_AMD64)
#include <intrin.h>
#define CMTS_YIELD_CPU _mm_pause()
#else
#error "UNSUPPORTED PROCESSOR ARCHITECTURE"
#endif
#define CMTS_EXPECT(expression, value) (expression)
#define CMTS_ASSUME(expression) __assume((expression))
#define CMTS_ALLOCA(size) _alloca((size))
#define CMTS_POPCOUNT(value) __popcnt((value))
#define CMTS_UNSIGNED_LOG2(value) _tzcnt_u32((value))
#define CMTS_ROTATE_LEFT32(mask, count) _rotl((mask), (count))
#define CMTS_ROTATE_LEFT64(mask, count) _rotl64((mask), (count))
#define CMTS_ROTATE_RIGHT32(mask, count) _rotr((mask), (count))
#define CMTS_ROTATE_RIGHT64(mask, count) _rotr64((mask), (count))
#define CMTS_TERMINATE __fastfail(7)
#ifdef CMTS_DEBUG
#define CMTS_UNREACHABLE CMTS_TERMINATE; CMTS_ASSUME(0)
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER __declspec(noinline)
#else
#define CMTS_UNREACHABLE CMTS_ASSUME(0)
#define CMTS_INLINE_ALWAYS __forceinline
#define CMTS_INLINE_NEVER __declspec(noinline)
#endif
#else
#error "cmts: UNSUPPORTED COMPILER";
#endif

#define CMTS_LIKELY_IF(expression) if (CMTS_EXPECT(expression, true))
#define CMTS_UNLIKELY_IF(expression) if (CMTS_EXPECT(expression, false))

#ifdef __cplusplus
#if __cplusplus >= 201703L
#define USING_STD_CACHE_LINE
#include <new> // => hardware_constructive_interference_size / hardware_destructive_interference_size
#endif
#endif

#ifdef USING_STD_CACHE_LINE
static constexpr bool CMTS_CALLING_CONVENTION static_is_power_of_2(size_t value) CMTS_NOTHROW
{
	uint8_t r = 0;
	while (value)
	{
		r += (uint8_t)(value & 1);
		value >>= 1;
	}
	return r == 1;
}

static_assert(static_is_power_of_2(CMTS_FALSE_SHARING_THRESHOLD), "CMTS_FALSE_SHARING_THRESHOLD must be a power of two.");
#endif

#define CMTS_FLOOR_TO_ALIGNMENT(value, alignment)	((value) & ~((alignment) - 1))
#define CMTS_ROUND_TO_ALIGNMENT(value, alignment)	(((value) + ((alignment) - 1)) & ~((alignment) - 1))

#ifdef CMTS_DEBUG
#include <cassert>
#define CMTS_ASSERT(expression) assert(expression)
#define CMTS_ASSERT_IMPURE(expression) assert(expression)
#define CMTS_ASSERT_IS_TASK CMTS_ASSERT(get_root_task() != nullptr)
#define CMTS_ASSERT_IS_INITIALIZED CMTS_ASSERT(threads_ptr != nullptr)
#else
#define CMTS_ASSERT(expression) CMTS_ASSUME(expression)
#define CMTS_ASSERT_IMPURE(expression) (void)(expression);
#define CMTS_ASSERT_IS_TASK
#define CMTS_ASSERT_IS_INITIALIZED
#endif

enum : uint_fast32_t
{
	CMTS_UINT24_MAX = (1U << 24U) - 1U,
	CMTS_DEFAULT_TASK_STACK_SIZE = 1U << 16U,
	CMTS_DEFAULT_THREAD_STACK_SIZE = 1U << 16U,
	CMTS_GENERATION_MASK = (1U << 31U) - 1U
};

alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<bool> is_paused;
alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<bool> should_continue;



#ifndef USING_STD_CACHE_LINE
static uint_fast8_t							queue_shift;
static uint_fast8_t							queue_shift_mask;
#else

static constexpr uint_fast8_t				queue_shift = []() CMTS_NOTHROW
{
	switch (CMTS_FALSE_SHARING_THRESHOLD)
	{
#if UINTPTR_MAX == UINT32_MAX
	case 4:		return 2:
#endif
	case 8:		return 3;
	case 16:	return 4;
	case 32:	return 5;
	case 64:	return 6;
	case 128:	return 7;
	case 256:	return 8;
	default:	return 0;
	}
}();

static constexpr uint_fast8_t				queue_shift_mask = CMTS_FALSE_SHARING_THRESHOLD - 1;

static_assert(queue_shift != 0, "std::hardware_destructive_interference_size was defined to an invalid value.");

#endif

#ifdef CMTS_NO_BUSY_WAIT
static decltype(WaitOnAddress)*				futex_await;
static decltype(WakeByAddressAll)*			futex_signal;
#endif

static uint_fast32_t						task_stack_size;
static uint_fast32_t						max_tasks;
static uint_fast32_t						worker_thread_count;
static uint_fast8_t							queue_capacity_log2;
static uint_fast32_t						queue_capacity_mask;
static HANDLE*								threads_ptr;



#ifndef CMTS_TLS_WORKAROUND
static thread_local HANDLE					root_task;
static thread_local uint_fast32_t			current_task;
static thread_local uint_fast32_t			worker_thread_index;
static thread_local uint_fast32_t			local_reserved_indices[CMTS_MAX_PRIORITY];

static CMTS_INLINE_ALWAYS HANDLE CMTS_CALLING_CONVENTION get_root_task() CMTS_NOTHROW
{
	return root_task;
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_root_task(HANDLE value) CMTS_NOTHROW
{
	root_task = value;
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_current_task() CMTS_NOTHROW
{
	return current_task;
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_current_task(uint_fast32_t value) CMTS_NOTHROW
{
	current_task = value;
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_worker_thread_index() CMTS_NOTHROW
{
	return worker_thread_index;
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_worker_thread_index(uint_fast32_t value) CMTS_NOTHROW
{
	worker_thread_index = value;
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION init_local_queue_indices() CMTS_NOTHROW
{
	(void)memset(local_reserved_indices, 0xff, sizeof(local_reserved_indices));
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_queue_local_index(uint_fast32_t index) CMTS_NOTHROW
{
	return local_reserved_indices[index];
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_queue_local_index(uint_fast32_t index, uint_fast32_t value) CMTS_NOTHROW
{
	local_reserved_indices[index] = value;
}

#else

static HANDLE*			root_tasks_ptr;
static uint_fast32_t*	current_tasks_ptr;
static uint_fast32_t*	local_reserved_indices_ptr[CMTS_MAX_PRIORITY];

static CMTS_INLINE_ALWAYS size_t tls_workaround_required_size(uint_fast32_t core_count) CMTS_NOTHROW
{
	size_t r = 0;
	r += sizeof(HANDLE) * core_count;
	r += sizeof(uint_fast32_t) * core_count;
	r += sizeof(uint_fast32_t) * core_count * CMTS_MAX_PRIORITY;
	return r;
}

static CMTS_INLINE_ALWAYS void init_tls_workaround(uint_fast32_t core_count, uint8_t* memory) CMTS_NOTHROW
{
	root_tasks_ptr = (HANDLE*)memory;
	memory += sizeof(HANDLE) * core_count;
	current_tasks_ptr = (uint_fast32_t*)memory;
	memory += sizeof(uint_fast32_t) * core_count;

	const uint_fast32_t k = sizeof(uint_fast32_t) * core_count;

	for (uint_fast32_t i = 0; i != CMTS_MAX_PRIORITY; ++i)
	{
		local_reserved_indices_ptr[i] = (uint_fast32_t*)memory;
		memset(local_reserved_indices_ptr[i], 0xff, k);
		memory += k;
	}
}

static constexpr void CMTS_CALLING_CONVENTION set_worker_thread_index(uint_fast32_t value) CMTS_NOTHROW
{
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_worker_thread_index() CMTS_NOTHROW
{
	return cmts_cpu_core_index();
}

static CMTS_INLINE_ALWAYS HANDLE CMTS_CALLING_CONVENTION get_root_task() CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	return root_tasks_ptr[core];
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_root_task(HANDLE value) CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	root_tasks_ptr[core] = value;
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_current_task() CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	return current_tasks_ptr[core];
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_current_task(uint_fast32_t value) CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	current_tasks_ptr[core] = value;
}

static constexpr void CMTS_CALLING_CONVENTION init_local_queue_indices() CMTS_NOTHROW
{
}

static CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION get_queue_local_index(uint_fast32_t index) CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	return local_reserved_indices_ptr[index][core];
}

static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION set_queue_local_index(uint_fast32_t index, uint_fast32_t value) CMTS_NOTHROW
{
	const uint_fast32_t core = get_worker_thread_index();
	local_reserved_indices_ptr[index][core] = value;
}
#endif



#ifndef USING_STD_CACHE_LINE
CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION load_cache_line_info() CMTS_NOTHROW
{
	DWORD k = 0;

#ifdef CMTS_DEBUG
	(void)GetLogicalProcessorInformation(nullptr, &k);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* const buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)CMTS_ALLOCA(k);
	const bool flag = GetLogicalProcessorInformation(buffer, &k);
	CMTS_ASSERT(flag);
#else
	(void)GetLogicalProcessorInformation(nullptr, &k);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* const buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)CMTS_ALLOCA(k);
	(void)GetLogicalProcessorInformation(buffer, &k);
#endif

	for (uint_fast32_t i = 0; i != k; ++i)
	{
		if (buffer[i].Relationship == RelationCache)
		{
			if (buffer[i].Cache.Level == 1)
			{
				const uint_fast32_t cls = buffer[i].Cache.LineSize;
				CMTS_ASSERT(cls != 0);
				const uint_fast32_t u32log2 = CMTS_UNSIGNED_LOG2(sizeof(std::atomic<uint32_t>));
				queue_shift = CMTS_UNSIGNED_LOG2(cls) - u32log2;
				queue_shift_mask = (cls >> u32log2) - 1;
				return;
			}
		}
	}
	CMTS_UNREACHABLE;
}
#endif

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION conditionally_exit_thread() CMTS_NOTHROW
{
	CMTS_UNLIKELY_IF(!should_continue.load(std::memory_order_acquire))
	{
		ExitThread(0);
		CMTS_UNREACHABLE;
	}
}

template <typename T>
CMTS_INLINE_ALWAYS static T CMTS_CALLING_CONVENTION non_atomic_load(const std::atomic<T>& from) CMTS_NOTHROW
{
	return *(const T*)&from;
}

template <typename T, typename U = T>
CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION non_atomic_store(std::atomic<T>& where, U value) CMTS_NOTHROW
{
	*(T*)&where = value;
}

struct alignas(uint64_t) pool_control_block
{
	uint64_t
		freelist : 24,
		size : 24,
		generation : 16;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		freelist = CMTS_UINT24_MAX;
		size = 0;
		generation = 0;
	}
};

struct alignas(uint64_t) wait_list_control_block
{
	uint32_t head;
	uint32_t generation;
};

struct alignas(CMTS_FALSE_SHARING_THRESHOLD / 2) task_state
{
	HANDLE					handle;
	cmts_function_pointer_t	function;
	void*					parameter;
	cmts_handle_t			sync_handle;
	uint32_t				wait_next;
	uint8_t					priority;
	uint8_t					sync_type;
	bool					sleeping;

	uint32_t				lock_next;
	uint32_t				pool_next;
	uint32_t				generation;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		function = nullptr;
		parameter = nullptr;
		pool_next = CMTS_UINT24_MAX;
	}
};

struct alignas(CMTS_FALSE_SHARING_THRESHOLD) fence_state
{
	struct alignas(uint32_t) control_block
	{
		uint32_t
			flag : 1,
			generation : 31;
	};

	std::atomic<control_block> ctrl;
	uint32_t pool_next;
	std::atomic<wait_list_control_block> wait_list;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		non_atomic_store(ctrl, {});
		pool_next = CMTS_UINT24_MAX;
		non_atomic_store(wait_list, { (uint32_t)CMTS_NIL_HANDLE, 0 });
	}

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION is_done() CMTS_NOTHROW
	{
		return !ctrl.load(std::memory_order_acquire).flag;
	}

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION signal(uint_fast32_t generation) CMTS_NOTHROW
	{
		control_block c, nc;
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();

			c = ctrl.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(!c.flag || c.generation != generation)
				return false;
			nc.flag = false;
			nc.generation = generation + 1;
			CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				return true;
			CMTS_YIELD_CPU;
		}
	}
};

struct alignas(CMTS_FALSE_SHARING_THRESHOLD) counter_state
{
	struct alignas(uint64_t) control_block
	{
		uint32_t counter;
		uint32_t generation;
	};

	std::atomic<control_block> ctrl;
	uint32_t pool_next;
	std::atomic<wait_list_control_block> wait_list;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		non_atomic_store(ctrl, {});
		pool_next = CMTS_UINT24_MAX;
		non_atomic_store(wait_list, { (uint32_t)CMTS_NIL_HANDLE, 0 });
	}

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION is_done() CMTS_NOTHROW
	{
		return ctrl.load(std::memory_order_acquire).counter == 0;
	}

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION decrement(uint_fast32_t generation) CMTS_NOTHROW
	{
		control_block c, nc;
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();

			c = ctrl.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(c.counter == 0 || c.generation != generation)
				return false;
			nc.counter = c.counter - 1;
			const bool r = nc.counter == 0;
			nc.generation = generation + (uint_fast32_t)r;
			CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				return r;
			CMTS_YIELD_CPU;
		}
	}
};

struct alignas(CMTS_FALSE_SHARING_THRESHOLD) cmts_shared_queue_state
{
	static constexpr size_t ENTRY_SIZE = sizeof(std::atomic<uint32_t>);

	alignas(CMTS_FALSE_SHARING_THRESHOLD) std::atomic<uint_fast32_t> head;
	alignas(CMTS_FALSE_SHARING_THRESHOLD) std::atomic<uint_fast32_t> tail;
	std::atomic<uint32_t>* values;

	CMTS_INLINE_ALWAYS void initialize(void* const buffer)
	{
		values = (std::atomic<uint32_t>*)buffer;
		const size_t k = ENTRY_SIZE * (queue_capacity_mask + 1U);
		(void)memset(buffer, 0xff, k);
	}
};

template <typename T>
CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION shared_pool_acquire(std::atomic<pool_control_block>& ctrl, T* const elements) CMTS_NOTHROW
{
	uint_fast32_t r;
	pool_control_block c, nc;
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		c = ctrl.load(std::memory_order_acquire);
		CMTS_LIKELY_IF(c.freelist != CMTS_UINT24_MAX)
		{
			r = c.freelist;
			CMTS_ASSERT((r < CMTS_UINT24_MAX) && (r < max_tasks));
			nc.freelist = elements[r].pool_next;
			nc.size = c.size;
		}
		else
		{
			CMTS_UNLIKELY_IF(c.size == max_tasks)
				return (uint32_t)CMTS_NIL_HANDLE;
			r = c.size;
			CMTS_ASSERT(r < CMTS_UINT24_MAX && r < max_tasks);
			nc.freelist = CMTS_UINT24_MAX;
			nc.size = c.size + 1;
		}
		nc.generation = c.generation + 1;
		CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
			return r;
		CMTS_YIELD_CPU;
	}
}

template <typename T>
CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION shared_pool_release(std::atomic<pool_control_block>& ctrl, T* const elements, uint_fast32_t index) CMTS_NOTHROW
{
	CMTS_ASSERT(index < CMTS_MAX_TASKS);
	CMTS_ASSERT(index < max_tasks);
	pool_control_block c, nc;
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		c = ctrl.load(std::memory_order_acquire);
		elements[index].pool_next = c.freelist;
		nc.freelist = index;
		nc.size = c.size;
		nc.generation = c.generation + 1;
		CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
			break;
		CMTS_YIELD_CPU;
	}
}

static task_state*																task_pool_ptr;
static fence_state*																fence_pool_ptr;
static counter_state*															counter_pool_ptr;

alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<pool_control_block>	task_pool_ctrl;
alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<pool_control_block>	fence_pool_ctrl;
alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<pool_control_block>	counter_pool_ctrl;
alignas(CMTS_FALSE_SHARING_THRESHOLD) static cmts_shared_queue_state			queues[CMTS_MAX_PRIORITY];

#ifdef CMTS_NO_BUSY_WAIT
alignas(CMTS_FALSE_SHARING_THRESHOLD) static std::atomic<uint32_t>				scheduler_generation;
#endif

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_wait_list(std::atomic<wait_list_control_block>& ctrl) CMTS_NOTHROW
{
	wait_list_control_block c, nc;
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		c = ctrl.load(std::memory_order_acquire);
		CMTS_UNLIKELY_IF(c.head == (uint32_t)CMTS_NIL_HANDLE)
			return (uint32_t)CMTS_NIL_HANDLE;
		CMTS_ASSERT(c.head < CMTS_MAX_TASKS);
		CMTS_ASSERT(c.head < max_tasks);
		nc.head = task_pool_ptr[c.head].wait_next;
		nc.generation = c.generation;
		CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
			return c.head;
		CMTS_YIELD_CPU;
	}
	CMTS_UNREACHABLE;
}

CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION try_append_wait_list(std::atomic<wait_list_control_block>& ctrl, const uint_fast32_t index) CMTS_NOTHROW
{
	wait_list_control_block c, nc;
	c = ctrl.load(std::memory_order_acquire);
	nc.head = index;
	task_pool_ptr[index].wait_next = c.head;
	nc.generation = c.generation + 1;
	return ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed);
}

template <typename T>
CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION append_wait_list(T& state, uint_fast32_t task_index) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
		{
			conditionally_exit_thread();
		}

		CMTS_UNLIKELY_IF(state.is_done())
		{
			return false;
		}
		
		CMTS_LIKELY_IF(try_append_wait_list(state.wait_list, task_index))
		{
			return true;
		}

		CMTS_YIELD_CPU;
	}
	CMTS_UNREACHABLE;
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION adjust_queue_index(uint_fast32_t index) CMTS_NOTHROW
{
	uint_fast32_t r;
#ifdef CMTS_DISABLE_QUEUE_FALSE_SHARING_COMPENSATION
	r = index;
#else
	// Rotate index bits to minimize the chance that multiple threads modify the same cache line.
	const uint_fast32_t low = (index >> queue_shift) & queue_shift_mask;
	const uint_fast32_t high = index << queue_shift;
	r = high | low;
#endif
	return r & queue_capacity_mask;
}

CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION submit_to_queue(const uint_fast32_t task_index, const uint8_t priority) CMTS_NOTHROW
{
	CMTS_ASSERT(priority < CMTS_MAX_PRIORITY);

	cmts_shared_queue_state& q = queues[priority];
	const uint_fast32_t k = (uint_fast32_t)q.head.fetch_add(1, std::memory_order_acquire);
	const uint_fast32_t index = adjust_queue_index(k);
	std::atomic<uint32_t>& e = q.values[index];
	for (uint_fast8_t i = 0;; ++i)
	{
		uint_fast32_t empty = UINT32_MAX;

		while ((non_atomic_load(e) != empty) & non_atomic_load(should_continue))
		{
			CMTS_YIELD_CPU;
		}
		
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
		{
			conditionally_exit_thread();
		}

		CMTS_LIKELY_IF(e.load(std::memory_order_acquire) == empty)
		{
			CMTS_LIKELY_IF(e.compare_exchange_weak(empty, task_index, std::memory_order_release, std::memory_order_relaxed))
			{
				break;
			}
		}
	}

#ifdef CMTS_NO_BUSY_WAIT
	(void)scheduler_generation.fetch_add(1, std::memory_order_release);
	futex_signal(&scheduler_generation);
#endif
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_from_queue() CMTS_NOTHROW
{
	while (true)
	{
#ifdef CMTS_NO_BUSY_WAIT
		uint32_t last_generation = scheduler_generation.load(std::memory_order_acquire);
#endif

		for (uint_fast32_t i = 0; i != CMTS_MAX_PRIORITY; ++i)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			{
				conditionally_exit_thread();
			}

			cmts_shared_queue_state& q = queues[i];

			CMTS_LIKELY_IF(non_atomic_load(q.head) == non_atomic_load(q.tail))
			{
				continue;
			}

			CMTS_LIKELY_IF(get_queue_local_index(i) == UINT32_MAX)
			{
				set_queue_local_index(i, q.tail.fetch_add(1, std::memory_order_acquire));
			}

			std::atomic<uint32_t>& e = q.values[adjust_queue_index(get_queue_local_index(i))];

			const uint_fast32_t max_retries = 1 << (CMTS_MAX_PRIORITY - i);

			for (uint_fast32_t j = 0; j < max_retries; ++j)
			{
				uint_fast32_t expected = e.load(std::memory_order_acquire);
				CMTS_LIKELY_IF(expected != UINT32_MAX)
				{
					CMTS_LIKELY_IF(e.compare_exchange_weak(expected, UINT32_MAX, std::memory_order_release, std::memory_order_relaxed))
					{
						set_queue_local_index(i, UINT32_MAX);
						return expected;
					}
				}
				CMTS_YIELD_CPU;
			}
		}

#ifdef CMTS_NO_BUSY_WAIT
		futex_await(&scheduler_generation, &last_generation, sizeof(last_generation), INFINITE);
#endif
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION fence_wake_tasks(const uint_fast32_t fence_index) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		const uint_fast32_t i = fetch_wait_list(fence_pool_ptr[fence_index].wait_list);
		CMTS_UNLIKELY_IF(i == (uint32_t)CMTS_NIL_HANDLE)
			break;
		task_pool_ptr[i].sleeping = false;
		submit_to_queue(i, task_pool_ptr[i].priority);
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION counter_wake_tasks(const uint_fast32_t counter_index) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		const uint_fast32_t i = fetch_wait_list(counter_pool_ptr[counter_index].wait_list);
		CMTS_UNLIKELY_IF(i == (uint32_t)CMTS_NIL_HANDLE)
			break;
		task_state& e = task_pool_ptr[i];
		CMTS_ASSERT(e.sleeping);
		e.sleeping = false;
		submit_to_queue(i, task_pool_ptr[i].priority);
	}
}

static void WINAPI task_main(void* param) CMTS_NOTHROW
{
	CMTS_ASSERT(param != nullptr);
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		CMTS_ASSERT_IMPURE(get_current_task() < CMTS_MAX_TASKS);
		CMTS_ASSERT_IMPURE(get_current_task() < max_tasks);
		task_state& state = task_pool_ptr[get_current_task()];
		CMTS_ASSERT(state.function != nullptr);
		state.function(state.parameter);
		state.function = nullptr;
		SwitchToFiber(get_root_task());
	}
}

static DWORD WINAPI thread_main(void* param) CMTS_NOTHROW
{
	set_worker_thread_index((uint_fast32_t)(size_t)param);
	set_root_task(ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH));
	
	CMTS_ASSERT_IMPURE(get_root_task() != nullptr);

	init_local_queue_indices();

	while (true)
	{
		set_current_task(fetch_from_queue());

		CMTS_ASSERT_IMPURE(get_current_task() < CMTS_MAX_TASKS);
		CMTS_ASSERT_IMPURE(get_current_task() < max_tasks);

		task_state& f = task_pool_ptr[get_current_task()];

		CMTS_ASSERT(f.function != nullptr);
		CMTS_ASSERT(f.handle != nullptr);

		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();

		SwitchToFiber(f.handle);

		if (f.function != nullptr)
		{
			CMTS_LIKELY_IF(!f.sleeping)
			{
				submit_to_queue(get_current_task(), f.priority);
			}
		}
		else
		{
			const uint_fast8_t sync_type = f.sync_type;
			const uint_fast32_t sync_index = (uint32_t)f.sync_handle;
			const uint_fast32_t sync_generation = (uint32_t)(f.sync_handle >> 32);
			switch (sync_type)
			{
			case CMTS_SYNC_TYPE_NONE:
				break;
			case CMTS_SYNC_TYPE_FENCE:
				CMTS_LIKELY_IF(!fence_pool_ptr[sync_index].signal(sync_generation))
					fence_wake_tasks(sync_index);
				break;
			case CMTS_SYNC_TYPE_COUNTER:
				CMTS_UNLIKELY_IF(counter_pool_ptr[sync_index].decrement(sync_generation))
					counter_wake_tasks(sync_index);
				break;
			default:
				CMTS_UNREACHABLE;
			}

			shared_pool_release(task_pool_ctrl, task_pool_ptr, get_current_task());
		}
	}
	CMTS_UNREACHABLE;
}

static cmts_result_t CMTS_CALLING_CONVENTION custom_library_init(const cmts_init_options_t* options) CMTS_NOTHROW
{
	CMTS_UNLIKELY_IF(options->max_tasks > CMTS_MAX_TASKS || options->task_stack_size == 0 || options->max_threads == 0 || CMTS_POPCOUNT(options->max_tasks) != 1 || options->max_tasks == 0)
		return CMTS_ERROR_INVALID_PARAMETER;

	task_stack_size = options->task_stack_size;
	worker_thread_count = options->max_threads;
	max_tasks = options->max_tasks;
	queue_capacity_log2 = CMTS_UNSIGNED_LOG2(max_tasks);
	queue_capacity_mask = max_tasks - 1;

	const size_t queue_buffer_size = max_tasks * cmts_shared_queue_state::ENTRY_SIZE;
	const size_t buffer_threads_size = CMTS_ROUND_TO_ALIGNMENT(worker_thread_count * sizeof(HANDLE), CMTS_FALSE_SHARING_THRESHOLD);
	const size_t buffer_queues_size = queue_buffer_size * CMTS_MAX_PRIORITY;
	const size_t buffer_pools_size = max_tasks * (sizeof(task_state) + sizeof(fence_state) + sizeof(counter_state));

	size_t buffer_size = 0;
	buffer_size += buffer_threads_size;
	buffer_size += buffer_queues_size;
	buffer_size += buffer_pools_size;

#ifdef CMTS_TLS_WORKAROUND
	CMTS_UNLIKELY_IF(!options->use_affinity)
		return CMTS_ERROR_AFFINITY_IS_REQUIRED;
	const size_t wrs = tls_workaround_required_size(worker_thread_count);
	buffer_size += wrs;
#endif

	uint8_t* internal_buffer = (uint8_t*)CMTS_OS_ALLOCATE(buffer_size);
	CMTS_UNLIKELY_IF(internal_buffer == nullptr)
		return CMTS_ERROR_MEMORY_ALLOCATION_FAILURE;

#ifdef CMTS_TLS_WORKAROUND
	init_tls_workaround(worker_thread_count, internal_buffer);
	internal_buffer += wrs;
#endif

	threads_ptr = (HANDLE*)internal_buffer;
	internal_buffer += buffer_threads_size;
	task_pool_ptr = (task_state*)internal_buffer;
	internal_buffer += sizeof(task_state) * max_tasks;
	fence_pool_ptr = (fence_state*)internal_buffer;
	internal_buffer += sizeof(fence_state) * max_tasks;
	counter_pool_ptr = (counter_state*)internal_buffer;
	internal_buffer += sizeof(counter_state) * max_tasks;

	(*(pool_control_block*)&task_pool_ctrl).reset();
	(*(pool_control_block*)&fence_pool_ctrl).reset();
	(*(pool_control_block*)&counter_pool_ctrl).reset();

	for (uint_fast32_t i = 0; i != CMTS_MAX_PRIORITY; ++i)
	{
		queues[i].initialize(internal_buffer);
		internal_buffer += queue_buffer_size;
	}

	for (uint_fast32_t i = 0; i != max_tasks; ++i)
	{
		task_pool_ptr[i].reset();
		fence_pool_ptr[i].reset();
		counter_pool_ptr[i].reset();
	}

	CMTS_LIKELY_IF(options->use_affinity)
	{
		if (options->use_manual_affinity)
		{
			if (worker_thread_count <= 64)
			{
				for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
				{
					threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
					CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
						return CMTS_ERROR_THREAD_CREATION_FAILURE;
					CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)options->cpu_indices[i])) == 0)
						return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
					CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
						return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
				}
			}
			else
			{
				for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
				{
					threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
					CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
						return CMTS_ERROR_THREAD_CREATION_FAILURE;
					
					const uint32_t index = options->cpu_indices[i];
					GROUP_AFFINITY previous = {};
					GROUP_AFFINITY group = {};
					group.Group = index >> 6;
					group.Mask = (DWORD_PTR)1 << (DWORD_PTR)(index & 63U);

					CMTS_UNLIKELY_IF(SetThreadGroupAffinity(threads_ptr[i], &group, &previous) == 0)
						return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
					CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
						return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
				}
			}
		}
		else
		{
			if (worker_thread_count <= 64)
			{
				for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
				{
					threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
					CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
						return CMTS_ERROR_THREAD_CREATION_FAILURE;
					CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)i)) == 0)
						return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
					CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
						return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
				}
			}
			else
			{
				for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
				{
					threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
					CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
						return CMTS_ERROR_THREAD_CREATION_FAILURE;
					GROUP_AFFINITY previous = {};
					GROUP_AFFINITY group = {};
					group.Group = i >> 6;
					group.Mask = (DWORD_PTR)1 << (DWORD_PTR)(i & 63U);
					CMTS_UNLIKELY_IF(SetThreadGroupAffinity(threads_ptr[i], &group, &previous) == 0)
						return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
					CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
						return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
				}
			}
		}
	}
	else
	{
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			threads_ptr[i] = CreateThread(nullptr, CMTS_DEFAULT_THREAD_STACK_SIZE, thread_main, (void*)(size_t)i, 0, nullptr);
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return CMTS_ERROR_THREAD_CREATION_FAILURE;
		}
	}

	return CMTS_SUCCESS;
}

static cmts_result_t CMTS_CALLING_CONVENTION default_library_init() CMTS_NOTHROW
{
	const uint_fast32_t ncpus = cmts_cpu_core_count();

	task_stack_size = CMTS_DEFAULT_TASK_STACK_SIZE;
	worker_thread_count = ncpus;
	max_tasks = ncpus * 128;
	queue_capacity_log2 = CMTS_UNSIGNED_LOG2(max_tasks);
	queue_capacity_mask = max_tasks - 1;

	const size_t queue_buffer_size = max_tasks * cmts_shared_queue_state::ENTRY_SIZE;
	const size_t buffer_threads_size = CMTS_ROUND_TO_ALIGNMENT(worker_thread_count * sizeof(HANDLE), CMTS_FALSE_SHARING_THRESHOLD);
	const size_t buffer_queues_size = queue_buffer_size * CMTS_MAX_PRIORITY;
	const size_t buffer_pools_size = max_tasks * (sizeof(task_state) + sizeof(fence_state) + sizeof(counter_state));

	size_t buffer_size = 0;
	buffer_size += buffer_threads_size;
	buffer_size += buffer_queues_size;
	buffer_size += buffer_pools_size;

#ifdef CMTS_TLS_WORKAROUND
	const size_t wrs = tls_workaround_required_size(ncpus);
	buffer_size += wrs;
#endif

	uint8_t* internal_buffer = (uint8_t*)CMTS_OS_ALLOCATE(buffer_size);
	CMTS_UNLIKELY_IF(internal_buffer == nullptr)
		return CMTS_ERROR_MEMORY_ALLOCATION_FAILURE;

#ifdef CMTS_TLS_WORKAROUND
	init_tls_workaround(ncpus, internal_buffer);
	internal_buffer += wrs;
#endif

	threads_ptr = (HANDLE*)internal_buffer;
	internal_buffer += buffer_threads_size;
	task_pool_ptr = (task_state*)internal_buffer;
	internal_buffer += sizeof(task_state) * max_tasks;
	fence_pool_ptr = (fence_state*)internal_buffer;
	internal_buffer += sizeof(fence_state) * max_tasks;
	counter_pool_ptr = (counter_state*)internal_buffer;
	internal_buffer += sizeof(counter_state) * max_tasks;

	(*(pool_control_block*)&task_pool_ctrl).reset();
	(*(pool_control_block*)&fence_pool_ctrl).reset();
	(*(pool_control_block*)&counter_pool_ctrl).reset();

	for (uint_fast32_t i = 0; i != CMTS_MAX_PRIORITY; ++i)
	{
		queues[i].initialize(internal_buffer);
		internal_buffer += queue_buffer_size;
	}

	for (uint_fast32_t i = 0; i != max_tasks; ++i)
	{
		task_pool_ptr[i].reset();
		fence_pool_ptr[i].reset();
		counter_pool_ptr[i].reset();
	}

	if (worker_thread_count <= 64)
	{
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			threads_ptr[i] = CreateThread(nullptr, CMTS_DEFAULT_THREAD_STACK_SIZE, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return CMTS_ERROR_THREAD_CREATION_FAILURE;
			CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)i)) == 0)
				return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
			CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
				return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
		}
	}
	else
	{
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			threads_ptr[i] = CreateThread(nullptr, CMTS_DEFAULT_THREAD_STACK_SIZE, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return CMTS_ERROR_THREAD_CREATION_FAILURE;
			GROUP_AFFINITY previous = {};
			GROUP_AFFINITY group = {};
			group.Group = i >> 6;
			group.Mask = (DWORD_PTR)1 << (DWORD_PTR)(i & 63U);
			CMTS_UNLIKELY_IF(SetThreadGroupAffinity(threads_ptr[i], &group, &previous) == 0)
				return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
			CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
				return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
		}
	}

	return CMTS_SUCCESS;
}

#ifdef CMTS_NO_BUSY_WAIT
static bool CMTS_CALLING_CONVENTION enable_queue_futex() CMTS_NOTHROW
{
	HMODULE hmodule = GetModuleHandleA("Synchronization.lib");
	if (hmodule == nullptr)
		hmodule = GetModuleHandleA("API-MS-Win-Core-Synch-l1-2-0.dll");
	futex_await = (decltype(WaitOnAddress)*)GetProcAddress(hmodule, "WaitOnAddress");
	CMTS_UNLIKELY_IF(futex_await == nullptr)
		return false;
	futex_signal = (decltype(WakeByAddressAll)*)GetProcAddress(hmodule, "WakeByAddressAll");
	CMTS_UNLIKELY_IF(futex_signal == nullptr)
		return false;
	return true;
}
#endif



extern "C"
{

	cmts_result_t CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options)
	{
		CMTS_ASSERT(threads_ptr == nullptr);

		cmts_result_t r;
		non_atomic_store(should_continue, true);

#ifdef CMTS_NO_BUSY_WAIT
		if (futex_signal == nullptr)
		{
			CMTS_UNLIKELY_IF(!enable_queue_futex())
			{
				return CMTS_ERROR_FAILED_TO_ENABLE_FUTEXES;
			}
		}
#endif

#ifndef USING_STD_CACHE_LINE
		load_cache_line_info();
#endif

		if (options == nullptr)
			r = default_library_init();
		else
			r = custom_library_init(options);

		return r;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_break()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			CMTS_ASSERT(threads_ptr[i] != nullptr);
			CMTS_UNLIKELY_IF(SuspendThread(threads_ptr[i]) == MAXDWORD)
				return CMTS_ERROR_FAILED_TO_SUSPEND_WORKER_THREAD;
		}
		is_paused.store(true, std::memory_order_release);
		return CMTS_SUCCESS;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_continue()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			CMTS_ASSERT(threads_ptr[i] != nullptr);
			CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
				return CMTS_ERROR_FAILED_TO_RESUME_WORKER_THREAD;
		}
		is_paused.store(false, std::memory_order_release);
		return CMTS_SUCCESS;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_finalize()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		should_continue.store(false, std::memory_order_release);
#ifdef CMTS_NO_BUSY_WAIT
		(void)scheduler_generation.fetch_add(1, std::memory_order_acquire);
		futex_signal(&scheduler_generation);
#endif
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_finalize(cmts_deallocate_function_pointer_t deallocate)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const DWORD r = WaitForMultipleObjects(worker_thread_count, threads_ptr, true, INFINITE);
		CMTS_UNLIKELY_IF(r != WAIT_OBJECT_0)
			return CMTS_ERROR_FAILED_TO_AWAIT_WORKER_THREADS;

		if (deallocate == nullptr)
		{
			CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
				return CMTS_ERROR_MEMORY_DEALLOCATION_FAILURE;
		}
		else
		{
			const size_t queue_buffer_size = max_tasks * cmts_shared_queue_state::ENTRY_SIZE;
			const size_t buffer_size = (worker_thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(task_state) + sizeof(fence_state) + sizeof(counter_state)));
			CMTS_UNLIKELY_IF(!deallocate(threads_ptr, buffer_size))
				return CMTS_ERROR_MEMORY_DEALLOCATION_FAILURE;
		}

		threads_ptr = nullptr;
		return CMTS_SUCCESS;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_terminate(cmts_deallocate_function_pointer_t deallocate)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		cmts_signal_finalize();
		for (uint_fast32_t i = 0; i != worker_thread_count; ++i)
		{
			CMTS_ASSERT(threads_ptr[i] != nullptr);
			const DWORD r = TerminateThread(threads_ptr[i], MAXDWORD);
			CMTS_UNLIKELY_IF(r == 0)
				return CMTS_ERROR_FAILED_TO_TERMINATE_WORKER_THREAD;
		}

		if (deallocate == nullptr)
		{
			CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
				return CMTS_ERROR_MEMORY_DEALLOCATION_FAILURE;
		}
		else
		{
			const size_t queue_buffer_size = max_tasks * cmts_shared_queue_state::ENTRY_SIZE;
			const size_t buffer_size = (worker_thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(task_state) + sizeof(fence_state) + sizeof(counter_state)));
			CMTS_UNLIKELY_IF(!deallocate(threads_ptr, buffer_size))
				return CMTS_ERROR_MEMORY_DEALLOCATION_FAILURE;
		}

		threads_ptr = nullptr;
		return CMTS_SUCCESS;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return get_root_task() != nullptr;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_initialized()
	{
		return threads_ptr != nullptr;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_live()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return non_atomic_load(should_continue);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_paused()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return non_atomic_load(is_paused);
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t entry_point, const cmts_dispatch_options_t* options)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(entry_point != nullptr);
		const uint_fast32_t id = shared_pool_acquire(task_pool_ctrl, task_pool_ptr);
		CMTS_UNLIKELY_IF(id == (uint32_t)CMTS_NIL_HANDLE)
			return CMTS_DISPATCH_ERROR_TASK_POOL_LIMIT_REACHED;
		task_state& e = task_pool_ptr[id];
		++e.generation;
		e.generation &= CMTS_GENERATION_MASK;
		e.function = entry_point;
		if (options != nullptr)
		{
			CMTS_ASSERT(options->priority < CMTS_MAX_PRIORITY);
			CMTS_ASSERT(options->sync_type < CMTS_SYNC_TYPE_MAX_ENUM);
			e.parameter = options->parameter;
			e.priority = options->priority;
			e.sync_type = options->sync_type;
			e.sync_handle = options->sync_object;
			if (e.sync_type != CMTS_SYNC_TYPE_NONE)
			{
				const uint_fast32_t sync_generation = (uint_fast32_t)(options->sync_object >> 32);

				uint_fast32_t generation;

				if (e.sync_type == CMTS_SYNC_TYPE_FENCE)
				{
					generation = fence_pool_ptr[(uint32_t)e.sync_handle].ctrl.load(std::memory_order_acquire).generation;
				}
				else
				{
					generation = counter_pool_ptr[(uint32_t)e.sync_handle].ctrl.load(std::memory_order_acquire).generation;
				}

				CMTS_UNLIKELY_IF(sync_generation != generation)
				{
					shared_pool_release(task_pool_ctrl, task_pool_ptr, id);
					return CMTS_DISPATCH_ERROR_EXPIRED_SYNC_OBJECT;
				}
			}
		}
		else
		{
			e.parameter = nullptr;
			e.priority = 0;
			e.sync_type = CMTS_SYNC_TYPE_NONE;
		}
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)task_main, &e);
		CMTS_ASSERT(e.handle != nullptr);
		submit_to_queue(id, e.priority);
		return CMTS_SUCCESS;
	}

	void CMTS_CALLING_CONVENTION cmts_yield()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		SwitchToFiber(get_root_task());
	}

	void CMTS_CALLING_CONVENTION cmts_exit()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		task_pool_ptr[get_current_task()].function = nullptr;
		cmts_yield();
		CMTS_UNREACHABLE;
	}

	cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = shared_pool_acquire(fence_pool_ctrl, fence_pool_ptr);
		CMTS_UNLIKELY_IF(index == (uint32_t)CMTS_NIL_HANDLE)
			return (uint32_t)CMTS_NIL_HANDLE;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		fence_state& e = fence_pool_ptr[index];
		const fence_state::control_block c = non_atomic_load(e.ctrl);
		const fence_state::control_block nc = { true, (c.generation + 1U) & CMTS_GENERATION_MASK };
		non_atomic_store(e.ctrl, nc);
		return (cmts_fence_t)index | ((cmts_fence_t)nc.generation << 32);
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return CMTS_ERROR_INVALID_SYNC_OBJECT_HANDLE;
		return (cmts_result_t)(fence_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation == (uint32_t)(fence >> 32));
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(fence != (uint32_t)CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation != generation)
			return CMTS_ERROR_EXPIRED_SYNC_OBJECT;
		fence_wake_tasks(index);
		return CMTS_SUCCESS;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(fence != (uint32_t)CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation == generation)
			return CMTS_ERROR_EXPIRED_SYNC_OBJECT;
		shared_pool_release(fence_pool_ctrl, fence_pool_ptr, index);
		return CMTS_SUCCESS;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence, cmts_boolean_t delete_counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(fence != (uint32_t)CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation != generation)
			return CMTS_ERROR_EXPIRED_SYNC_OBJECT;
		CMTS_UNLIKELY_IF(!append_wait_list(fence_pool_ptr[index], get_current_task()))
			return CMTS_SYNC_OBJECT_EXPIRED;
		task_pool_ptr[get_current_task()].sleeping = true;
		cmts_yield();
		CMTS_LIKELY_IF(delete_counter)
		{
			fence_pool_ptr[index].reset();
			shared_pool_release(fence_pool_ctrl, fence_pool_ptr, index);
		}
		return CMTS_SUCCESS;
	}

	cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(start_value != 0);
		CMTS_ASSERT(start_value <= CMTS_MAX_TASKS);
		const uint_fast32_t index = shared_pool_acquire(counter_pool_ctrl, counter_pool_ptr);
		CMTS_UNLIKELY_IF(index == (uint32_t)CMTS_NIL_HANDLE)
			return (uint32_t)CMTS_NIL_HANDLE;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		counter_state& e = counter_pool_ptr[index];
		const counter_state::control_block c = non_atomic_load(e.ctrl);
		const counter_state::control_block nc = { true, (c.generation + 1U) & CMTS_GENERATION_MASK };
		non_atomic_store(e.ctrl, nc);
		return (cmts_counter_t)index | ((cmts_counter_t)nc.generation << 32);
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return CMTS_ERROR_INVALID_SYNC_OBJECT_HANDLE;
		return (cmts_result_t)(counter_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation == (uint32_t)(counter >> 32));
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter, cmts_boolean_t delete_counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(counter != (uint32_t)CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		counter_state& e = counter_pool_ptr[index];
		CMTS_UNLIKELY_IF(e.ctrl.load(std::memory_order_acquire).generation != generation)
			return CMTS_ERROR_EXPIRED_SYNC_OBJECT;
		CMTS_UNLIKELY_IF(!append_wait_list(e, get_current_task()))
			return CMTS_SYNC_OBJECT_EXPIRED;
		task_pool_ptr[get_current_task()].sleeping = true;
		cmts_yield();
		CMTS_LIKELY_IF(delete_counter)
		{
			e.reset();
			shared_pool_release(counter_pool_ctrl, counter_pool_ptr, index);
		}
		return CMTS_SUCCESS;
	}

	cmts_result_t CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(counter != (uint32_t)CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		CMTS_UNLIKELY_IF(counter_pool_ptr[index].ctrl.load(std::memory_order_acquire).generation != generation)
			return CMTS_ERROR_EXPIRED_SYNC_OBJECT;
		counter_pool_ptr[index].reset();
		shared_pool_release(counter_pool_ctrl, counter_pool_ptr, index);
		return CMTS_SUCCESS;
	}

	cmts_function_pointer_t CMTS_CALLING_CONVENTION cmts_task_entry_point()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return task_pool_ptr[get_current_task()].function;
	}

	void* CMTS_CALLING_CONVENTION cmts_task_parameter()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return task_pool_ptr[get_current_task()].parameter;
	}

	uint64_t CMTS_CALLING_CONVENTION cmts_task_id()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast64_t low = (uint_fast64_t)get_current_task();
		const uint_fast64_t high = (uint_fast64_t)task_pool_ptr[low].generation;
		return (uint64_t)((high << 32) | low);
	}

	uint8_t CMTS_CALLING_CONVENTION cmts_task_priority()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return task_pool_ptr[get_current_task()].priority;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_thread_index()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return get_worker_thread_index();
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return worker_thread_count;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_cpu_core_count()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return info.dwNumberOfProcessors;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_cpu_core_index()
	{
		PROCESSOR_NUMBER k = {};
		GetCurrentProcessorNumberEx(&k);
		return (uint32_t)((k.Group << 6) | k.Number);
	}

	void CMTS_CALLING_CONVENTION cmts_parallel_for(cmts_function_pointer_t body, const cmts_parallel_for_options_t* options)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(body != nullptr);
		CMTS_ASSERT(options != nullptr);

		CMTS_UNLIKELY_IF(options->begin == options->end)
			return;

		CMTS_ASSERT(options->begin < options->end);

		cmts_counter_t counter;
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();

			counter = cmts_new_counter(options->end - options->begin);
			CMTS_LIKELY_IF(counter != (uint32_t)CMTS_NIL_HANDLE)
				break;
			CMTS_YIELD_CPU;
		}

		cmts_dispatch_options_t opt;
		opt.sync_object = counter;
		opt.sync_type = CMTS_SYNC_TYPE_COUNTER;
		opt.priority = options->priority;

		for (uint_fast32_t i = options->begin; i != options->end; ++i)
		{
			opt.parameter = (void*)(size_t)i;
			while (cmts_dispatch(body, &opt) != CMTS_SUCCESS)
				CMTS_YIELD_CPU;
		}

		cmts_await_counter(counter, true);
	}

}