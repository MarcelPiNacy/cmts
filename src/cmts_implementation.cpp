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



#include "cmts.h"
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
#define CMTS_YIELD_CURRENT_THREAD SwitchToThread()
#else
#error "cmts: UNSUPPORTED OPERATING SYSTEM"
#endif

#ifdef __clang__
#if defined(__arm__) || defined(__aarch64__)
#define CMTS_NOOP __nop()
#define CMTS_YIELD_CPU __yield()
#elif defined(__i386__) || defined(__x86_64__)
#include <intrin.h>
#define CMTS_NOOP __nop()
#define CMTS_YIELD_CPU _mm_pause()
#else
#error "UNSUPPORTED PROCESSOR ARCHITECTURE"
#endif
#define CMTS_LIKELY_IF(expression) if (__builtin_expect((expression), 1))
#define CMTS_UNLIKELY_IF(expression) if (__builtin_expect((expression), 0))
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
#define CMTS_INLINE_NEVER
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
#define CMTS_LIKELY_IF(expression) if ((expression))
#define CMTS_UNLIKELY_IF(expression) if ((expression))
#define CMTS_ASSUME(expression) __assume((expression))
#define CMTS_ALLOCA(size) _alloca((size))
#define CMTS_POPCOUNT(value) __popcnt((value))
#define CMTS_UNSIGNED_LOG2(value) _tzcnt_u32((value))
#define CMTS_ROTATE_LEFT32(mask, count) _rotl((mask), (count))
#define CMTS_ROTATE_LEFT64(mask, count) _rotl64((mask), (count))
#define CMTS_ROTATE_RIGHT32(mask, count) _rotr((mask), (count))
#define CMTS_ROTATE_RIGHT64(mask, count) _rotr64((mask), (count))
#define CMTS_TERMINATE __fastfail(-1)
#ifdef CMTS_DEBUG
#define CMTS_UNREACHABLE CMTS_TERMINATE; CMTS_ASSUME(0)
#define CMTS_INLINE_ALWAYS
#define CMTS_INLINE_NEVER
#else
#define CMTS_UNREACHABLE CMTS_ASSUME(0)
#define CMTS_INLINE_ALWAYS __forceinline
#define CMTS_INLINE_NEVER __declspec(noinline)
#endif
#else
#error "cmts: UNSUPPORTED COMPILER";
#endif

#if CMTS_EXPECTED_CACHE_LINE_SIZE != 64
static_assert(CMTS_POPCOUNT(CMTS_EXPECTED_CACHE_LINE_SIZE) == 1, "CMTS_EXPECTED_CACHE_LINE_SIZE MUST BE A POWER OF TWO");
#endif

#define CMTS_ROUND_TO_ALIGNMENT(K, A)	((K + ((A) - 1)) & ~(A - 1))
#define CMTS_FLOOR_TO_ALIGNMENT(K, A)	((K) & ~(A - 1))

#define CMTS_UINT24_MAX ((1U << 24U) - 1U)
#define CMTS_DEFAULT_TASK_STACK_SIZE (1U << 16U)
#define CMTS_DEFAULT_THREAD_STACK_SIZE (1U << 21U)

#ifdef CMTS_DEBUG
#include <cassert>
#include "..\cmts.h"
#define CMTS_ASSERT(expression) assert(expression)
#define CMTS_ASSERT_IS_TASK CMTS_ASSERT(root_fiber != nullptr)
#define CMTS_ASSERT_IS_INITIALIZED CMTS_ASSERT(threads_ptr != nullptr)
#else
#define CMTS_ASSERT(expression) CMTS_ASSUME((expression))
#define CMTS_ASSERT_IS_TASK
#define CMTS_ASSERT_IS_INITIALIZED
#endif

static uint_fast8_t					cache_line_size_log2;
static uint_fast32_t				cache_line_size_mask;
static uint_fast32_t				task_stack_size;
static uint_fast32_t				max_tasks;
static uint_fast32_t				thread_count;
static uint_fast32_t				queue_capacity_log2;
static uint_fast32_t				queue_capacity_mask;
static HANDLE*						threads_ptr;
static thread_local HANDLE			root_fiber;
static thread_local uint_fast32_t	current_task;
static thread_local uint_fast32_t	processor_index;

static void CMTS_CALLING_CONVENTION load_cache_line_info() CMTS_NOTHROW
{
	DWORD k = 0;
#ifdef CMTS_DEBUG
	(void)GetLogicalProcessorInformation(nullptr, &k);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* const buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)CMTS_ALLOCA(k);
	CMTS_ASSERT(buffer != nullptr);
	const bool flag = GetLogicalProcessorInformation(buffer, &k);
	CMTS_ASSERT(flag);
#else
	(void)GetLogicalProcessorInformation(nullptr, &k);
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION* const buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION*)CMTS_ALLOCA(k);
	(void)GetLogicalProcessorInformation(buffer, &k);
#endif
	for (uint_fast32_t i = 0; i < k; ++i)
	{
		if ((buffer[i].Cache.Level == 1) & (buffer[i].Relationship == RelationCache))
		{
			const WORD cls = buffer[i].Cache.LineSize;
			CMTS_ASSERT(cls != 0);
			cache_line_size_log2 = CMTS_UNSIGNED_LOG2(cls);
			cache_line_size_mask = cls - 1;
			return;
		}
	}
	CMTS_UNREACHABLE;
}

template <typename T>
static CMTS_INLINE_ALWAYS T CMTS_CALLING_CONVENTION non_atomic_load(const std::atomic<T>& from) CMTS_NOTHROW
{
	return *(const T*)&from;
}

template <typename T, typename U = T>
static CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION non_atomic_store(std::atomic<T>& where, U value) CMTS_NOTHROW
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

	CMTS_INLINE_ALWAYS uint64_t CMTS_CALLING_CONVENTION mask() const CMTS_NOTHROW
	{
		return *(const uint64_t*)this;
	}
};

struct alignas(uint64_t) wait_list_control_block
{
	uint32_t head;
	uint32_t generation;

	CMTS_INLINE_ALWAYS uint_fast64_t CMTS_CALLING_CONVENTION mask() const CMTS_NOTHROW
	{
		return *(const uint64_t*)this;
	}
};

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE / 2) fiber_state
{
	HANDLE					handle;
	cmts_function_pointer_t	function;
	void*					parameter;
	uint32_t				sync_id;
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

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) fence_state
{
	uint32_t generation;
	uint32_t pool_next;
	std::atomic<wait_list_control_block> wait_list;
	std::atomic<bool> flag;

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION is_done() const CMTS_NOTHROW
	{
		return !flag.load(std::memory_order_acquire);
	}

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		pool_next = CMTS_UINT24_MAX;
		non_atomic_store(wait_list, { CMTS_NIL_HANDLE, 0 });
	}
};

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) counter_state
{
	uint32_t generation;
	uint32_t pool_next;
	std::atomic<uint_fast32_t> counter;
	std::atomic<wait_list_control_block> wait_list;

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION is_done() const CMTS_NOTHROW
	{
		return counter.load(std::memory_order_acquire) == 0;
	}

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		pool_next = CMTS_NIL_HANDLE;
		non_atomic_store(wait_list, { CMTS_NIL_HANDLE, 0 });
	}
};

struct alignas(uint32_t) task_mutex
{
	uint32_t	flag : 1,
				head : 31;
};

alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<bool> is_paused;
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<bool> should_continue;

CMTS_INLINE_NEVER static CMTS_CALLING_CONVENTION void conditionally_exit_thread() CMTS_NOTHROW
{
	CMTS_UNLIKELY_IF(!should_continue.load(std::memory_order_acquire))
	{
		ExitThread(0);
		CMTS_UNREACHABLE;
	}
}

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) cmts_shared_queue
{
	struct alignas(uint64_t) control_block
	{
		uint64_t
			head : 24,
			tail : 24,
			generation : 16;

		CMTS_INLINE_ALWAYS uint64_t CMTS_CALLING_CONVENTION mask() const CMTS_NOTHROW
		{
			return *(const uint64_t*)this;
		}
	};

	struct alignas(uint32_t) entry_type
	{
		uint32_t
			is_used : 1,
			generation : 7,
			value : 24;

		CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION mask() const CMTS_NOTHROW
		{
			return *(const uint32_t*)this;
		}
	};

	std::atomic<control_block> ctrl;
	std::atomic<entry_type>* entries;

	static constexpr size_t ENTRY_SIZE = sizeof(std::atomic<entry_type>);

	CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION adjust_index(uint_fast32_t index) CMTS_NOTHROW
	{
		const uint_fast32_t low = index >> cache_line_size_log2;
		const uint_fast32_t high = index << queue_capacity_log2;
		const uint_fast32_t joined = high | low;
		return index & queue_capacity_mask;
	}

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION initialize(void* memory) CMTS_NOTHROW
	{
		entries = (std::atomic<entry_type>*)memory;
	}

	CMTS_INLINE_ALWAYS bool CMTS_CALLING_CONVENTION store(uint_fast32_t value) CMTS_NOTHROW
	{
		CMTS_ASSERT(value != CMTS_NIL_HANDLE);
		control_block c, nc;
		entry_type e, f;
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();
			c = ctrl.load(std::memory_order_acquire);
			nc.head = c.head + 1;
			CMTS_UNLIKELY_IF(nc.head == c.tail)
				return false;
			nc.tail = c.tail;
			nc.generation = c.generation + 1;
			CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
				CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
		const uint_fast32_t index = adjust_index(c.head);
		std::atomic<entry_type>& target = entries[index];
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();
			e = target.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(!e.is_used)
			{
				f.is_used = true;
				f.generation = e.generation + 1;
				f.value = value;
				CMTS_LIKELY_IF(target.load(std::memory_order_acquire).mask() == e.mask())
					CMTS_LIKELY_IF(target.compare_exchange_weak(e, f, std::memory_order_release, std::memory_order_relaxed))
						break;
			}
			CMTS_YIELD_CPU;
		}
		return true;
	}

	CMTS_INLINE_ALWAYS uint_fast32_t CMTS_CALLING_CONVENTION fetch() CMTS_NOTHROW
	{
		uint_fast32_t r;
		control_block c, nc;
		entry_type e, f;
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();
			c = ctrl.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(c.head == c.tail)
				return CMTS_NIL_HANDLE;
			nc.head = c.head;
			nc.tail = c.tail + 1;
			nc.generation = c.generation + 1;
			CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
				CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
		const uint_fast32_t index = adjust_index(c.tail);
		std::atomic<entry_type>& target = entries[index];
		while (true)
		{
			CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
				conditionally_exit_thread();
			e = target.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(e.is_used)
			{
				f.is_used = false;
				f.generation = e.generation + 1;
				r = e.value;
				CMTS_LIKELY_IF(target.load(std::memory_order_acquire).mask() == e.mask())
					CMTS_LIKELY_IF(target.compare_exchange_weak(e, f, std::memory_order_release, std::memory_order_relaxed))
						break;
			}
			CMTS_YIELD_CPU;
		}
		CMTS_ASSERT(r != CMTS_NIL_HANDLE);
		return r;
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
				return CMTS_NIL_HANDLE;
			r = c.size;
			CMTS_ASSERT(r < CMTS_UINT24_MAX&& r < max_tasks);
			nc.freelist = CMTS_UINT24_MAX;
			nc.size = c.size + 1;
		}
		nc.generation = c.generation + 1;
		CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
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
		CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
			CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		CMTS_YIELD_CPU;
	}
}

template <typename T>
CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION shared_pool_release_no_inline(std::atomic<pool_control_block>& ctrl, T* const elements, uint_fast32_t index) CMTS_NOTHROW
{
	::shared_pool_release<T>(ctrl, elements, index);
}

static fiber_state*																fiber_pool_ptr;
static fence_state*																fence_pool_ptr;
static counter_state*															counter_pool_ptr;
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	fiber_pool_ctrl;
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	fence_pool_ctrl;
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	counter_pool_ctrl;
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static cmts_shared_queue					queues[CMTS_MAX_PRIORITY];

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_wait_list(std::atomic<wait_list_control_block>& ctrl) CMTS_NOTHROW
{
	wait_list_control_block c, nc;
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		c = ctrl.load(std::memory_order_acquire);
		CMTS_UNLIKELY_IF(c.head == CMTS_NIL_HANDLE)
			return CMTS_NIL_HANDLE;
		CMTS_ASSERT(c.head < CMTS_MAX_TASKS);
		CMTS_ASSERT(c.head < max_tasks);
		nc.head = fiber_pool_ptr[c.head].wait_next;
		nc.generation = c.generation + 1;
		CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
			CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
				return c.head;
		CMTS_YIELD_CPU;
	}
	CMTS_UNREACHABLE;
}

CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION try_append_wait_list(std::atomic<wait_list_control_block>& ctrl, const uint_fast32_t index) CMTS_NOTHROW
{
	bool r = false;
	wait_list_control_block c, nc;
	c = ctrl.load(std::memory_order_acquire);
	nc.head = index;
	fiber_pool_ptr[index].wait_next = c.head;
	nc.generation = c.generation + 1;
	CMTS_LIKELY_IF(ctrl.load(std::memory_order_acquire).mask() == c.mask())
		r = ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed);
	return r;
}

template <typename T>
CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION append_wait_list(T& state, uint_fast32_t index) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		CMTS_UNLIKELY_IF(state.is_done())
			return false;
		CMTS_LIKELY_IF(try_append_wait_list(state.wait_list, index))
			return true;
		CMTS_YIELD_CPU;
	}
	CMTS_UNREACHABLE;
}

CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION submit_to_queue(const uint_fast32_t fiber, const uint8_t priority) CMTS_NOTHROW
{
	CMTS_ASSERT(priority < CMTS_MAX_PRIORITY);
	while (true)
	{
		CMTS_LIKELY_IF(queues[priority].store(fiber))
			break;
		CMTS_YIELD_CPU;
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION fence_wake_fibers(const uint_fast32_t fence_index) CMTS_NOTHROW
{
	non_atomic_store(fence_pool_ptr[fence_index].flag, true);
	while (true)
	{
		const uint_fast32_t i = fetch_wait_list(fence_pool_ptr[fence_index].wait_list);
		CMTS_UNLIKELY_IF(i == CMTS_NIL_HANDLE)
			break;
		fiber_pool_ptr[i].sleeping = false;
		submit_to_queue(i, fiber_pool_ptr[i].priority);
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION counter_wake_fibers(const uint_fast32_t counter_index) CMTS_NOTHROW
{
	while (true)
	{
		const uint_fast32_t i = fetch_wait_list(counter_pool_ptr[counter_index].wait_list);
		CMTS_UNLIKELY_IF(i == CMTS_NIL_HANDLE)
			break;
		fiber_pool_ptr[i].sleeping = false;
		submit_to_queue(i, fiber_pool_ptr[i].priority);
	}
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_fiber_from_queue() CMTS_NOTHROW
{
	uint_fast32_t r;
	while (true)
	{
		for (uint_fast32_t i = 0; i < CMTS_MAX_PRIORITY; ++i)
		{
			r = queues[i].fetch();
			CMTS_LIKELY_IF(r != CMTS_NIL_HANDLE)
				return r;
		}
		CMTS_YIELD_CPU;
	}
	return r;
}

static void WINAPI fiber_main(void* param) CMTS_NOTHROW
{
	CMTS_ASSERT(param != nullptr);
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		CMTS_ASSERT(current_task < CMTS_MAX_TASKS);
		CMTS_ASSERT(current_task < max_tasks);
		fiber_state& state = fiber_pool_ptr[current_task];
		CMTS_ASSERT(state.function != nullptr);
		state.function(state.parameter);
		state.function = nullptr;
		SwitchToFiber(root_fiber);
	}
}

static DWORD WINAPI thread_main(void* param) CMTS_NOTHROW
{
	processor_index = (uint_fast32_t)(size_t)param;
	root_fiber = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);
	CMTS_ASSERT(root_fiber != nullptr);
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		current_task = fetch_fiber_from_queue();
		CMTS_ASSERT(current_task < CMTS_MAX_TASKS);
		CMTS_ASSERT(current_task < max_tasks);
		fiber_state& f = fiber_pool_ptr[current_task];
		CMTS_ASSERT(f.function != nullptr);
		CMTS_ASSERT(f.handle != nullptr);
		SwitchToFiber(f.handle);
		if (f.function != nullptr)
		{
			CMTS_LIKELY_IF(!f.sleeping)
				submit_to_queue(current_task, f.priority);
		}
		else
		{
			const uint_fast8_t sync_type = f.sync_type;
			const uint_fast32_t sync_index = f.sync_id;
			switch (sync_type)
			{
			case CMTS_SYNCHRONIZATION_TYPE_NONE:
				break;
			case CMTS_SYNCHRONIZATION_TYPE_FENCE:
				CMTS_LIKELY_IF(!fence_pool_ptr[sync_index].flag.exchange(true, std::memory_order_acquire))
					fence_wake_fibers(sync_index);
				break;
			case CMTS_SYNCHRONIZATION_TYPE_COUNTER:
				CMTS_UNLIKELY_IF((counter_pool_ptr[sync_index].counter.fetch_sub(1, std::memory_order_acquire) - 1) == 0)
					counter_wake_fibers(sync_index);
				break;
			default:
				CMTS_UNREACHABLE;
			}
			shared_pool_release_no_inline(fiber_pool_ctrl, fiber_pool_ptr, current_task);
		}
	}
}

static bool CMTS_CALLING_CONVENTION custom_library_init(const cmts_init_options_t* options) CMTS_NOTHROW
{
	CMTS_UNLIKELY_IF(options->max_tasks > CMTS_MAX_TASKS ||
		options->task_stack_size == 0 ||
		options->max_threads == 0 ||
		CMTS_POPCOUNT(options->max_tasks) != 1 ||
		options->max_tasks == 0)
		return false;
	load_cache_line_info();
	task_stack_size = options->task_stack_size;
	thread_count = options->max_threads;
	max_tasks = options->max_tasks;
	queue_capacity_log2 = CMTS_UNSIGNED_LOG2(max_tasks) - cache_line_size_log2;
	queue_capacity_mask = max_tasks - 1;
	const size_t queue_buffer_size = max_tasks * cmts_shared_queue::ENTRY_SIZE;
	const size_t buffer_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
	uint8_t* const ptr = (uint8_t*)CMTS_OS_ALLOCATE(buffer_size);
	CMTS_UNLIKELY_IF(ptr == nullptr)
		return false;
	threads_ptr = (HANDLE*)ptr;
	fiber_pool_ptr = (fiber_state*)CMTS_ROUND_TO_ALIGNMENT((size_t)(threads_ptr + thread_count), CMTS_EXPECTED_CACHE_LINE_SIZE);
	fence_pool_ptr = (fence_state*)(fiber_pool_ptr + max_tasks);
	counter_pool_ptr = (counter_state*)(fence_pool_ptr + max_tasks);
	uint8_t* const qptr = (uint8_t*)(counter_pool_ptr + max_tasks);

	for (uint_fast32_t i = 0; i < CMTS_MAX_PRIORITY; ++i)
		queues[i].initialize(qptr + i * queue_buffer_size);

	for (uint_fast32_t i = 0; i < max_tasks; ++i)
	{
		fiber_pool_ptr[i].reset();
		fence_pool_ptr[i].reset();
		counter_pool_ptr[i].reset();
	}

	CMTS_LIKELY_IF(options->use_affinity)
	{
		if (options->use_manual_affinity)
		{
			for (uint_fast32_t i = 0; i < thread_count; ++i)
			{
				threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
				CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
					return false;
				CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)options->cpu_indices[i])) == 0)
					return false;
				CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
					return false;
			}
		}
		else
		{
			for (uint_fast32_t i = 0; i < thread_count; ++i)
			{
				threads_ptr[i] = CreateThread(nullptr, options->thread_stack_size, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
				CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
					return false;
				CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)i)) == 0)
					return false;
				CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
					return false;
			}
		}
	}
	else
	{
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			threads_ptr[i] = CreateThread(nullptr, CMTS_DEFAULT_THREAD_STACK_SIZE, thread_main, (void*)(size_t)i, 0, nullptr);
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
		}
	}

	return true;
}

static bool CMTS_CALLING_CONVENTION default_library_init() CMTS_NOTHROW
{
	load_cache_line_info();
	const uint_fast32_t ncpus = cmts_core_count();
	task_stack_size = CMTS_DEFAULT_TASK_STACK_SIZE;
	thread_count = ncpus;
	max_tasks = ncpus * 256;
	queue_capacity_log2 = CMTS_UNSIGNED_LOG2(max_tasks) - cache_line_size_log2;
	queue_capacity_mask = max_tasks - 1;
	const size_t queue_buffer_size = max_tasks * sizeof(cmts_shared_queue::ENTRY_SIZE);
	const size_t buffer_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
	uint8_t* const ptr = (uint8_t*)CMTS_OS_ALLOCATE(buffer_size);
	CMTS_ASSERT(ptr != nullptr);
	threads_ptr = (HANDLE*)ptr;
	fiber_pool_ptr = (fiber_state*)CMTS_ROUND_TO_ALIGNMENT((size_t)(threads_ptr + thread_count), CMTS_EXPECTED_CACHE_LINE_SIZE);
	fence_pool_ptr = (fence_state*)(fiber_pool_ptr + max_tasks);
	counter_pool_ptr = (counter_state*)(fence_pool_ptr + max_tasks);
	uint8_t* const qptr = (uint8_t*)(counter_pool_ptr + max_tasks);
	(*(pool_control_block*)&fiber_pool_ctrl).reset();
	(*(pool_control_block*)&fence_pool_ctrl).reset();
	(*(pool_control_block*)&counter_pool_ctrl).reset();

	for (uint_fast32_t i = 0; i < CMTS_MAX_PRIORITY; ++i)
		queues[i].initialize(qptr + i * queue_buffer_size);

	for (uint_fast32_t i = 0; i < max_tasks; ++i)
	{
		fiber_pool_ptr[i].reset();
		fence_pool_ptr[i].reset();
		counter_pool_ptr[i].reset();
	}

	for (uint_fast32_t i = 0; i < thread_count; ++i)
	{
		threads_ptr[i] = CreateThread(nullptr, CMTS_DEFAULT_THREAD_STACK_SIZE, thread_main, (void*)(size_t)i, CREATE_SUSPENDED, nullptr);
		CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
			return false;
		CMTS_UNLIKELY_IF(SetThreadAffinityMask(threads_ptr[i], ((DWORD_PTR)1U << (DWORD_PTR)i)) == 0)
			return false;
		CMTS_UNLIKELY_IF(ResumeThread(threads_ptr[i]) == MAXDWORD)
			return false;
	}

	return true;
}



extern "C"
{

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options)
	{
		non_atomic_store(should_continue, true);
		if (options != nullptr)
			return custom_library_init(options);
		else
			return default_library_init();
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_break()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = SuspendThread(threads_ptr[i]);
			CMTS_UNLIKELY_IF(r == MAXDWORD)
				return false;
		}
		is_paused.store(true, std::memory_order_release);
		return true;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_continue()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = ResumeThread(threads_ptr[i]);
			CMTS_UNLIKELY_IF(r == MAXDWORD)
				return false;
		}
		is_paused.store(false, std::memory_order_release);
		return true;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_finalize()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		should_continue.store(false, std::memory_order_release);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_finalize(cmts_deallocate_function_pointer_t deallocate)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const DWORD r = WaitForMultipleObjects(thread_count, threads_ptr, true, INFINITE);
		CMTS_UNLIKELY_IF(r != WAIT_OBJECT_0)
			return false;
		for (uint_fast32_t i = 0; i < thread_count; ++i)
			CMTS_UNLIKELY_IF(CloseHandle(threads_ptr[i]))
				return false;
		if (deallocate == nullptr)
		{
			CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
				return false;
		}
		else
		{
			const size_t queue_buffer_size = max_tasks * cmts_shared_queue::ENTRY_SIZE;
			const size_t buffer_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
			deallocate(threads_ptr, buffer_size);
		}
		CMTS_UNLIKELY_IF(!ConvertFiberToThread())
			return false;
		threads_ptr = nullptr;
		return true;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_terminate(cmts_deallocate_function_pointer_t deallocate)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		cmts_signal_finalize();
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = TerminateThread(threads_ptr[i], MAXDWORD);
			CMTS_UNLIKELY_IF(r == 0)
				return false;
			CMTS_UNLIKELY_IF(CloseHandle(threads_ptr[i]))
				return false;
		}

		if (deallocate == nullptr)
		{
			CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
				return false;
		}
		else
		{
			const size_t queue_buffer_size = max_tasks * cmts_shared_queue::ENTRY_SIZE;
			const size_t buffer_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
			deallocate(threads_ptr, buffer_size);
		}

		CMTS_UNLIKELY_IF(!ConvertFiberToThread())
			return false;
		threads_ptr = nullptr;
		return true;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return root_fiber != nullptr;
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

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t entry_point, const cmts_dispatch_options_t* options)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(entry_point != nullptr);
		const uint_fast32_t id = shared_pool_acquire(fiber_pool_ctrl, fiber_pool_ptr);
		CMTS_UNLIKELY_IF(id == CMTS_NIL_HANDLE)
			return false;
		fiber_state& e = fiber_pool_ptr[id];
		++e.generation;
		e.function = entry_point;
		if (options != nullptr)
		{
			CMTS_ASSERT(options->priority < CMTS_MAX_PRIORITY);
			CMTS_ASSERT(options->synchronization_type < CMTS_SYNCHRONIZATION_TYPE_MAX_ENUM);
			e.parameter = options->parameter;
			e.priority = options->priority;
			e.sync_type = options->synchronization_type;
			e.sync_id = (uint32_t)options->sync_object;
			if (e.sync_type != CMTS_SYNCHRONIZATION_TYPE_NONE)
			{
				const uint_fast32_t sync_generation = (uint_fast32_t)(options->sync_object >> 32);
				const uint_fast32_t generation = *(e.sync_type == CMTS_SYNCHRONIZATION_TYPE_FENCE ? (const uint32_t*)(fence_pool_ptr + e.sync_id) : (const uint32_t*)(counter_pool_ptr + e.sync_id));
				CMTS_UNLIKELY_IF(sync_generation != generation)
				{
					shared_pool_release(fiber_pool_ctrl, fiber_pool_ptr, id);
					return true;
				}
			}
		}
		else
		{
			e.parameter = nullptr;
			e.priority = 0;
			e.sync_type = CMTS_SYNCHRONIZATION_TYPE_NONE;
		}
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		CMTS_ASSERT(e.handle != nullptr);
		submit_to_queue(id, e.priority);
		return true;
	}

	void CMTS_CALLING_CONVENTION cmts_yield()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		SwitchToFiber(root_fiber);
	}

	void CMTS_CALLING_CONVENTION cmts_exit()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		fiber_pool_ptr[current_task].function = nullptr;
		cmts_yield();
	}

	cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = shared_pool_acquire(fence_pool_ctrl, fence_pool_ptr);
		CMTS_UNLIKELY_IF(index == CMTS_NIL_HANDLE)
			return CMTS_NIL_HANDLE;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		fence_state& e = fence_pool_ptr[index];
		non_atomic_store(e.flag, false);
		++e.generation;
		return (cmts_fence_t)((uint64_t)index | ((uint64_t)e.generation << 32));
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return false;
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		return fence_pool_ptr[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(fence != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool_ptr[index].generation == generation);
		fence_wake_fibers(index);
	}

	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(fence != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_ASSERT(fence_pool_ptr[index].generation == generation);
		fence_pool_ptr[index].reset();
		shared_pool_release(fence_pool_ctrl, fence_pool_ptr, index);
	}

	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(fence != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].generation != generation)
			return;
		fiber_state& e = fiber_pool_ptr[current_task];
		if (!append_wait_list(fence_pool_ptr[index], current_task))
			return;
		e.sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(fence != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].generation != generation)
			return;
		if (!append_wait_list(fence_pool_ptr[index], current_task))
			return;
		fiber_pool_ptr[current_task].sleeping = true;
		cmts_yield();
		fence_pool_ptr[index].reset();
		shared_pool_release(fence_pool_ctrl, fence_pool_ptr, index);
	}

	cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(start_value != 0);
		CMTS_ASSERT(start_value <= CMTS_MAX_TASKS);
		CMTS_ASSERT(start_value <= max_tasks);
		const uint_fast32_t index = shared_pool_acquire(counter_pool_ctrl, counter_pool_ptr);
		CMTS_UNLIKELY_IF(index == CMTS_NIL_HANDLE)
			return CMTS_NIL_HANDLE;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		counter_state& e = counter_pool_ptr[index];
		non_atomic_store(e.counter, start_value);
		++e.generation;
		return (cmts_counter_t)((uint64_t)index | ((uint64_t)e.generation << 32));
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return false;
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		return counter_pool_ptr[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(counter != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		CMTS_UNLIKELY_IF(counter_pool_ptr[index].generation != generation)
			return;
		CMTS_UNLIKELY_IF(!append_wait_list(counter_pool_ptr[index], current_task))
			return;
		fiber_pool_ptr[current_task].sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		CMTS_ASSERT(counter != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		counter_state& s = counter_pool_ptr[index];
		CMTS_UNLIKELY_IF(s.generation != generation)
			return;
		CMTS_UNLIKELY_IF(!append_wait_list(s, current_task))
			return;
		fiber_pool_ptr[current_task].sleeping = true;
		cmts_yield();
		s.reset();
		shared_pool_release(counter_pool_ctrl, counter_pool_ptr, index);
	}

	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(counter != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		CMTS_ASSERT(counter_pool_ptr[index].generation == generation);
		counter_pool_ptr[index].reset();
		shared_pool_release(counter_pool_ctrl, counter_pool_ptr, index);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t entry_point, void* param, uint8_t priority, cmts_fence_t fence)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(entry_point != nullptr);
		CMTS_ASSERT(priority < CMTS_MAX_PRIORITY);
		CMTS_ASSERT(fence != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)fence;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(fence >> 32);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].generation != generation)
			return false;
		const uint_fast32_t id = shared_pool_acquire(fiber_pool_ctrl, fiber_pool_ptr);
		CMTS_UNLIKELY_IF(id == CMTS_NIL_HANDLE)
			return false;
		fiber_state& e = fiber_pool_ptr[id];
		e.function = entry_point;
		e.parameter = param;
		e.sync_type = CMTS_SYNCHRONIZATION_TYPE_FENCE;
		e.sync_id = index;
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		CMTS_ASSERT(e.handle != nullptr);
		submit_to_queue(id, priority);
		return true;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t entry_point, void* param, uint8_t priority, cmts_counter_t counter)
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT(entry_point != nullptr);
		CMTS_ASSERT(priority < CMTS_MAX_PRIORITY);
		CMTS_ASSERT(counter != CMTS_NIL_HANDLE);
		const uint_fast32_t index = (uint32_t)counter;
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = (uint32_t)(counter >> 32);
		CMTS_UNLIKELY_IF(counter_pool_ptr[index].generation != generation)
			return false;
		const uint_fast32_t id = shared_pool_acquire(fiber_pool_ctrl, fiber_pool_ptr);
		CMTS_UNLIKELY_IF(id == CMTS_NIL_HANDLE)
			return false;
		fiber_state& e = fiber_pool_ptr[id];
		e.function = entry_point;
		e.parameter = param;
		e.sync_type = CMTS_SYNCHRONIZATION_TYPE_COUNTER;
		e.sync_id = index;
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		CMTS_ASSERT(e.handle != nullptr);
		submit_to_queue(id, priority);
		return true;
	}

	cmts_function_pointer_t CMTS_CALLING_CONVENTION cmts_task_entry_point()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return fiber_pool_ptr[current_task].function;
	}

	void* CMTS_CALLING_CONVENTION cmts_task_parameter()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return fiber_pool_ptr[current_task].parameter;
	}

	uint64_t CMTS_CALLING_CONVENTION cmts_task_id()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		const uint_fast64_t low = current_task;
		const uint_fast64_t high = fiber_pool_ptr[low].generation;
		return (uint64_t)((high << 32) | low);
	}

	uint8_t CMTS_CALLING_CONVENTION cmts_task_priority()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		CMTS_ASSERT_IS_TASK;
		return fiber_pool_ptr[current_task].priority;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_thread_index()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return processor_index;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count()
	{
		CMTS_ASSERT_IS_INITIALIZED;
		return thread_count;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_core_count()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return info.dwNumberOfProcessors;
	}

}