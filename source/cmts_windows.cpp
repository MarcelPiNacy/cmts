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

#include "../cmts.h"
#include "common.cpp"

static uint_fast8_t CMTS_CALLING_CONVENTION get_cache_line_size_log2() CMTS_NOTHROW
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
			CMTS_ASSUME(cls != 0);
			unsigned long r;
			(void)_BitScanReverse(&r, cls);
			return (uint_fast8_t)r;
		}
	}
	CMTS_UNREACHABLE;
}

static const uint_fast8_t			cache_line_size_log2 = get_cache_line_size_log2();
static uint32_t						task_stack_size;
static uint32_t						max_tasks;
static uint32_t						thread_count;
static uint32_t						queue_capacity_mask;
static HANDLE*						threads_ptr;
static thread_local HANDLE			root_fiber;
static thread_local uint32_t		current_fiber;
static thread_local uint32_t		processor_index;

#define CMTS_ASSERT_IS_TASK				CMTS_ASSERT_SIDE_EFFECTS(cmts_is_task())
#define CMTS_ROUND_TO_ALIGNMENT(K, A)	((K + ((A) - 1)) & ~(A - 1))
#define CMTS_FLOOR_TO_ALIGNMENT(K, A)	((K) & ~(A - 1))

template <typename T>
static constexpr T CMTS_CALLING_CONVENTION non_atomic_load(const std::atomic<T>& from) CMTS_NOTHROW
{
	return *(const T*)&from;
}

template <typename T>
static constexpr void CMTS_CALLING_CONVENTION non_atomic_store(std::atomic<T>& where, T value) CMTS_NOTHROW
{
	*(T*)&where = value;
}

#ifdef CMTS_USE_SPINLOCK_BASED_QUEUE
struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) cmts_shared_queue
{
	alignas(CMTS_EXPECTED_CACHE_LINE_SIZE)
	std::atomic_bool	spinlock;
	uint_fast32_t		head;
	uint_fast32_t		tail;
	uint32_t*			values;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION initialize(void* memory) CMTS_NOTHROW
	{
		values = (uint32_t*)memory;
#ifdef CMTS_DEBUG
		memset(values, 0xff, max_tasks * sizeof(uint32_t));
#endif
	}

	bool CMTS_CALLING_CONVENTION store(const uint_fast32_t value) CMTS_NOTHROW
	{
		while (spinlock.exchange(true, std::memory_order_acquire))
			CMTS_YIELD_CPU;
		const uint_fast32_t nh = head + 1;
		const bool r = nh != tail;
		if (r)
		{
			values[head & queue_capacity_mask] = value;
			head = nh;
		}
		spinlock.store(false, std::memory_order_release);
		return r;
	}

	uint_fast32_t CMTS_CALLING_CONVENTION fetch() CMTS_NOTHROW
	{
		uint_fast32_t n = 0;
		while (spinlock.exchange(true, std::memory_order_acquire))
		{
			if (n < 64)
			{
				++n;
				CMTS_YIELD_CPU;
			}
			else
			{
				CMTS_YIELD_CURRENT_THREAD;
			}
		}
		uint_fast32_t r = UINT32_MAX;
		if (head != tail)
		{
			r = values[tail & queue_capacity_mask];
			++tail;
		}
		spinlock.store(false, std::memory_order_release);
		return r;
	}
};

#else

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) cmts_shared_queue
{
	struct alignas(uint64_t) control_block
	{
		uint64_t
			generation : 16,
			head : 24,
			tail : 24;

		constexpr uint64_t mask() const CMTS_NOTHROW
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

		constexpr uint_fast32_t mask() const CMTS_NOTHROW
		{
			return *(const uint32_t*)this;
		}
	};

	std::atomic<control_block> ctrl;
	std::atomic<entry_type>* entries;

	static constexpr auto ENTRY_SIZE = sizeof(std::atomic<entry_type>);

	static uint_fast32_t CMTS_CALLING_CONVENTION adjust_index(uint_fast32_t index) CMTS_NOTHROW
	{
		CMTS_ASSERT(index < max_tasks);
		index &= queue_capacity_mask;
		const uint_fast32_t high_mask = (1ui32 << cache_line_size_log2) - 1ui32;
		const uint_fast32_t high = (index & high_mask) << cache_line_size_log2;
		const uint_fast32_t low = index >> cache_line_size_log2;
		return low | high;
	}

	void CMTS_CALLING_CONVENTION initialize(void* memory) CMTS_NOTHROW
	{
		entries = (std::atomic<entry_type>*)memory;
	}

	bool CMTS_CALLING_CONVENTION store(uint_fast32_t value) CMTS_NOTHROW
	{
		control_block c, nc;
		entry_type e, f;
		while (true)
		{
			c = ctrl.load(std::memory_order_acquire);
			nc = c;
			++nc.head;
			if (nc.head == nc.tail)
				return false;
			++nc.generation;
			if (ctrl.load(std::memory_order_acquire).mask() == c.mask())
				if (ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
		std::atomic<entry_type>& target = entries[adjust_index(c.head)];
		while (true)
		{
			e = target.load(std::memory_order_acquire);
			if (!e.is_used)
			{
				f = e;
				f.is_used = true;
				++f.generation;
				f.value = value;
				if (target.load(std::memory_order_acquire).mask() == e.mask())
					if (target.compare_exchange_weak(e, f, std::memory_order_acquire, std::memory_order_relaxed))
						break;
			}
			CMTS_YIELD_CPU;
		}
		return true;
	}

	uint_fast32_t CMTS_CALLING_CONVENTION fetch() CMTS_NOTHROW
	{
		uint_fast32_t r;
		control_block c, nc;
		entry_type e, f;
		while (true)
		{
			c = ctrl.load(std::memory_order_acquire);
			if (c.head == c.tail)
				return UINT32_MAX;
			nc = c;
			++nc.tail;
			++nc.generation;
			if (ctrl.load(std::memory_order_acquire).mask() == c.mask())
				if (ctrl.compare_exchange_weak(c, nc, std::memory_order_acquire))
					break;
			CMTS_YIELD_CPU;
		}
		std::atomic<entry_type>& target = entries[adjust_index(c.tail)];
		while (true)
		{
			e = target.load(std::memory_order_acquire);
			if (e.is_used)
			{
				f = e;
				f.is_used = false;
				++f.generation;
				r = f.value;
				if (target.load(std::memory_order_acquire).mask() == e.mask())
					if (target.compare_exchange_weak(e, f, std::memory_order_release, std::memory_order_relaxed))
						break;
			}
			CMTS_YIELD_CPU;
		}
		return r;
	}
};
#endif

struct alignas(uint32_t) wait_list_control_block
{
	uint32_t
		generation : 8,
		head : 24;

	uint_fast32_t CMTS_CALLING_CONVENTION packed() const CMTS_NOTHROW
	{
		return *(const uint32_t*)this;
	}
};

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) fiber_state
{
	using F = cmts_function_pointer_t;

	HANDLE			handle;
	F				function;
	void*			parameter;
	uint32_t		pool_next;
	uint32_t		sync_id;
	uint32_t		sync_next;
	uint8_t			priority : 3,
					sync_type : 2,
					sleeping : 1;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		function = nullptr;
		parameter = nullptr;
		pool_next = UINT32_MAX;
	}
};

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) fence_state
{
	std::atomic<bool> flag;
	uint32_t generation;
	uint32_t pool_next;
	std::atomic<wait_list_control_block> wait_list;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		pool_next = UINT32_MAX;
		non_atomic_store(wait_list, { UINT32_MAX, 0 });
	}
};

struct alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) counter_state
{
	std::atomic<uint32_t> counter;
	uint32_t generation;
	uint32_t pool_next;
	std::atomic<wait_list_control_block> wait_list;

	CMTS_INLINE_ALWAYS void CMTS_CALLING_CONVENTION reset() CMTS_NOTHROW
	{
		pool_next = UINT32_MAX;
		non_atomic_store(wait_list, { UINT32_MAX, 0 });
	}
};

struct alignas(uint64_t) pool_control_block
{
	uint32_t freelist = UINT32_MAX;
	uint32_t generation = 0;

	uint64_t CMTS_CALLING_CONVENTION packed() const CMTS_NOTHROW
	{
		return *(const uint64_t*)this;
	}
};

static fiber_state* fiber_pool_ptr;
static fence_state* fence_pool_ptr;
static counter_state* counter_pool_ptr;

alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	fiber_pool_ctrl = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<uint32_t>				fiber_pool_size = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	fence_pool_ctrl = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<uint32_t>				fence_pool_size = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<pool_control_block>	counter_pool_ctrl = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<uint32_t>				counter_pool_size = { {} };
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static cmts_shared_queue					queues[CMTS_MAX_PRIORITY];
alignas(CMTS_EXPECTED_CACHE_LINE_SIZE) static std::atomic<bool>					should_continue = { {} };

CMTS_INLINE_ALWAYS static constexpr uint64_t CMTS_CALLING_CONVENTION make_handle(const uint32_t value, const uint32_t generation) CMTS_NOTHROW
{
	return (uint64_t)((uint64_t)value | ((uint64_t)generation << 32));
}

CMTS_INLINE_ALWAYS static constexpr uint_fast32_t CMTS_CALLING_CONVENTION get_handle_index(const uint64_t handle) CMTS_NOTHROW
{
	return (uint32_t)handle;
}

CMTS_INLINE_ALWAYS static constexpr uint_fast32_t CMTS_CALLING_CONVENTION get_handle_generation(const uint64_t handle) CMTS_NOTHROW
{
	return (uint32_t)(handle >> 32);
}

static const uint64_t qpc_frequency = []() CMTS_NOTHROW
{
	LARGE_INTEGER r;
	(void)QueryPerformanceFrequency(&r);
	return r.QuadPart;
}();

CMTS_INLINE_ALWAYS static CMTS_CALLING_CONVENTION uint64_t timestamp_ns() CMTS_NOTHROW
{
	LARGE_INTEGER r;
	(void)QueryPerformanceCounter(&r);
	return (r.QuadPart * (uint64_t)1000000000) / qpc_frequency;
}

CMTS_INLINE_NEVER static CMTS_CALLING_CONVENTION void conditionally_exit_thread() CMTS_NOTHROW
{
	CMTS_UNLIKELY_IF(!should_continue.load(std::memory_order_acquire))
		ExitThread(0);
}

CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION counter_append_wait_list(counter_state& state, const uint_fast32_t fiber) CMTS_NOTHROW
{
	wait_list_control_block c, nc;
	while (true)
	{
		if (state.counter.load(std::memory_order_acquire) == 0)
			return false;
		c = nc = state.wait_list.load(std::memory_order_acquire);
		fiber_pool_ptr[fiber].sync_next = c.head;
		nc.head = fiber;
		++nc.generation;
		CMTS_LIKELY_IF(state.wait_list.load(std::memory_order_acquire).packed() == c.packed())
			CMTS_LIKELY_IF(state.wait_list.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
			break;
		CMTS_YIELD_CPU;
	}
	return true;
}

CMTS_INLINE_ALWAYS static bool CMTS_CALLING_CONVENTION fence_append_wait_list(fence_state& state, const uint_fast32_t fiber) CMTS_NOTHROW
{
	wait_list_control_block c, nc;
	while (true)
	{
		if (state.flag.load(std::memory_order_acquire))
			return false;
		c = nc = state.wait_list.load(std::memory_order_acquire);
		fiber_pool_ptr[fiber].sync_next = c.head;
		nc.head = fiber;
		++nc.generation;
		if (state.wait_list.load(std::memory_order_acquire).packed() == c.packed())
			CMTS_LIKELY_IF(state.wait_list.compare_exchange_weak(c, nc, std::memory_order_acquire, std::memory_order_relaxed))
				break;
		CMTS_YIELD_CPU;
	}
	return true;
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_wait_list(std::atomic<wait_list_control_block>& ctrl) CMTS_NOTHROW
{
	uint_fast32_t r;
	wait_list_control_block c, nc;
	while (true)
	{
		c = nc = ctrl.load(std::memory_order_acquire);
		r = c.head;
		if (r == UINT32_MAX)
			break;
		nc.head = fiber_pool_ptr[c.head].sync_next;
		++nc.generation;
		if (ctrl.load(std::memory_order_acquire).packed() == c.packed())
			CMTS_LIKELY_IF(ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		CMTS_YIELD_CPU;
	}
	return r;
}

static void CMTS_CALLING_CONVENTION wait_for_available_resource_task(const std::atomic<uint32_t>& pool_size) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_LIKELY_IF(pool_size.load(std::memory_order_acquire) != max_tasks)
			CMTS_LIKELY_IF(pool_size.load(std::memory_order_acquire) != max_tasks)
			break;
		cmts_yield();
	}
}

static void CMTS_CALLING_CONVENTION wait_for_available_resource_thread(const std::atomic<uint32_t>& pool_size) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_LIKELY_IF(pool_size.load(std::memory_order_acquire) != max_tasks)
			CMTS_LIKELY_IF(pool_size.load(std::memory_order_acquire) != max_tasks)
			break;
		CMTS_YIELD_CURRENT_THREAD;
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION wait_for_available_resource(const std::atomic<uint32_t>& pool_size) CMTS_NOTHROW
{
	CMTS_LIKELY_IF(cmts_is_task())
		wait_for_available_resource_task(pool_size);
	else
	wait_for_available_resource_thread(pool_size);
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION new_fiber() CMTS_NOTHROW
{
	pool_control_block c, nc;
	uint_fast32_t r = UINT32_MAX;
	while (true)
	{
		CMTS_UNLIKELY_IF(fiber_pool_size.load(std::memory_order_acquire) == max_tasks)
			wait_for_available_resource(fiber_pool_size);

		c = fiber_pool_ctrl.load(std::memory_order_acquire);
		CMTS_LIKELY_IF(c.freelist != UINT32_MAX)
		{
			nc = c;
			r = nc.freelist;
			nc.freelist = fiber_pool_ptr[r].pool_next;
			++nc.generation;
			if (fiber_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
				CMTS_LIKELY_IF(fiber_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
		}
		else
		{
			uint_fast32_t k = fiber_pool_size.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(k == max_tasks)
				continue;
			r = k + 1;
			if (fiber_pool_size.load(std::memory_order_acquire) == k)
				CMTS_LIKELY_IF(fiber_pool_size.compare_exchange_weak(k, r, std::memory_order_release, std::memory_order_relaxed))
					break;
		}
		CMTS_YIELD_CPU;
	}
	return r;
}

CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION delete_fiber(const uint_fast32_t fiber) CMTS_NOTHROW
{
	fiber_state& f = fiber_pool_ptr[fiber];
	HANDLE h = f.handle;
	f.reset();
	f.handle = h;
	pool_control_block c, nc;
	while (true)
	{
		c = fiber_pool_ctrl.load(std::memory_order_acquire);
		nc = c;
		f.pool_next = nc.freelist;
		nc.freelist = fiber;
		++nc.generation;
		if (fiber_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
			CMTS_LIKELY_IF(fiber_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
				break;
		CMTS_YIELD_CPU;
	}
}

CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION submit_fiber_to_queue(const uint_fast32_t fiber, const uint8_t priority) CMTS_NOTHROW
{
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		CMTS_LIKELY_IF(queues[priority].store(fiber))
			return;
		CMTS_YIELD_CPU;
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION fence_wake_fibers(const uint_fast32_t fence_index) CMTS_NOTHROW
{
	non_atomic_store(fence_pool_ptr[fence_index].flag, true);
	uint_fast32_t i;
	while (true)
	{
		i = fetch_wait_list(fence_pool_ptr[fence_index].wait_list);
		CMTS_UNLIKELY_IF(i == UINT32_MAX)
			break;
		fiber_pool_ptr[i].sleeping = false;
		submit_fiber_to_queue(i, fiber_pool_ptr[i].priority);
	}
}

CMTS_INLINE_NEVER static void CMTS_CALLING_CONVENTION counter_wake_fibers(const uint_fast32_t counter_index) CMTS_NOTHROW
{
	uint_fast32_t i;
	while (true)
	{
		i = fetch_wait_list(counter_pool_ptr[counter_index].wait_list);
		CMTS_UNLIKELY_IF(i == UINT32_MAX)
			break;
		fiber_pool_ptr[i].sleeping = false;
		submit_fiber_to_queue(i, fiber_pool_ptr[i].priority);
	}
}

CMTS_INLINE_ALWAYS static void CMTS_CALLING_CONVENTION counter_conditionally_wake_fibers(const uint_fast32_t counter_index) CMTS_NOTHROW
{
	const uint_fast32_t value = counter_pool_ptr[counter_index].counter.fetch_sub(1, std::memory_order_acquire) - 1;
	CMTS_LIKELY_IF(value == 0)
		counter_wake_fibers(counter_index);
}

CMTS_INLINE_ALWAYS static uint_fast32_t CMTS_CALLING_CONVENTION fetch_fiber_from_queue() CMTS_NOTHROW
{
	uint_fast32_t r;
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		for (uint_fast32_t i = 0; i < CMTS_MAX_PRIORITY; ++i)
		{
			r = queues[i].fetch();
			CMTS_LIKELY_IF(r != UINT32_MAX)
				return r;
		}
		CMTS_YIELD_CPU;
	}
	return r;
}

static void WINAPI fiber_main(fiber_state* const param) CMTS_NOTHROW
{
	CMTS_ASSERT(param != nullptr);
	while (true)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			conditionally_exit_thread();
		CMTS_ASSERT(param->function != nullptr);
		param->function(param->parameter);
		param->function = nullptr;
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
		current_fiber = fetch_fiber_from_queue();
		fiber_state& f = fiber_pool_ptr[current_fiber];
		SwitchToFiber(f.handle);
		if (f.function != nullptr)
		{
			if (!f.sleeping)
				submit_fiber_to_queue(current_fiber, f.priority);
		}
		else
		{
			const uint_fast8_t sync_type = f.sync_type;
			const uint_fast32_t sync_index = f.sync_id;
			delete_fiber(current_fiber);
			switch (sync_type)
			{
			case CMTS_SYNCHRONIZATION_TYPE_FENCE:
				CMTS_LIKELY_IF(!fence_pool_ptr[sync_index].flag.exchange(true, std::memory_order_acquire))
					fence_wake_fibers(sync_index);
				break;
			case CMTS_SYNCHRONIZATION_TYPE_COUNTER:
				counter_conditionally_wake_fibers(sync_index);
				break;
			default:
				break;
			}
		}
	}
}

static bool CMTS_CALLING_CONVENTION custom_library_init(const cmts_init_options_t* options) CMTS_NOTHROW
{
	if (options->max_tasks > CMTS_MAX_TASKS ||
		options->task_stack_size != 0 ||
		options->max_threads != 0 ||
		CMTS_POPCOUNT(options->max_tasks) != 1 ||
		options->max_tasks != 0)
		return false;
	task_stack_size = options->task_stack_size;
	thread_count = options->max_threads;
	max_tasks = options->max_tasks;
	queue_capacity_mask = max_tasks - 1;
	const size_t queue_buffer_size = max_tasks * cmts_shared_queue::ENTRY_SIZE;
	const size_t allocation_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
	uint8_t* const ptr = (uint8_t*)CMTS_OS_ALLOCATE(allocation_size);
	if (ptr == nullptr)
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
	if (options->use_affinity)
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

	non_atomic_store(should_continue, true);
	return true;
}

static bool CMTS_CALLING_CONVENTION default_library_init() CMTS_NOTHROW
{
	non_atomic_store(should_continue, true);
	const uint_fast32_t ncpus = cmts_available_cpu_count();
	thread_count = ncpus;
	max_tasks = ncpus * 1024;
	queue_capacity_mask = max_tasks - 1;
	const size_t queue_buffer_size = max_tasks * sizeof(cmts_shared_queue::ENTRY_SIZE);
	const size_t allocation_size = (thread_count * sizeof(HANDLE)) + (queue_buffer_size * CMTS_MAX_PRIORITY) + (max_tasks * (sizeof(fiber_state) + sizeof(fence_state) + sizeof(counter_state)));
	uint8_t* const ptr = (uint8_t*)CMTS_OS_ALLOCATE(allocation_size);
	CMTS_ASSERT(ptr != nullptr);
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



#ifdef __cplusplus
extern "C"
{
#endif

	bool CMTS_CALLING_CONVENTION cmts_init(const cmts_init_options_t* options)
	{
		CMTS_UNLIKELY_IF(!non_atomic_load(should_continue))
			CMTS_UNLIKELY_IF(should_continue.load(std::memory_order_acquire))
				return false;
		if (options != nullptr)
			return custom_library_init(options);
		else
			return default_library_init();
	}

	bool CMTS_CALLING_CONVENTION cmts_break()
	{
		CMTS_ASSERT(threads_ptr != nullptr);
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = SuspendThread(threads_ptr[i]);
			CMTS_UNLIKELY_IF(r == MAXDWORD)
				return false;
		}
		return true;
	}

	bool CMTS_CALLING_CONVENTION cmts_continue()
	{
		CMTS_UNLIKELY_IF(threads_ptr == nullptr)
			return false;
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = ResumeThread(threads_ptr[i]);
			CMTS_UNLIKELY_IF(r == MAXDWORD)
				return false;
		}
		return true;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_finalize()
	{
		CMTS_ASSERT(threads_ptr != nullptr);
		should_continue.store(false, std::memory_order_release);
	}

	bool CMTS_CALLING_CONVENTION cmts_finalize()
	{
		CMTS_UNLIKELY_IF(threads_ptr == nullptr)
			return false;
		const DWORD r = WaitForMultipleObjects(thread_count, threads_ptr, true, INFINITE);
		CMTS_UNLIKELY_IF(r != WAIT_OBJECT_0)
			return false;
		CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
			return false;
		CMTS_UNLIKELY_IF(!ConvertFiberToThread())
			return false;
		threads_ptr = nullptr;
		return true;
	}

	bool CMTS_CALLING_CONVENTION cmts_terminate()
	{
		CMTS_UNLIKELY_IF(threads_ptr == nullptr)
			return false;
		cmts_signal_finalize();
		for (uint_fast32_t i = 0; i < thread_count; ++i)
		{
			CMTS_UNLIKELY_IF(threads_ptr[i] == nullptr)
				return false;
			const DWORD r = TerminateThread(threads_ptr[i], UINT32_MAX);
			CMTS_UNLIKELY_IF(r == 0)
				return false;
		}
		CMTS_UNLIKELY_IF(!VirtualFree(threads_ptr, 0, MEM_RELEASE))
			return false;
		CMTS_UNLIKELY_IF(!ConvertFiberToThread())
			return false;
		threads_ptr = nullptr;
		return true;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_initialized()
	{
		return threads_ptr != nullptr;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_task()
	{
		return root_fiber != nullptr;
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_running()
	{
		return non_atomic_load(should_continue);
	}

	void CMTS_CALLING_CONVENTION cmts_dispatch(cmts_function_pointer_t task_function, const cmts_dispatch_options_t* options)
	{
		CMTS_ASSERT(task_function != nullptr);
		const uint_fast32_t id = new_fiber();
		fiber_state& e = fiber_pool_ptr[id];
		e.function = task_function;
		if (options != nullptr)
		{
			e.parameter = options->parameter;
			e.priority = options->priority;
			if (options->synchronization_type != CMTS_SYNCHRONIZATION_TYPE_FENCE)
			{
				e.sync_type = CMTS_SYNCHRONIZATION_TYPE_FENCE;
				e.sync_id = get_handle_index(options->fence);
				CMTS_UNLIKELY_IF(fence_pool_ptr[e.sync_id].generation != get_handle_generation(options->fence))
					return;
			}
			else if (options->synchronization_type != CMTS_SYNCHRONIZATION_TYPE_COUNTER)
			{
				e.sync_type = CMTS_SYNCHRONIZATION_TYPE_COUNTER;
				e.sync_id = get_handle_index(options->counter);
				CMTS_UNLIKELY_IF(counter_pool_ptr[e.sync_id].generation != get_handle_generation(options->counter))
					return;
			}
		}
		else
		{
			e.parameter = nullptr;
			e.priority = 0;
			e.sync_type = CMTS_SYNCHRONIZATION_TYPE_NONE;
#ifdef CMTS_DEBUG
			e.sync_id = CMTS_NIL_HANDLE;
#endif
		}
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		submit_fiber_to_queue(id, e.priority);
	}

	void CMTS_CALLING_CONVENTION cmts_yield()
	{
		CMTS_ASSERT_IS_TASK;
		SwitchToFiber(root_fiber);
	}

	void CMTS_CALLING_CONVENTION cmts_exit()
	{
		CMTS_ASSERT_IS_TASK;
		fiber_pool_ptr[current_fiber].function = nullptr;
		cmts_yield();
	}

	cmts_fence_t CMTS_CALLING_CONVENTION cmts_new_fence()
	{
		pool_control_block c, nc;
		uint_fast32_t index;
		while (true)
		{
			CMTS_UNLIKELY_IF(fence_pool_size.load(std::memory_order_acquire) == max_tasks)
				wait_for_available_resource(fence_pool_size);
			c = fence_pool_ctrl.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(c.freelist != UINT32_MAX)
			{
				nc = c;
				index = nc.freelist;
				nc.freelist = fence_pool_ptr[index].pool_next;
				++nc.generation;
				if (fence_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
					CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
						break;
			}
			else
			{
				index = fence_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(index == max_tasks)
					continue;
				if (fence_pool_size.load(std::memory_order_acquire) == index)
					CMTS_LIKELY_IF(fence_pool_size.compare_exchange_weak(index, index + 1, std::memory_order_release, std::memory_order_relaxed))
						break;
			}
			CMTS_YIELD_CPU;
		}
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		fence_state& e = fence_pool_ptr[index];
		non_atomic_store(e.flag, false);
		++e.generation;
		return make_handle(index, e.generation);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_fence_valid(cmts_fence_t fence)
	{
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return false;
		const uint_fast32_t generation = get_handle_generation(fence);
		return fence_pool_ptr[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_signal_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT(fence != CMTS_NIL_FENCE);
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(fence);
		CMTS_ASSERT(fence_pool_ptr[index].generation == generation);
		fence_wake_fibers(index);
	}

	void CMTS_CALLING_CONVENTION cmts_delete_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT(fence != CMTS_NIL_FENCE);
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(fence);
		CMTS_ASSERT(fence_pool_ptr[index].generation == generation);
		fence_pool_ptr[index].reset();
		pool_control_block c, nc;
		while (true)
		{
			c = fence_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			fence_pool_ptr[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			if (fence_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
				CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
	}

	void CMTS_CALLING_CONVENTION cmts_await_fence(cmts_fence_t fence)
	{
		CMTS_ASSERT(fence != CMTS_NIL_FENCE);
		CMTS_ASSERT_IS_TASK;
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(fence);
		if (fence_pool_ptr[index].generation != generation)
			return;
		fiber_state& e = fiber_pool_ptr[current_fiber];
		if (!fence_append_wait_list(fence_pool_ptr[index], current_fiber))
			return;
		e.sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_fence_and_delete(cmts_fence_t fence)
	{
		CMTS_ASSERT(fence != CMTS_NIL_FENCE);
		CMTS_ASSERT_IS_TASK;
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(fence);
		if (fence_pool_ptr[index].generation != generation)
			return;
		fiber_state& e = fiber_pool_ptr[current_fiber];
		if (!fence_append_wait_list(fence_pool_ptr[index], current_fiber))
			return;
		e.sleeping = true;
		cmts_yield();
		fence_pool_ptr[index].reset();
		pool_control_block c, nc;
		while (true)
		{
			c = fence_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			fence_pool_ptr[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			if (fence_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
				CMTS_LIKELY_IF(fence_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
	}

	cmts_counter_t CMTS_CALLING_CONVENTION cmts_new_counter(uint32_t start_value)
	{
		CMTS_ASSERT(start_value <= CMTS_MAX_TASKS);
		CMTS_ASSERT(start_value <= max_tasks);
		pool_control_block c, nc;
		uint_fast32_t index;
		while (true)
		{
			CMTS_UNLIKELY_IF(counter_pool_size.load(std::memory_order_acquire) == max_tasks)
				wait_for_available_resource(counter_pool_size);
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			CMTS_LIKELY_IF(c.freelist != UINT32_MAX)
			{
				nc = c;
				index = nc.freelist;
				nc.freelist = counter_pool_ptr[index].pool_next;
				++nc.generation;
				if (counter_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
					CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
						break;
				CMTS_YIELD_CPU;
			}
			else
			{
				index = counter_pool_size.load(std::memory_order_acquire);
				CMTS_UNLIKELY_IF(index == max_tasks)
					continue;
				if (counter_pool_size.load(std::memory_order_acquire) == index)
					CMTS_LIKELY_IF(counter_pool_size.compare_exchange_weak(index, index + 1, std::memory_order_release, std::memory_order_relaxed))
						break;
				CMTS_YIELD_CPU;
			}
		}
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		counter_state& e = counter_pool_ptr[index];
		non_atomic_store<uint32_t>(e.counter, start_value);
		++e.generation;
		return make_handle(index, e.generation);
	}

	cmts_boolean_t CMTS_CALLING_CONVENTION cmts_is_counter_valid(cmts_counter_t counter)
	{
		const uint_fast32_t index = get_handle_index(counter);
		CMTS_UNLIKELY_IF(index >= CMTS_MAX_TASKS || index >= max_tasks)
			return false;
		const uint_fast32_t generation = get_handle_generation(counter);
		return counter_pool_ptr[index].generation == generation;
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT(counter != CMTS_NIL_FENCE);
		CMTS_ASSERT_IS_TASK;
		const uint_fast32_t index = get_handle_index(counter);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(counter);
		fiber_state& e = fiber_pool_ptr[current_fiber];
		CMTS_UNLIKELY_IF(counter_pool_ptr[index].generation != generation)
			return;
		CMTS_UNLIKELY_IF(!counter_append_wait_list(counter_pool_ptr[index], current_fiber))
			return;
		e.sleeping = true;
		cmts_yield();
	}

	void CMTS_CALLING_CONVENTION cmts_await_counter_and_delete(cmts_counter_t counter)
	{
		CMTS_ASSERT(counter != CMTS_NIL_FENCE);
		CMTS_ASSERT_IS_TASK;
		const uint_fast32_t index = get_handle_index(counter);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(counter);
		counter_state& s = counter_pool_ptr[index];
		CMTS_UNLIKELY_IF(s.generation != generation)
			return;
		fiber_state& e = fiber_pool_ptr[current_fiber];
		CMTS_UNLIKELY_IF(!counter_append_wait_list(s, current_fiber))
			return;
		e.sleeping = true;
		cmts_yield();
		s.reset();
		pool_control_block c, nc;
		while (true)
		{
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			s.pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			if (counter_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
				CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
	}

	void CMTS_CALLING_CONVENTION cmts_delete_counter(cmts_counter_t counter)
	{
		CMTS_ASSERT(counter != CMTS_NIL_FENCE);
		const uint_fast32_t index = get_handle_index(counter);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(counter);
		CMTS_ASSERT(counter_pool_ptr[index].generation == generation);
		counter_pool_ptr[index].reset();
		pool_control_block c, nc;
		while (true)
		{
			c = counter_pool_ctrl.load(std::memory_order_acquire);
			nc = c;
			counter_pool_ptr[index].pool_next = nc.freelist;
			nc.freelist = index;
			++nc.generation;
			if (counter_pool_ctrl.load(std::memory_order_acquire).packed() == c.packed())
				CMTS_LIKELY_IF(counter_pool_ctrl.compare_exchange_weak(c, nc, std::memory_order_release, std::memory_order_relaxed))
					break;
			CMTS_YIELD_CPU;
		}
	}

	void CMTS_CALLING_CONVENTION cmts_dispatch_with_fence(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_fence_t fence)
	{
		CMTS_ASSERT(task_function != nullptr);
		CMTS_ASSERT(priority_level < CMTS_MAX_PRIORITY);
		CMTS_ASSERT(fence != CMTS_NIL_FENCE);
		const uint_fast32_t index = get_handle_index(fence);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(fence);
		CMTS_UNLIKELY_IF(fence_pool_ptr[index].generation != generation)
			return;
		const uint_fast32_t id = new_fiber();
		fiber_state& e = fiber_pool_ptr[id];
		e.function = task_function;
		e.parameter = param;
		e.sync_type = CMTS_SYNCHRONIZATION_TYPE_FENCE;
		e.sync_id = index;
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		submit_fiber_to_queue(id, e.priority);
	}

	void CMTS_CALLING_CONVENTION cmts_dispatch_with_counter(cmts_function_pointer_t task_function, void* param, uint8_t priority_level, cmts_counter_t counter)
	{
		const uint_fast32_t index = get_handle_index(counter);
		CMTS_ASSERT(index < CMTS_MAX_TASKS);
		CMTS_ASSERT(index < max_tasks);
		const uint_fast32_t generation = get_handle_generation(counter);
		CMTS_UNLIKELY_IF(counter_pool_ptr[index].generation != generation)
			return;
		const uint32_t id = new_fiber();
		fiber_state& e = fiber_pool_ptr[id];
		e.function = task_function;
		e.parameter = param;
		e.sync_type = CMTS_SYNCHRONIZATION_TYPE_COUNTER;
		e.sync_id = index;
		CMTS_UNLIKELY_IF(e.handle == nullptr)
			e.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, (LPFIBER_START_ROUTINE)fiber_main, &e);
		submit_fiber_to_queue(id, e.priority);
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_current_task_id()
	{
		return current_fiber;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_worker_thread_index()
	{
		return processor_index;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_thread_count()
	{
		return thread_count;
	}

	uint32_t CMTS_CALLING_CONVENTION cmts_available_cpu_count()
	{
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		return info.dwNumberOfProcessors;
	}

#ifdef __cplusplus
}
#endif