#include "../include/cmts.h"
#include "../include/cmts.hpp"
#ifndef CMTS_IMPLEMENTATION_INCLUDED
#define CMTS_IMPLEMENTATION_INCLUDED
#include <atomic>
#include <cstdint>
#include <new>

#ifdef __has_cpp_attribute
	#if __has_cpp_attribute(likely)
		#define CMTS_LIKELY_IF(condition) if ((condition)) [[likely]]
	#else
		#define CMTS_LIKELY_IF(condition) if ((condition))
	#endif
	
	#if __has_cpp_attribute(unlikely)
		#define CMTS_UNLIKELY_IF(condition) if ((condition)) [[unlikely]]
	#else
		#define CMTS_UNLIKELY_IF(condition) if ((condition))
	#endif
#else
	#define CMTS_LIKELY_IF(condition) if ((condition))
	#define CMTS_UNLIKELY_IF(condition) if ((condition))
#endif

#if defined(_MSVC_LANG) || defined(_MSC_VER)

	#define CMTS_ASSUME(expression) __assume((expression))
	#define CMTS_INLINE_NEVER __declspec(noinline)
	#define CMTS_INLINE_ALWAYS __forceinline
	#define CMTS_FAST_LOG2(value) _tzcnt_u32((value))

	#ifdef CMTS_32BIT
		#define CMTS_POPCOUNT(value) ((ufast8)__popcnt((unsigned int)(value)))
	#else
		#define CMTS_POPCOUNT(value) ((ufast8)__popcnt64((unsigned long long)(value)))
	#endif

#endif

#if defined(_DEBUG) && !defined(NDEBUG)
	[[noreturn]] void cmts_debug_assertion_handler(const char* expression);
	#define CMTS_DEBUG
	#define CMTS_INVARIANT(expression) CMTS_UNLIKELY_IF(!(expression)) { CMTS_DEBUG_TRAP(); cmts_debug_assertion_handler(#expression); }
	#define CMTS_ASSERT_IMPURE(expression) CMTS_INVARIANT((expression))
#else
	#define CMTS_INVARIANT(expression) CMTS_ASSUME((expression))
	#define CMTS_ASSERT_IMPURE(expression) ((expression))
#endif

using uint8 = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;
using ufast8 = uint_fast8_t;
using ufast16 = uint_fast16_t;
using ufast32 = uint_fast32_t;
using ufast64 = uint_fast64_t;
using uintptr = size_t;
#if UINTPTR_MAX == UINT32_MAX
#define CMTS_32BIT
using ufastptr = ufast32;
#else
#define CMTS_64BIT
using ufastptr = ufast64;
#endif

using int8 = int8_t;
using int16 = int16_t;
using int32 = int32_t;
using int64 = int64_t;
using ifast8 = int_fast8_t;
using ifast16 = int_fast16_t;
using ifast32 = int_fast32_t;
using ifast64 = int_fast64_t;
using intptr = ptrdiff_t;
#if UINTPTR_MAX == UINT32_MAX
#define CMTS_32BIT
using ifastptr = ifast32;
#else
#define CMTS_64BIT
using ifastptr = ifast64;
#endif

template <typename T>
static T non_atomic_load(const std::atomic<T>& from)
{
	if constexpr (std::atomic<T>::is_always_lock_free)
	{
		return *(const T*)&from;
	}
	else
	{
#ifdef _MSVC_LANG
		return from._Storage;
#endif
	}
}

template <typename T>
static T& non_atomic_ref(std::atomic<T>& from)
{
	if constexpr (std::atomic<T>::is_always_lock_free)
	{
		return *(T*)&from;
	}
	else
	{
#ifdef _MSVC_LANG
		return from._Storage;
#endif
	}
}

template <typename T, typename U = T>
static void non_atomic_store(std::atomic<T>& where, U value)
{
	if constexpr (std::atomic<T>::is_always_lock_free)
	{
		*(T*)&where = value;
	}
	else
	{
#ifdef _MSVC_LANG
		where._Storage = value;
#endif
	}
}

static constexpr ufastptr constexpr_log2(ufastptr value)
{
	switch (value)
	{
	case 2:		return 1;
	case 4:		return 2;
	case 8:		return 3;
	case 16:	return 4;
	case 32:	return 5;
	case 64:	return 6;
	case 128:	return 7;
	case 256:	return 8;
	default:	return 0;
	}
}

static constexpr ufast32 NIL_INDEX = UINT32_MAX;
static constexpr ufastptr FALSE_SHARING_THRESHOLD = std::hardware_destructive_interference_size;
static constexpr ufastptr FALSE_SHARING_THRESHOLD_MASK = FALSE_SHARING_THRESHOLD - 1;
static constexpr ufastptr FALSE_SHARING_THRESHOLD_LOG2 = constexpr_log2(FALSE_SHARING_THRESHOLD);
static constexpr ufastptr SHARED_QUEUE_BASE_SHIFT = constexpr_log2(FALSE_SHARING_THRESHOLD / sizeof(std::atomic<uint32>));
static_assert(FALSE_SHARING_THRESHOLD_LOG2 != 0);

#define CMTS_SHARED_ATTR alignas (FALSE_SHARING_THRESHOLD)

#ifdef CMTS_DEBUG
	namespace debugger
	{
		static void* context;
		static cmts_ext_debugger_message_callback_t callback;
	
		namespace detail
		{
			template <typename T>
			constexpr ufastptr array_size(T& array) { return sizeof(array) / sizeof(array[0]); }
		}

		static void init(const cmts_ext_debugger_init_options_t& options)
		{
			context = options.context;
			callback = options.message_callback;
		}
	
		template <cmts_ext_debugger_message_severity_t S, typename String>
		CMTS_INLINE_ALWAYS static void message(String text)
		{
			if (callback == nullptr)
				return;
			cmts_ext_debugger_message_t message;
			message.ext = nullptr;
			message.message = text;
			message.message_length = detail::array_size(text) - 1;
			message.severity = S;
			callback(context, &message);
		}
	}
	
	#define CMTS_REPORT_INFO(msg) debugger::message<CMTS_EXT_DEBUGGER_MESSAGE_SEVERITY_INFO>(CMTS_TEXT(msg))
	#define CMTS_REPORT_WARNING(msg) debugger::message<CMTS_EXT_DEBUGGER_MESSAGE_SEVERITY_WARNING>(CMTS_TEXT(msg))
	#define CMTS_REPORT_ERROR(msg) debugger::message<CMTS_EXT_DEBUGGER_MESSAGE_SEVERITY_ERROR>(CMTS_TEXT(msg))
#else
	#define CMTS_REPORT_INFO(msg)
	#define CMTS_REPORT_WARNING(msg)
	#define CMTS_REPORT_ERROR(msg)
#endif
	
#ifdef _WIN32

	#define CMTS_WINDOWS

	#ifndef NOMINMAX
		#define NOMINMAX
	#endif

	#ifndef VC_EXTRALEAN
		#define VC_EXTRALEAN
	#endif

	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif

	#include <Windows.h>

	#define CMTS_WORKER_TASK_CALLING_CONVENTION WINAPI
	#define CMTS_WORKER_THREAD_CALLING_CONVENTION WINAPI
	#define CMTS_DEBUG_TRAP() DebugBreak()
	#define CMTS_SPIN_WAIT() YieldProcessor()
	
	namespace os
	{
		using thread_return_type = DWORD;
		using thread_parameter_type = void*;
		using WaitOnAddress_t = decltype(WaitOnAddress);
		using WakeByAddressAll_t = decltype(WakeByAddressAll);
		using WakeByAddressSingle_t = decltype(WakeByAddressSingle);
		
		static HMODULE sync_library;
		static WaitOnAddress_t* wait_on_address;
		static WakeByAddressSingle_t* wake_by_address_single;
		static WakeByAddressAll_t* wake_by_address_all;
	
		CMTS_INLINE_ALWAYS static bool initialize()
		{
			sync_library = GetModuleHandle(TEXT("Synchronization.lib"));
			CMTS_UNLIKELY_IF(sync_library == nullptr)
			{
				sync_library = GetModuleHandle(TEXT("API-MS-Win-Core-Synch-l1-2-0.dll"));
				CMTS_REPORT_WARNING("\"GetModuleHandle(\"Synchronization.lib\")\" returned NULL. Attempting the same with \"API-MS-Win-Core-Synch-l1-2-0.dll\".");
				CMTS_UNLIKELY_IF(sync_library == nullptr)
				{
					CMTS_REPORT_ERROR("\"GetModuleHandle(\"API-MS-Win-Core-Synch-l1-2-0.dll\")\" returned NULL. Library initialization failed.");
					return false;
				}
			}

			wait_on_address = (WaitOnAddress_t*)GetProcAddress(sync_library, "WaitOnAddress");
			CMTS_UNLIKELY_IF(wait_on_address == nullptr)
			{
				CMTS_REPORT_ERROR("Failed to fetch the address of WaitOnAddress. Library initialization failed.");
				return false;
			}
			wake_by_address_single = (WakeByAddressSingle_t*)GetProcAddress(sync_library, "WakeByAddressSingle");
			CMTS_UNLIKELY_IF(sync_library == nullptr)
			{
				CMTS_REPORT_ERROR("Failed to fetch the address of WakeByAddressSingle. Library initialization failed.");
				return false;
			}
			wake_by_address_all = (WakeByAddressAll_t*)GetProcAddress(sync_library, "WakeByAddressAll");
			CMTS_UNLIKELY_IF(sync_library == nullptr)
			{
				CMTS_REPORT_ERROR("Failed to fetch the address of WakeByAddressAll. Library initialization failed.");
				return false;
			}
			return true;
		}

		CMTS_INLINE_ALWAYS static void* allocate(ufastptr size)
		{
			return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}
	
		CMTS_INLINE_ALWAYS static bool deallocate(void* ptr, ufastptr size)
		{
			return VirtualFree(ptr, 0, MEM_RELEASE);
		}
	
		CMTS_INLINE_ALWAYS static HANDLE new_thread(LPTHREAD_START_ROUTINE entry_point, void* param, ufastptr stack_size, bool suspended)
		{
			return CreateThread(nullptr, stack_size, entry_point, param, suspended ? CREATE_SUSPENDED : 0, nullptr);
		}
	
		template <typename T, typename U>
		CMTS_INLINE_ALWAYS static void futex_await(T& address, U old_value)
		{
			static_assert(sizeof(T) == sizeof(U));
			U tmp = old_value;
			(void)wait_on_address((volatile void*)&address, &tmp, sizeof(U), INFINITE);
		}
	
		template <typename T>
		CMTS_INLINE_ALWAYS static void futex_signal_single(T& address)
		{
			wake_by_address_single(&address);
		}
	
		template <typename T>
		CMTS_INLINE_ALWAYS static void futex_signal(T& address)
		{
			wake_by_address_all(&address);
		}
	
		CMTS_INLINE_ALWAYS static bool set_thread_affinities(HANDLE* threads, DWORD count, DWORD first)
		{
			GROUP_AFFINITY prior = {};
			GROUP_AFFINITY group = {};
			for (ufast32 i = 0; i != count; ++i)
			{
				group.Group = (WORD)(first >> 6);
				group.Mask = (DWORD_PTR)1 << (DWORD_PTR)(first & 63U);
				CMTS_UNLIKELY_IF(!SetThreadGroupAffinity(threads[i], &group, &prior))
				{
					CMTS_REPORT_ERROR("SetThreadGroupAffinity returned FALSE. Library initialization failed.");
					return false;
				}
				++first;
			}
			return true;
		}
	
		CMTS_INLINE_ALWAYS static bool await_threads(HANDLE* threads, DWORD count)
		{
			return WaitForMultipleObjects(count, threads, true, INFINITE) == WAIT_OBJECT_0;
		}
	
		CMTS_INLINE_ALWAYS static bool suspend_threads(HANDLE* threads, DWORD count)
		{
			for (ufast32 i = 0; i != count; ++i)
			{
				CMTS_UNLIKELY_IF(SuspendThread(threads[i]) == MAXDWORD)
				{
					CMTS_REPORT_ERROR("SuspendThread returned FALSE.");
					return false;
				}
			}
			return true;
		}
	
		CMTS_INLINE_ALWAYS static bool resume_threads(HANDLE* threads, DWORD count)
		{
			for (ufast32 i = 0; i != count; ++i)
			{
				CMTS_UNLIKELY_IF(ResumeThread(threads[i]) == MAXDWORD)
				{
					CMTS_REPORT_ERROR("ResumeThread returned FALSE.");
					return false;
				}
			}
			return true;
		}
	
		CMTS_INLINE_ALWAYS static void exit_thread()
		{
			ExitThread(0);
		}
	
		CMTS_INLINE_ALWAYS static bool terminate_threads(HANDLE* threads, DWORD count)
		{
			for (ufast32 i = 0; i != count; ++i)
			{
				CMTS_UNLIKELY_IF(!TerminateThread(threads[i], MAXDWORD))
				{
					CMTS_REPORT_ERROR("TerminateThread returned FALSE.");
					return false;
				}
			}
			return true;
		}
	}

#else
	#error "CMTS: UNSUPPORTED OPERATING SYSTEM."
#endif

#ifdef CMTS_WINDOWS
	static HANDLE* worker_threads;
#endif

static uint32 worker_thread_count;

#ifdef CMTS_DEBUG
	[[noreturn]] void cmts_debug_assertion_handler(const char* expression)
	{
		(void)os::suspend_threads(worker_threads, worker_thread_count);
		(void)fprintf(stderr, "CMTS: Assertion failed! Expression: \"%s\"", expression);
		abort();
	}
#endif

static uint32 queue_capacity_mask;
static uint32 adjust_queue_index_shift;
static uint32 max_tasks;
static uintptr task_stack_size;

#ifdef CMTS_WINDOWS
	thread_local static HANDLE root_task;
#endif
	
thread_local static uint32 current_task_index;
thread_local static uint32 worker_thread_index;
thread_local static ufast32 cached_indices[CMTS_MAX_PRIORITY];

template <typename T>
CMTS_INLINE_ALWAYS static void spin_while_eq(const std::atomic<T>& where, T value)
{
	while (where.load(std::memory_order_relaxed) == value)
		CMTS_SPIN_WAIT();
	std::atomic_thread_fence(std::memory_order_acquire);
}

template <typename T>
CMTS_INLINE_ALWAYS static void spin_while_neq(const std::atomic<T>& where, T value)
{
	while (where.load(std::memory_order_relaxed) != value)
		CMTS_SPIN_WAIT();
	std::atomic_thread_fence(std::memory_order_acquire);
}

CMTS_SHARED_ATTR static std::atomic<ufast32> library_guard_ticket;
CMTS_SHARED_ATTR static std::atomic<ufast32> library_guard_grant;

struct library_guard
{
	library_guard()
	{
		ufast32 desired = library_guard_ticket.fetch_add(1, std::memory_order_acquire);
		spin_while_neq(library_guard_grant, desired);
	}

	~library_guard()
	{
		library_guard_grant.store(non_atomic_load(library_guard_grant) + 1, std::memory_order_release);
	}
};

CMTS_SHARED_ATTR static std::atomic_bool library_exit_flag;
CMTS_SHARED_ATTR static std::atomic_bool library_is_initialized;
CMTS_SHARED_ATTR static std::atomic_bool library_is_paused;

CMTS_INLINE_ALWAYS static void exit_thread()
{
#ifdef CMTS_WINDOWS
	ExitThread(0);
#endif
}

CMTS_INLINE_ALWAYS static void finalize_check()
{
	CMTS_UNLIKELY_IF(library_exit_flag.load(std::memory_order_acquire))
		exit_thread();
}

struct CMTS_SHARED_ATTR shared_queue_header
{
	CMTS_SHARED_ATTR std::atomic<ufast32> head;
	CMTS_SHARED_ATTR std::atomic<ufast32> tail;
	CMTS_SHARED_ATTR std::atomic<ufast32> size;
	CMTS_SHARED_ATTR std::atomic<uint32>* values;
};

enum class task_state : uint8
{
	INACTIVE,
	RUNNING,
	GOING_TO_SLEEP,
	SLEEPING,
};

struct CMTS_SHARED_ATTR task_data
{
	HANDLE handle;
	cmts_task_function_pointer_t function;
	void* parameter;
	void* sync_object;
	// x64: 32B
	uint32 next;
	uint32 generation;
	uint8 priority;
	uint8 sync_type;
	std::atomic<task_state> state;
	void* ext;

	CMTS_INLINE_ALWAYS bool has_stack() const
	{
		return handle != nullptr;
	}
};

struct alignas(uint64) index_generation_pair
{
	uint32 index;
	uint32 generation;
};

struct CMTS_SHARED_ATTR object_pool_header
{
	CMTS_SHARED_ATTR std::atomic<index_generation_pair> freelist;
	CMTS_SHARED_ATTR std::atomic<ufast32> bump;

	CMTS_INLINE_ALWAYS void initialize()
	{
		non_atomic_store(freelist, { NIL_INDEX, 0 });
		non_atomic_store(bump, 0);
	}
};

CMTS_SHARED_ATTR static object_pool_header task_pool_header;
CMTS_SHARED_ATTR static object_pool_header event_pool_header;
CMTS_SHARED_ATTR static object_pool_header counter_pool_header;
CMTS_SHARED_ATTR static shared_queue_header queues[CMTS_MAX_PRIORITY];
CMTS_SHARED_ATTR static std::atomic<ufast32> futex_counters[CMTS_MAX_PRIORITY];
CMTS_SHARED_ATTR static task_data* task_pool;

struct ext_task_name_view
{
	const CMTS_CHAR* begin;
	size_t length;
};

struct CMTS_SHARED_ATTR ext_task_name_data
{
	std::atomic<ext_task_name_view> name;
};

static ext_task_name_data* ext_task_names;



struct pool_helper_type_task { };
pool_helper_type_task task_pool_view = { };

struct wait_queue_node
{
	std::atomic<wait_queue_node*> next;
	uint32 index;
};

struct wait_queue
{
	std::atomic<wait_queue_node*> tail;

	alignas (wait_queue_node)
	std::atomic<wait_queue_node*> head;
	std::atomic_bool done;
};

struct event_data
{
	wait_queue queue;
};

struct counter_data
{
	std::atomic<ufast64> value;
	wait_queue queue;
};

struct mutex_data
{
	std::atomic<ufast32> tail;
};

struct rwlock_data
{
	uint32	is_writing : 1,
			reader_count : 31;
	uint32	tail;
};

static_assert(sizeof(cmts_event_t) >= sizeof(event_data));
static_assert(sizeof(cmts_counter_t) >= sizeof(counter_data));
static_assert(sizeof(cmts_mutex_t) >= sizeof(mutex_data));
static_assert(sizeof(cmts_rwlock_t) >= sizeof(std::atomic<rwlock_data>));

#ifdef CMTS_NO_BUSY_WAIT
	namespace queue_futex
	{
		static CMTS_SHARED_ATTR std::atomic<ufast32> counter;
	
		CMTS_INLINE_ALWAYS static ufast32 get_generation()
		{
			return counter.load(std::memory_order_acquire);
		}
	
		CMTS_INLINE_ALWAYS static void await_submission(ufast32 prior)
		{
			for (ufast8 i = 0; i != CMTS_SPIN_THRESHOLD; ++i)
			{
				CMTS_LIKELY_IF(counter.load(std::memory_order_acquire) != prior)
					return;
				CMTS_SPIN_WAIT();
			}
			
			os::futex_await(counter, prior);
		}
	
		CMTS_INLINE_ALWAYS static void signal_submission()
		{
			ufast32 value = non_atomic_load(counter);
			counter.store(value + 1, std::memory_order_release);
			os::futex_signal_single(counter);
		}
	}
#endif



template <typename T>
CMTS_INLINE_ALWAYS static bool enum_range_check(T value, T min, T max)
{
	return value >= min && value <= max;
}

CMTS_INLINE_ALWAYS static ufastptr round_to_cache_alignment(ufastptr value)
{
	return (value + FALSE_SHARING_THRESHOLD_MASK) & (~FALSE_SHARING_THRESHOLD_MASK);
}

CMTS_INLINE_ALWAYS static ufast64 make_handle(ufast32 index, ufast32 generation)
{
	uint64 r = generation;
	r <<= 32;
	r |= index;
	return r;
}

CMTS_INLINE_ALWAYS static void split_handle(ufast64 handle, ufast32& out_index, ufast32& out_generation)
{
	out_index = (uint32)handle;
	handle >>= 32;
	out_generation = (uint32)handle;
}

CMTS_INLINE_ALWAYS static void initialize_thread_local_state(os::thread_parameter_type param)
{
#ifdef CMTS_WINDOWS
	worker_thread_index = (uint32)(ufastptr)param;
	CMTS_INVARIANT(worker_thread_index < worker_thread_count);
	root_task = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH);
	CMTS_INVARIANT(root_task != nullptr);
#endif
	(void)memset(cached_indices, 0xff, sizeof(cached_indices));
}

CMTS_INLINE_ALWAYS static ufast32 adjust_queue_index(ufast32 index)
{
	//ufast32 low = index >> adjust_queue_index_shift;
	//ufast32 high = index << FALSE_SHARING_THRESHOLD_LOG2;
	//index = low | high;
	index &= queue_capacity_mask;
	return index;
}

CMTS_INLINE_ALWAYS static bool is_valid_task(ufast32 index)
{
	if (index >= max_tasks)
		return false;
	if (index >= task_pool_header.bump.load(std::memory_order_acquire))
		return false;
	return true;
}

CMTS_INLINE_ALWAYS static void submit_task(ufast32 task_index, ufast8 priority)
{
	task_data& task = task_pool[task_index];
	CMTS_INVARIANT(task.state.load(std::memory_order_acquire) == task_state::INACTIVE);
	CMTS_INVARIANT(task.function != nullptr);
	CMTS_INVARIANT(is_valid_task(task_index));
	shared_queue_header& queue = queues[priority];
	spin_while_eq(queue.size, max_tasks);
	ufast32 index = queue.head.fetch_add(1, std::memory_order_acquire);
	index = adjust_queue_index(index);
	CMTS_INVARIANT(index < max_tasks);
	std::atomic<uint32>& target = queue.values[index];
	spin_while_neq(target, NIL_INDEX);
#ifdef CMTS_DEBUG
	ufast32 prior = target.exchange(task_index, std::memory_order_release);
	CMTS_INVARIANT(prior == NIL_INDEX);
#else
	target.store(task_index, std::memory_order_release);
#endif
	(void)queue.size.fetch_add(1, std::memory_order_relaxed);
#ifdef CMTS_NO_BUSY_WAIT
	queue_futex::signal_submission();
#endif
}

CMTS_INLINE_ALWAYS static ufast32 try_fetch_task(ufast8 priority)
{
	CMTS_INVARIANT(priority < CMTS_MAX_PRIORITY);
	shared_queue_header& queue = queues[priority];
	CMTS_LIKELY_IF(queue.size.load(std::memory_order_acquire) == 0)
		return NIL_INDEX;
	ufast32& cached_index = cached_indices[priority];
	ufast32 index = cached_index;
	CMTS_LIKELY_IF(index == NIL_INDEX)
	{
		index = queue.tail.fetch_add(1, std::memory_order_release);
		index = adjust_queue_index(index);
		cached_index = index;
	}
	std::atomic<uint32>& target = queue.values[index];
	ufast32 task_index;
	const ufast32 max_retries = 1 + (CMTS_MAX_PRIORITY - priority);
	for (ufast32 i = 0;;)
	{
		task_index = target.load(std::memory_order_acquire);
		++i;
		if (i == max_retries || task_index != NIL_INDEX)
			break;
	}
	CMTS_UNLIKELY_IF(task_index == NIL_INDEX)
		return NIL_INDEX;
	cached_index = NIL_INDEX;
	target.store(NIL_INDEX, std::memory_order_release);
	CMTS_INVARIANT(is_valid_task(task_index));
	task_data& task = task_pool[task_index];
	CMTS_INVARIANT(task.function != nullptr);
	(void)queue.size.fetch_sub(1, std::memory_order_relaxed);
	return task_index;
}

CMTS_INLINE_ALWAYS static task_data& get_current_task()
{
	CMTS_INVARIANT(cmts_is_task());
	CMTS_INVARIANT(is_valid_task(current_task_index));
	return task_pool[current_task_index];
}

CMTS_INLINE_ALWAYS static ufast32 fetch_task()
{
	for (;; finalize_check())
	{
#ifdef CMTS_NO_BUSY_WAIT
		ufast32 generation = queue_futex::get_generation();
#endif
		for (ufast8 priority = 0; priority != CMTS_MAX_PRIORITY; ++priority)
		{
			ufast32 r = try_fetch_task(priority);
			CMTS_UNLIKELY_IF(r != NIL_INDEX)
				return r;
		}

#ifdef CMTS_NO_BUSY_WAIT
		queue_futex::await_submission(generation);
#endif
	}
}

CMTS_INLINE_ALWAYS static void yield_impl()
{
#ifdef CMTS_WINDOWS
	CMTS_INVARIANT(root_task != nullptr);
	SwitchToFiber(root_task);
	CMTS_INVARIANT(root_task != nullptr);
#endif
}

CMTS_INLINE_ALWAYS static void sleep_impl()
{
	get_current_task().state.store(task_state::GOING_TO_SLEEP, std::memory_order_release);
	yield_impl();
}

CMTS_INLINE_ALWAYS static void wake_task(ufast32 index)
{
	spin_while_neq(task_pool[index].state, task_state::SLEEPING);
	task_pool[index].state.store(task_state::INACTIVE, std::memory_order_release);
	submit_task(index, task_pool[index].priority);
}

CMTS_INLINE_ALWAYS static void wait_queue_init(wait_queue& queue)
{
	non_atomic_store(queue.tail, (wait_queue_node*)&queue.head);
	non_atomic_store(queue.head, nullptr);
	non_atomic_store(queue.done, false);
}

CMTS_INLINE_ALWAYS static bool wait_queue_reset(wait_queue& queue)
{
	if (!queue.done.load(std::memory_order_acquire))
		return false;
	wait_queue_init(queue);
	return true;
}

// This queue uses a slightly modified version of Mellor-Crummey and Scott's spinlock algorithm:
CMTS_INLINE_ALWAYS static bool wait_queue_push(wait_queue& queue)
{
	wait_queue_node node;
	non_atomic_store(node.next, nullptr);
	node.index = current_task_index;
	wait_queue_node* prior;
	for (;; CMTS_SPIN_WAIT())
	{
		prior = queue.tail.load(std::memory_order_acquire);
		if (prior == nullptr)
			return false;
		if (queue.tail.compare_exchange_weak(prior, &node, std::memory_order_release, std::memory_order_relaxed))
			break;
	}
	prior->next.store(&node, std::memory_order_release);
	sleep_impl();
	return true;
}

CMTS_INLINE_ALWAYS static bool wait_queue_submit(wait_queue& queue)
{
	wait_queue_node* tail = queue.tail.exchange(nullptr, std::memory_order_acquire);
	bool flag = tail == (wait_queue_node*)&queue.head;
	if (tail == nullptr || flag)
		return flag;
	wait_queue_node* n;
	wait_queue_node* next;
	for (;; CMTS_SPIN_WAIT())
	{
		n = queue.head.load(std::memory_order_acquire);
		if (n != nullptr)
			break;
	}
	queue.done.store(true, std::memory_order_release);
	while (true)
	{
		wake_task(n->index);
		if (n == tail)
			break;
		for (;; CMTS_SPIN_WAIT())
		{
			next = n->next.load(std::memory_order_acquire);
			if (next != nullptr)
				break;
		}
		n = next;
	}
	return true;
}

CMTS_INLINE_ALWAYS static ufast32 try_acquire_task()
{
	index_generation_pair expected, desired;
	expected = task_pool_header.freelist.load(std::memory_order_acquire);
	CMTS_LIKELY_IF(expected.index != NIL_INDEX)
	{
		desired.index = task_pool[expected.index].next;
		desired.generation = expected.generation + 1;
		CMTS_LIKELY_IF(task_pool_header.freelist.compare_exchange_weak(expected, desired, std::memory_order_acquire, std::memory_order_relaxed))
			return expected.index;
	}
	else
	{
		CMTS_LIKELY_IF(task_pool_header.bump.load(std::memory_order_acquire) < max_tasks)
		{
			ufast32 r = task_pool_header.bump.fetch_add(1, std::memory_order_acquire);
			CMTS_LIKELY_IF(r < max_tasks)
				return r;
			ufast32 expected_bump = task_pool_header.bump.load(std::memory_order_acquire);
			CMTS_UNLIKELY_IF(expected_bump > max_tasks)
				(void)task_pool_header.bump.compare_exchange_weak(expected_bump, max_tasks, std::memory_order_release, std::memory_order_relaxed);
		}
	}
	return NIL_INDEX;
}

CMTS_INLINE_ALWAYS static ufast32 acquire_task_blocking()
{
	ufast32 r;
	for (;; cmts_yield())
	{
		for (ufast8 i = 0; i != CMTS_SPIN_THRESHOLD; ++i)
		{
			r = try_acquire_task();
			CMTS_LIKELY_IF(r != NIL_INDEX)
				return r;
			CMTS_SPIN_WAIT();
		}
	}
}

CMTS_INLINE_ALWAYS static void release_task(ufast32 index)
{
	CMTS_INVARIANT(task_pool[index].next == NIL_INDEX);
	CMTS_INVARIANT(is_valid_task(index));
	task_data& task = task_pool[index];
	++task.generation;
	task.function = nullptr;
	task.parameter = nullptr;
	task.priority = 0;
	task.sync_type = CMTS_SYNC_TYPE_NONE;
	task.sync_object = nullptr;
	for (;; CMTS_SPIN_WAIT())
	{
		index_generation_pair expected, desired;
		expected = task_pool_header.freelist.load(std::memory_order_acquire);
		task.next = expected.index;
		desired.index = index;
		desired.generation = expected.generation + 1;
		CMTS_LIKELY_IF(task_pool_header.freelist.compare_exchange_weak(expected, desired, std::memory_order_release, std::memory_order_relaxed))
			break;
	}
}

static os::thread_return_type CMTS_WORKER_THREAD_CALLING_CONVENTION worker_thread_entry_point(os::thread_parameter_type param)
{
	initialize_thread_local_state(param);
	while (true)
	{
		finalize_check();
		ufast32 index = fetch_task();
		CMTS_INVARIANT(is_valid_task(index));
		current_task_index = index;
		task_data& task = task_pool[index];
		CMTS_INVARIANT(task.function != nullptr);
		CMTS_INVARIANT(task.has_stack());
		task.state.store(task_state::RUNNING, std::memory_order_release);
#ifdef CMTS_WINDOWS
		SwitchToFiber(task.handle);
#endif
		CMTS_INVARIANT(index == current_task_index);
		bool to_sleep = non_atomic_load(task.state) == task_state::GOING_TO_SLEEP;
		if (to_sleep)
			task.state.store(task_state::SLEEPING, std::memory_order_release);
		if (task.function != nullptr)
		{
			if (!to_sleep)
				submit_task(index, task.priority);
		}
		else
		{
			CMTS_INVARIANT(!to_sleep);
			ufast8 sync_type = task.sync_type;
			void* sync_object = task.sync_object;
			release_task(index);
			if (sync_type == 0)
				continue;
			CMTS_INVARIANT((uint32)sync_type <= 2);
			CMTS_INVARIANT(sync_object != nullptr);
			using signal_ptr_type = void(*)(void*);
			signal_ptr_type signal = (signal_ptr_type)cmts_event_signal;
			if (sync_type == CMTS_SYNC_TYPE_COUNTER)
				signal = (signal_ptr_type)cmts_counter_signal;
			signal(sync_object);
		}
	}
	return 0;
}

static void CMTS_WORKER_TASK_CALLING_CONVENTION task_entry_point(void* param)
{
	CMTS_INVARIANT(param != nullptr);
	while (true)
	{
		CMTS_INVARIANT(current_task_index < max_tasks);
		task_data& task = task_pool[current_task_index];
		CMTS_INVARIANT(task.function != nullptr);
		task.function(task.parameter);
		task.function = nullptr;
		cmts_yield();
		finalize_check();
	}
}

struct ext_header
{
	const ext_header* next;
	cmts_ext_type_t type;
};

CMTS_INLINE_ALWAYS static void handle_extension(const cmts_init_options_t& options, const ext_header* node)
{
	switch (node->type)
	{
	case CMTS_EXT_TYPE_DEBUGGER:
#ifdef CMTS_DEBUG
		debugger::init(*(const cmts_ext_debugger_init_options_t*)node);
#endif
		break;
	default:
		abort();
	}
}

CMTS_INLINE_ALWAYS static ufastptr required_library_buffer_size()
{
	ufastptr r = 0;
	r += sizeof(*worker_threads) * worker_thread_count;
	r += sizeof(task_data) * max_tasks;
	r += sizeof(std::atomic<uint32>) * max_tasks * CMTS_MAX_PRIORITY;
	return r;
}

CMTS_INLINE_ALWAYS static ufastptr get_extension_sizes(const cmts_ext_type_t* extensions, uint32_t count)
{
	ufastptr r = 0;
	const cmts_ext_type_t* i = extensions;
	const cmts_ext_type_t* end = i + count;

#ifdef CMTS_DEBUG
	for (; i != end; ++i)
		for (const cmts_ext_type_t* j = i + 1; j != end; ++j)
			CMTS_INVARIANT(*j != *i);
	i = extensions;
#endif

	for (; i != end; ++i)
	{
		CMTS_INVARIANT(enum_range_check(*i, CMTS_EXT_TYPE_MIN_ENUM, CMTS_EXT_TYPE_MAX_ENUM));
		switch (*i)
		{
		case CMTS_EXT_TYPE_TASK_NAME:
			r += max_tasks * sizeof(ext_task_name_data);
			break;
		default:
			CMTS_INVARIANT(false);
		}
	}
	return r;
}

CMTS_INLINE_ALWAYS static void library_common_init(uint8* buffer)
{
	ufastptr thread_size = round_to_cache_alignment(sizeof(*worker_threads) * worker_thread_count);
	ufastptr task_size = round_to_cache_alignment(sizeof(task_data) * max_tasks);
	ufastptr queue_size = round_to_cache_alignment(sizeof(std::atomic<uint32>) * max_tasks);
	worker_threads = (decltype(worker_threads))buffer;
	buffer += thread_size;
	task_pool = (task_data*)buffer;
	buffer += task_size;
	for (shared_queue_header& queue : queues)
	{
		non_atomic_store(queue.head, 0);
		non_atomic_store(queue.tail, 0);
		queue.values = (std::atomic<uint32>*)buffer;
		(void)memset((void*)queue.values, 0xff, sizeof(std::atomic<uint32>) * max_tasks);
		buffer += queue_size;
	}
	task_pool_header.initialize();
	event_pool_header.initialize();
	counter_pool_header.initialize();
	for (ufast32 i = 0; i != max_tasks; ++i)
	{
		(void)memset(task_pool + i, 0, sizeof(task_data));
		task_pool[i].next = NIL_INDEX;
	}
}

static cmts_result_t default_library_init()
{
	ufast32 cpu_count = cmts_processor_count();
	worker_thread_count = cpu_count;
	max_tasks = CMTS_DEFAULT_TASKS_PER_PROCESSOR * cpu_count;
	CMTS_INVARIANT(CMTS_POPCOUNT(max_tasks) == 1);
	task_stack_size = cmts_default_task_stack_size();
	ufastptr buffer_size = required_library_buffer_size();
	uint8* buffer = (uint8*)os::allocate(buffer_size);
	CMTS_UNLIKELY_IF(buffer == nullptr)
		return CMTS_ERROR_MEMORY_ALLOCATION;
	library_common_init(buffer);
#ifdef CMTS_WINDOWS
	for (ufast32 i = 0; i != worker_thread_count; ++i)
	{
		worker_threads[i] = os::new_thread(worker_thread_entry_point, (void*)(uintptr)i, task_stack_size, true);
		CMTS_UNLIKELY_IF(worker_threads[i] == nullptr)
			return CMTS_ERROR_WORKER_THREAD_CREATION;
	}
	CMTS_UNLIKELY_IF(!os::set_thread_affinities(worker_threads, worker_thread_count, 0))
		return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
	CMTS_UNLIKELY_IF(!os::resume_threads(worker_threads, worker_thread_count))
		return CMTS_ERROR_RESUME_WORKER_THREAD;
#endif
	return CMTS_OK;
}

static cmts_result_t custom_library_init(const cmts_init_options_t& options)
{
	worker_thread_count = options.thread_count;
	max_tasks = options.max_tasks;
	CMTS_INVARIANT(CMTS_POPCOUNT(max_tasks) == 1);
	task_stack_size = options.task_stack_size;
	ufastptr buffer_size = required_library_buffer_size();
	uint8* buffer;
	if (options.allocate_function == nullptr)
		buffer = (uint8*)os::allocate(buffer_size);
	else
		buffer = (uint8*)options.allocate_function(buffer_size);
	CMTS_UNLIKELY_IF(buffer == nullptr)
		return CMTS_ERROR_MEMORY_ALLOCATION;
	library_common_init(buffer);
#ifdef CMTS_WINDOWS
	bool use_affinity = (options.flags & CMTS_INIT_FLAGS_USE_AFFINITY) != 0;
	for (ufast32 i = 0; i != worker_thread_count; ++i)
	{
		worker_threads[i] = os::new_thread(worker_thread_entry_point, (void*)(uintptr)i, options.task_stack_size, use_affinity);
		CMTS_UNLIKELY_IF(worker_threads[i] == nullptr)
			return CMTS_ERROR_WORKER_THREAD_CREATION;
	}
	if (use_affinity)
	{
		CMTS_UNLIKELY_IF(!os::set_thread_affinities(worker_threads, worker_thread_count, 0))
			return CMTS_ERROR_THREAD_AFFINITY_FAILURE;
		CMTS_UNLIKELY_IF(!os::resume_threads(worker_threads, worker_thread_count))
			return CMTS_ERROR_RESUME_WORKER_THREAD;
	}
#endif

	for (const ext_header* node = (const ext_header*)options.ext; node != nullptr; node = node->next)
		handle_extension(options, node);

	return CMTS_OK;
}

static cmts_result_t dispatch_default_options(cmts_task_function_pointer_t entry_point)
{
	ufast32 index = try_acquire_task();
	CMTS_UNLIKELY_IF(index == NIL_INDEX)
		return CMTS_ERROR_TASK_POOL_CAPACITY;
	CMTS_INVARIANT(is_valid_task(index));
	task_data& task = task_pool[index];
	task.function = entry_point;
	task.parameter = nullptr;
	task.sync_object = nullptr;
	task.next = NIL_INDEX;
	++task.generation;
	task.priority = 0;
	task.sync_type = CMTS_SYNC_TYPE_NONE;
	CMTS_INVARIANT(non_atomic_load(task.state) == task_state::INACTIVE);
#ifdef CMTS_WINDOWS
	CMTS_UNLIKELY_IF(task.handle == nullptr)
		task.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, task_entry_point, &task);
#endif
	CMTS_UNLIKELY_IF(!task.has_stack())
	{
		release_task(index);
		return CMTS_ERROR_TASK_ALLOCATION;
	}
	submit_task(index, task.priority);
	return CMTS_OK;
}



extern "C"
{
	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_init(const cmts_init_options_t* options)
	{
		cmts_result_t result;
		CMTS_INVARIANT(!library_is_initialized.load(std::memory_order_acquire));
		library_guard guard;
		if (!os::initialize())
			return CMTS_ERROR_OS_INIT;
		if (options == nullptr)
			result = default_library_init();
		else
			result = custom_library_init(*options);
		CMTS_UNLIKELY_IF(result < 0)
			return result;
		queue_capacity_mask = max_tasks - 1;
		adjust_queue_index_shift = CMTS_FAST_LOG2(max_tasks) - SHARED_QUEUE_BASE_SHIFT;
		non_atomic_store(library_exit_flag, false);
		library_is_initialized.store(true, std::memory_order_release);
		return result;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_pause()
	{
		if (library_is_paused.exchange(true, std::memory_order_acquire))
			return CMTS_OK;
		if (!library_is_initialized.load(std::memory_order_acquire))
			return CMTS_ERROR_LIBRARY_UNINITIALIZED;
		library_guard guard;
		if (!os::suspend_threads(worker_threads, worker_thread_count))
			return CMTS_ERROR_SUSPEND_WORKER_THREAD;
		return CMTS_OK;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_resume()
	{
		if (!library_is_paused.load(std::memory_order_acquire))
			return CMTS_OK;
		if (!library_is_initialized.load(std::memory_order_acquire))
			return CMTS_ERROR_LIBRARY_UNINITIALIZED;
		library_guard guard;
		if (!os::resume_threads(worker_threads, worker_thread_count))
			return CMTS_ERROR_SUSPEND_WORKER_THREAD;
		library_is_paused.store(false, std::memory_order_release);
		return CMTS_OK;
	}

	CMTS_ATTR void CMTS_CALL cmts_lib_exit_signal()
	{
		library_exit_flag.store(true, std::memory_order_release);
		if (cmts_is_task())
			exit_thread();
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_exit_await(cmts_deallocate_function_pointer_t deallocate)
	{
		CMTS_UNLIKELY_IF(!os::await_threads(worker_threads, worker_thread_count))
			return CMTS_ERROR_AWAIT_WORKER_THREAD;
		library_guard guard;
		for (ufast32 i = 0; i != non_atomic_load(task_pool_header.bump); ++i)
		{
			task_data& task = task_pool[i];
#ifdef CMTS_DEBUG
			if (task.handle != nullptr)
			{
				DeleteFiber(task.handle);
				task.handle = nullptr;
			}
#endif
		}
		ufastptr buffer_size = required_library_buffer_size();
		bool flag;
		if (deallocate != nullptr)
			flag = deallocate(worker_threads, buffer_size);
		else
			flag = os::deallocate(worker_threads, buffer_size);
		CMTS_UNLIKELY_IF(!flag)
			return CMTS_ERROR_MEMORY_DEALLOCATION;
		library_is_initialized.store(false, std::memory_order_release);
		return CMTS_OK;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_terminate(cmts_deallocate_function_pointer_t deallocate)
	{
		cmts_lib_exit_signal();
		library_guard guard;
		if (!os::terminate_threads(worker_threads, worker_thread_count))
			return CMTS_ERROR_WORKER_THREAD_TERMINATION;
		ufastptr buffer_size = required_library_buffer_size();
		bool flag;
		if (deallocate != nullptr)
			flag = deallocate(worker_threads, buffer_size);
		else
			flag = os::deallocate(worker_threads, buffer_size);
		CMTS_UNLIKELY_IF(!flag)
			return CMTS_ERROR_MEMORY_DEALLOCATION;
		library_is_initialized.store(false, std::memory_order_release);
		return CMTS_OK;
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_lib_is_initialized()
	{
		return library_is_initialized.load(std::memory_order_acquire);
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_lib_is_online()
	{
		CMTS_UNLIKELY_IF(!cmts_lib_is_initialized())
			return false;
		return !library_exit_flag.load(std::memory_order_acquire);
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_lib_is_paused()
	{
		return library_is_paused.load(std::memory_order_acquire);
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_lib_minimize(const cmts_minimize_options_t* options)
	{
		return CMTS_OK;
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_is_task()
	{
#ifdef CMTS_WINDOWS
		return root_task != nullptr;
#endif
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_dispatch(cmts_task_function_pointer_t entry_point, cmts_dispatch_options_t* options)
	{
		CMTS_UNLIKELY_IF(options == nullptr)
			return dispatch_default_options(entry_point);
		CMTS_INVARIANT(options->ext == nullptr);
		CMTS_INVARIANT(options->sync_type <= CMTS_SYNC_TYPE_MAX_ENUM);
		bool blocking_acquire = (options->flags & CMTS_DISPATCH_FLAGS_FORCE) != 0;
		ufast32 index;
		if (blocking_acquire)
			index = acquire_task_blocking();
		else
			index = try_acquire_task();
		CMTS_INVARIANT(!blocking_acquire || index != NIL_INDEX);
		CMTS_UNLIKELY_IF(index == NIL_INDEX)
			return CMTS_ERROR_TASK_POOL_CAPACITY;
		CMTS_INVARIANT(is_valid_task(index));
		task_data& task = task_pool[index];
		CMTS_INVARIANT(task.function == nullptr);
		task.function = entry_point;
		task.parameter = options->parameter;
		task.sync_object = options->sync_object;
		task.next = NIL_INDEX;
		++task.generation;
		task.priority = options->priority;
		task.sync_type = options->sync_type;
		CMTS_INVARIANT(task.state.load(std::memory_order_acquire) == task_state::INACTIVE);
#ifdef CMTS_WINDOWS
		CMTS_UNLIKELY_IF(task.handle == nullptr)
			task.handle = CreateFiberEx(task_stack_size, task_stack_size, FIBER_FLAG_FLOAT_SWITCH, task_entry_point, &task);
#endif
		CMTS_UNLIKELY_IF(!task.has_stack())
		{
			release_task(index);
			return CMTS_ERROR_TASK_POOL_CAPACITY;
		}
		if (options->out_task_id != nullptr)
			*options->out_task_id = make_handle(index, task.generation);
		submit_task(index, task.priority);
		return CMTS_OK;
	}

	CMTS_ATTR void CMTS_CALL cmts_yield()
	{
		CMTS_INVARIANT(cmts_is_task());
		task_pool[current_task_index].state.store(task_state::INACTIVE, std::memory_order_release);
		yield_impl();
	}

	CMTS_ATTR void CMTS_CALL cmts_exit()
	{
		CMTS_INVARIANT(cmts_is_task());
		task_pool[current_task_index].function = nullptr;
		task_pool[current_task_index].state.store(task_state::INACTIVE, std::memory_order_release);
		yield_impl();
	}

	CMTS_ATTR cmts_task_id_t CMTS_CALL cmts_this_task_id()
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(is_valid_task(current_task_index));
		return make_handle(current_task_index, task_pool[current_task_index].generation);
	}

	CMTS_ATTR uint8_t CMTS_CALL cmts_this_task_priority()
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(is_valid_task(current_task_index));
		uint8 r = task_pool[current_task_index].priority;
		CMTS_INVARIANT(r < CMTS_MAX_PRIORITY);
		return r;
	}

	CMTS_ATTR void CMTS_CALL cmts_this_task_set_priority(uint8_t new_priority)
	{
		CMTS_INVARIANT(new_priority < CMTS_MAX_PRIORITY);
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(is_valid_task(current_task_index));
		task_pool[current_task_index].priority = new_priority;
	}

	CMTS_ATTR cmts_task_function_pointer_t CMTS_CALL cmts_this_task_function()
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(is_valid_task(current_task_index));
		return task_pool[current_task_index].function;
	}

	CMTS_ATTR void* CMTS_CALL cmts_this_task_parameter()
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(is_valid_task(current_task_index));
		return task_pool[current_task_index].parameter;
	}

	CMTS_NODISCARD CMTS_ATTR uint32_t CMTS_CALL cmts_tls_new(cmts_destructor_function_pointer_t destructor)
	{
		return FlsAlloc(destructor);
	}

	CMTS_ATTR void CMTS_CALL cmts_tls_delete(uint32_t id)
	{
		bool success = FlsFree(id);
		CMTS_INVARIANT(success);
	}

	CMTS_ATTR void* CMTS_CALL cmts_tls_get(uint32_t id)
	{
		return FlsGetValue(id);
	}

	CMTS_ATTR void CMTS_CALL cmts_tls_set(uint32_t id, void* ptr)
	{
		bool success = FlsSetValue(id, ptr);
		CMTS_INVARIANT(success);
	}

	CMTS_ATTR void CMTS_CALL cmts_event_init(cmts_event_t* event_ptr)
	{
		CMTS_INVARIANT(event_ptr != nullptr);
		event_data& event = *(event_data*)event_ptr;
		wait_queue_init(event.queue);
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_event_signal(cmts_event_t* event_ptr)
	{
		CMTS_INVARIANT(event_ptr != nullptr);
		event_data& event = *(event_data*)event_ptr;
		if (!wait_queue_submit(event.queue))
			return CMTS_SYNC_OBJECT_EXPIRED;
		return CMTS_OK;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_event_await(cmts_event_t* event_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(event_ptr != nullptr);
		event_data& event = *(event_data*)event_ptr;
		if (!wait_queue_push(event.queue))
			return CMTS_SYNC_OBJECT_EXPIRED;
		return CMTS_OK;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_event_reset(cmts_event_t* event_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(event_ptr != nullptr);
		event_data& event = *(event_data*)event_ptr;
		if (!wait_queue_reset(event.queue))
			return CMTS_NOT_READY;
		return CMTS_OK;
	}

	CMTS_ATTR void CMTS_CALL cmts_counter_init(cmts_counter_t* counter_ptr, uint32_t start_value)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(counter_ptr != nullptr);
		counter_data& counter = *(counter_data*)counter_ptr;
		memset(counter_ptr, 0, sizeof(cmts_counter_t));
		non_atomic_store(counter.value, start_value);
		wait_queue_init(counter.queue);
	}

	CMTS_ATTR cmts_result_t CMTS_CALL CMTS_CALL cmts_counter_signal(cmts_counter_t* counter_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(counter_ptr != nullptr);
		counter_data& counter = *(counter_data*)counter_ptr;
		if (counter.queue.tail.load(std::memory_order_acquire) == nullptr)
			return CMTS_SYNC_OBJECT_EXPIRED;
		CMTS_LIKELY_IF(counter.value.fetch_sub(1, std::memory_order_acquire) != 1)
			return CMTS_NOT_READY;
		if (!wait_queue_submit(counter.queue))
			return CMTS_SYNC_OBJECT_EXPIRED;
		return CMTS_OK;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_counter_await(cmts_counter_t* counter_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(counter_ptr != nullptr);
		counter_data& counter = *(counter_data*)counter_ptr;
		CMTS_LIKELY_IF(wait_queue_push(counter.queue))
			return CMTS_OK;
		return CMTS_SYNC_OBJECT_EXPIRED;
	}

	CMTS_ATTR cmts_result_t CMTS_CALL cmts_counter_reset(cmts_counter_t* counter_ptr, uint32_t new_start_value)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(counter_ptr != nullptr);
		counter_data& counter = *(counter_data*)counter_ptr;
		if (!wait_queue_reset(counter.queue))
			return CMTS_NOT_READY;
		non_atomic_store(counter.value, new_start_value);
		return CMTS_OK;
	}

	CMTS_ATTR void CMTS_CALL cmts_mutex_init(cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		abort();
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_mutex_is_locked(const cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		abort();
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_mutex_try_lock(cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_mutex_lock(cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		task_data& task = task_pool[current_task_index];
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_mutex_lock_spin(cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_mutex_unlock(cmts_mutex_t* mutex_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(mutex_ptr != nullptr);
		mutex_data& mutex = *(mutex_data*)mutex_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_rwlock_init(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_rwlock_is_writing(const cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		const std::atomic<rwlock_data>& rwlock = *(const std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR uint32_t CMTS_CALL cmts_rwlock_reader_count(const cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		const std::atomic<rwlock_data>& rwlock = *(const std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_rwlock_read_try_lock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_rwlock_read_lock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_rwlock_read_unlock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR cmts_bool_t CMTS_CALL cmts_rwlock_write_try_lock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_rwlock_write_lock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR void CMTS_CALL cmts_rwlock_write_unlock(cmts_rwlock_t* rwlock_ptr)
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(rwlock_ptr != nullptr);
		std::atomic<rwlock_data>& rwlock = *(std::atomic<rwlock_data>*)rwlock_ptr;
		abort();
	}

	CMTS_ATTR uint32_t CMTS_CALL cmts_this_worker_thread_index()
	{
		CMTS_INVARIANT(cmts_is_task());
		CMTS_INVARIANT(worker_thread_index < worker_thread_count);
		return worker_thread_index;
	}

	CMTS_ATTR uint32_t CMTS_CALL cmts_worker_thread_count()
	{
		return worker_thread_count;
	}

	CMTS_ATTR uint32_t CMTS_CALL cmts_processor_count()
	{
		uint32_t cpu_count;
#ifdef CMTS_WINDOWS
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		cpu_count = info.dwNumberOfProcessors;
#endif
		return cpu_count;
	}

	CMTS_ATTR uint32_t CMTS_CALL cmts_this_processor_index()
	{
#ifdef CMTS_WINDOWS
		PROCESSOR_NUMBER k;
		GetCurrentProcessorNumberEx(&k);
		return ((uint32_t)k.Group << 6U) | (uint32_t)k.Number;
#endif
	}

	CMTS_ATTR size_t CMTS_CALL cmts_default_task_stack_size()
	{
		uintptr size;
#ifdef CMTS_WINDOWS
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		size = info.dwAllocationGranularity;
#endif
		return size;
	}

	CMTS_ATTR cmts_bool_t CMTS_ATTR cmts_ext_debugger_enabled()
	{
#ifdef CMTS_DEBUG
		return debugger::callback != nullptr;
#else
		return false;
#endif
	}

	CMTS_ATTR void CMTS_ATTR cmts_ext_task_name_set(cmts_task_id_t id, const CMTS_CHAR* name, size_t length)
	{
		CMTS_INVARIANT(ext_task_names != nullptr);
		ufast32 index, generation;
		split_handle(id, index, generation);
		CMTS_INVARIANT(is_valid_task(index));
		CMTS_INVARIANT(task_pool[index].generation == generation);
		ext_task_name_data& data = ext_task_names[index];
		ext_task_name_view new_value;
		new_value.begin = name;
		new_value.length = length;
		data.name.store(new_value, std::memory_order_release);
	}

	CMTS_ATTR void CMTS_ATTR cmts_ext_task_name_swap(cmts_task_id_t id, const CMTS_CHAR* name, size_t length, const CMTS_CHAR** out_old_name, size_t* out_old_length)
	{
		CMTS_INVARIANT(ext_task_names != nullptr);
		ufast32 index, generation;
		split_handle(id, index, generation);
		CMTS_INVARIANT(is_valid_task(index));
		CMTS_INVARIANT(task_pool[index].generation == generation);
		ext_task_name_data& data = ext_task_names[index];
		ext_task_name_view new_value;
		new_value.begin = name;
		new_value.length = length;
		ext_task_name_view prior = data.name.exchange(new_value, std::memory_order_release);
		*out_old_name = prior.begin;
		*out_old_length = prior.length;
	}

	CMTS_ATTR void CMTS_ATTR cmts_ext_task_name_get(cmts_task_id_t id, const CMTS_CHAR** out_name, size_t* out_length)
	{
		CMTS_INVARIANT(ext_task_names != nullptr);
		ufast32 index, generation;
		split_handle(id, index, generation);
		CMTS_INVARIANT(is_valid_task(index));
		CMTS_INVARIANT(task_pool[index].generation == generation);
		ext_task_name_view value = ext_task_names[index].name.load(std::memory_order_acquire);
		*out_name = value.begin;
		*out_length = value.length;
	}

	CMTS_ATTR void CMTS_ATTR cmts_ext_task_name_remove(cmts_task_id_t id)
	{
		CMTS_INVARIANT(ext_task_names != nullptr);
		ufast32 index, generation;
		split_handle(id, index, generation);
		CMTS_INVARIANT(is_valid_task(index));
		CMTS_INVARIANT(task_pool[index].generation == generation);
		ext_task_names[index].name.store({}, std::memory_order_release);
	}

};

#ifdef CMTS_CPP_INCLUDED
namespace cmts
{
}
#endif

#endif