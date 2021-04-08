/*
	Copyright 2021 Marcel Pi Nacy

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/



#ifndef CMTS_CPP_INCLUDED
#define CMTS_CPP_INCLUDED

#include "cmts.h"
#include <iterator>
#include <string_view>
#ifdef CMTS_DEBUG
#include <cassert>
#endif

namespace cmts
{
#ifdef UNICODE
	using string_view_type = std::string_view;
#else
	using string_view_type = std::wstring_view;
#endif

	using task_function_pointer = void(CMTS_PTR*)(void* parameter);
	using allocate_function_pointer = void* (CMTS_PTR*)(size_t size);
	using deallocate_function_pointer = bool(CMTS_PTR*)(void* memory, size_t size);
	using destructor_function_pointer = void(CMTS_PTR*)(void* object);

	enum class result : int8_t
	{
		OK = 0,
		SYNC_OBJECT_EXPIRED = 1,
		NOT_READY = 2,
		TIMEOUT = 3,

		ERROR_MEMORY_ALLOCATION = -1,
		ERROR_MEMORY_DEALLOCATION = -2,
		ERROR_WORKER_THREAD_CREATION = -3,
		ERROR_THREAD_AFFINITY_FAILURE = -4,
		ERROR_RESUME_WORKER_THREAD = -5,
		ERROR_SUSPEND_WORKER_THREAD = -6,
		ERROR_WORKER_THREAD_TERMINATION = -7,
		ERROR_AWAIT_WORKER_THREAD = -8,
		ERROR_TASK_POOL_CAPACITY = -9,
		ERROR_AFFINITY = -10,
		ERROR_TASK_ALLOCATION = -11,
		ERROR_FUTEX = -12,
		ERROR_LIBRARY_UNINITIALIZED = -13,
		ERROR_OS_INIT = -14,

		RESULT_MIN_ENUM = ERROR_LIBRARY_UNINITIALIZED,
		RESULT_MAX_ENUM = NOT_READY,
	};

	enum class sync_type : uint8_t
	{
		NONE,
		EVENT,
		COUNTER,

		MIN_ENUM = NONE,
		MAX_ENUM = COUNTER,
	};

	enum class dispatch_flags : uint64_t
	{
		FORCE = 1,
	};

	enum class init_flags : uint64_t
	{
		USE_AFFINITY = 1,
	};

	enum class extension_type : uint32_t
	{
		TASK_NAME,
		DEBUGGER,

		MIN_ENUM = TASK_NAME,
		MAX_ENUM = DEBUGGER,
	};

	enum class task_id : cmts_task_id_t {};

	struct init_options
	{
		allocate_function_pointer allocate_function;
		size_t task_stack_size;
		uint32_t thread_count;
		init_flags flags;
		uint32_t max_tasks;
		uint32_t enabled_extension_count;
		const extension_type* enabled_extensions;
		const void* ext;
	};

	struct dispatch_options
	{
		dispatch_flags flags;
		task_id* out_task_id;
		void* parameter;
		void* sync_object;
		sync_type sync_object_type;
		uint8_t priority;
		const void* ext;
	};

	struct minimize_options
	{
		const void* ext;
		uint64_t timeout_nanoseconds;
	};

	namespace sync
	{
		struct fence : cmts_fence_t
		{
			constexpr fence() noexcept
				: cmts_fence_t{ CMTS_FENCE_INIT }
			{
			}

			fence(const fence&) = delete;
			fence& operator=(const fence&) = delete;
			~fence() = default;

			inline void await() noexcept
			{
				cmts_fence_await((cmts_fence_t*)this);
			}

			inline void signal() noexcept
			{
				cmts_fence_signal((cmts_fence_t*)this);
			}
		};

		struct event : cmts_event_t
		{
			constexpr event() noexcept
				: cmts_event_t{ CMTS_EVENT_INIT }
			{
			}

			event(const event&) = delete;
			event& operator=(const event&) = delete;
			~event() = default;

			inline result reset() noexcept
			{
				return (result)cmts_event_reset((cmts_event_t*)this);
			}

			inline result await() noexcept
			{
				return (result)cmts_event_await((cmts_event_t*)this);
			}

			inline void signal() noexcept
			{
				return (result)cmts_event_signal((cmts_event_t*)this);
			}
		};

		struct counter : cmts_counter_t
		{
			constexpr counter(uint32_t start_value) noexcept
				: cmts_counter_t{ CMTS_COUNTER_INIT(start_value) }
			{
			}

			counter(const counter&) = delete;
			counter& operator=(const counter&) = delete;
			~counter() = default;

			inline result reset(uint32_t new_value) noexcept
			{
				return (result)cmts_counter_reset((cmts_counter_t*)this, new_value);
			}

			inline result await() noexcept
			{
				return (result)cmts_counter_await((cmts_counter_t*)this);
			}

			inline uint32_t value() const noexcept
			{
				return cmts_counter_value((const cmts_counter_t*)this);
			}

			inline void operator++(int unused) noexcept
			{
				return (result)cmts_counter_increment((cmts_counter_t*)this);
			}

			inline void operator++() noexcept
			{
				return (result)cmts_counter_increment((cmts_counter_t*)this);
			}

			inline void operator--(int unused) noexcept
			{
				return (result)cmts_counter_decrement((cmts_counter_t*)this);
			}

			inline void operator--() noexcept
			{
				return (result)cmts_counter_decrement((cmts_counter_t*)this);
			}
		};

		struct mutex : cmts_mutex_t
		{
			constexpr mutex() noexcept
				: cmts_mutex_t{ CMTS_MUTEX_INIT }
			{
			}

			mutex(const mutex&) = delete;
			mutex& operator=(const mutex&) = delete;
			~mutex() = default;

			inline bool is_locked() const noexcept
			{
				return cmts_mutex_is_locked((const cmts_mutex_t*)this);
			}

			inline bool try_lock() noexcept
			{
				return cmts_mutex_try_lock((cmts_mutex_t*)this);
			}

			inline void lock() noexcept
			{
				cmts_mutex_lock((cmts_mutex_t*)this);
			}

			inline void unlock() noexcept
			{
				cmts_mutex_unlock((cmts_mutex_t*)this);
			}
		};
	}



	inline result dispatch(void(*function)()) noexcept
	{
		return (result)cmts_dispatch((task_function_pointer)function, nullptr);
	}

	inline result dispatch(task_function_pointer function) noexcept
	{
		return (result)cmts_dispatch(function, nullptr);
	}

	inline result dispatch(task_function_pointer function, const dispatch_options& options) noexcept
	{
		return (result)cmts_dispatch(function, &options);
	}

	inline bool is_task() noexcept
	{
		return cmts_is_task();
	}



	inline result init() noexcept
	{
		return (result)cmts_init(nullptr);
	}

	inline result init(const init_options& options) noexcept
	{
		return (result)cmts_init((cmts_init_options_t)&options);
	}

	inline result pause() noexcept
	{
		return (result)cmts_pause();
	}

	inline result resume() noexcept
	{
		return (result)cmts_resume();
	}

	inline result exit_signal() noexcept
	{
		return (result)cmts_finalize_signal();
	}

	inline result exit_await() noexcept
	{
		return (result)cmts_finalize_await();
	}

	inline result terminate() noexcept
	{
		return (result)cmts_terminate();
	}

	inline bool is_initialized() noexcept
	{
		return cmts_is_initialized();
	}

	inline bool is_online() noexcept
	{
		return cmts_is_online();
	}

	inline bool is_paused()
	{
		return cmts_is_paused();
	}

	inline result purge(uint32_t max_trimmed_tasks, deallocate_function_pointer deallocate)
	{
		return (result)cmts_purge(max_trimmed_tasks, deallocate);
	}

	inline result purge_all()
	{
		return (result)cmts_purge_all();
	}

	inline uint32_t worker_thread_count()
	{
		return cmts_worker_thread_count();
	}



	namespace task
	{
		[[nodiscard]]
		inline task_id allocate()
		{
			return (task_id)cmts_task_allocate();
		}

		inline void deallocate(task_id id)
		{
			cmts_task_deallocate((cmts_task_id_t)id);
		}

		inline uint8_t get_priority(task_id id)
		{
			return cmts_task_get_priority((cmts_task_id_t)id);
		}

		inline void set_priority(task_id id, uint8_t priority)
		{
			cmts_task_set_priority((cmts_task_id_t)id, priority);
		}

		inline task_function_pointer get_function(task_id id)
		{
			return cmts_task_get_function((cmts_task_id_t)id);
		}

		inline void set_function(task_id id, cmts_task_function_pointer_t function)
		{
			cmts_task_set_function((cmts_task_id_t)id, function);
		}

		inline void* get_parameter(task_id id)
		{
			return cmts_task_get_parameter((cmts_task_id_t)id);
		}

		inline void set_parameter(task_id id, void* parameter)
		{
			cmts_task_set_parameter((cmts_task_id_t)id, parameter);
		}

		inline void attach_event(task_id id, sync::event& event)
		{
			cmts_task_attach_event((cmts_task_id_t)id, (cmts_event_t*)&event);
		}

		inline void attach_counter(task_id id, sync::counter& counter)
		{
			cmts_task_attach_counter((cmts_task_id_t)id, (cmts_counter_t*)&counter);
		}

		inline void sleep(task_id id)
		{
			cmts_task_sleep((cmts_task_id_t)id);
		}

		inline void wake(task_id id)
		{
			cmts_task_wake((cmts_task_id_t)id);
		}

		inline bool is_valid(task_id id)
		{
			return cmts_task_is_valid((cmts_task_id_t)id);
		}

		inline bool is_sleeping(task_id id)
		{
			return cmts_task_is_sleeping((cmts_task_id_t)id);
		}

		inline bool is_running(task_id id)
		{
			return cmts_task_is_running((cmts_task_id_t)id);
		}

		inline void dispatch(task_id id)
		{
			cmts_task_dispatch((cmts_task_id_t)id);
		}
	}



	namespace this_task
	{
		inline void yield()
		{
			cmts_yield();
		}

		inline void exit()
		{
			cmts_exit();
		}

		inline void id()
		{
			return (task_id)cmts_this_task_id();
		}
	}



	namespace this_thread
	{
		inline uint32_t index()
		{
			return cmts_this_worker_thread_index();
		}

		inline void enable_yield_trap()
		{
			cmts_enable_yield_trap();
		}

		inline void disable_yield_trap()
		{
			cmts_disable_yield_trap();
		}
	}



	namespace platform
	{
		inline uint32_t processor_count()
		{
			return cmts_processor_count();
		}

		inline uint32_t this_processor_index()
		{
			return cmts_this_processor_index();
		}

		inline uint32_t default_task_stack_size()
		{
			return cmts_default_task_stack_size();
		}
	}



	namespace ext
	{
		namespace debugger
		{
			enum class message_severity : uint8_t
			{
				INFO,
				WARNING,
				ERROR
			};

			struct message_info
			{
				const CMTS_CHAR* message_ptr;
				size_t message_length;
				message_severity severity;
				const void* ext;
			};

			using message_function_pointer = void(CMTS_CALL*)(void* context, const message_info* message);

			struct init_info
			{
				const void* next;
				extension_type ext_type = extension_type::DEBUGGER;
				void* context;
				message_function_pointer message_callback;
			};

			inline bool is_enabled()
			{
				return cmts_ext_debugger_enabled();
			}
		}

		namespace task_name
		{
			inline bool is_enabled()
			{
				return cmts_ext_task_name_enabled();
			}

			inline void set(task_id id, string_view_type name)
			{
				cmts_ext_task_name_set(id, name.data(), name.size());
			}

			inline void clear(task_id id)
			{
				cmts_ext_task_name_clear(id);
			}

			inline string_view_type get(task_id id)
			{
				const CMTS_CHAR* prior_ptr;
				size_t prior_size;
				cmts_ext_task_name_get(id, &prior_ptr, &prior_size);
				return string_view_type(prior_ptr, prior_size);
			}

			inline string_view_type swap(task_id id, string_view_type name)
			{
				const CMTS_CHAR* prior_ptr;
				size_t prior_size;
				cmts_ext_task_name_swap(id, name.data(), name.size(), &prior_ptr, &prior_size);
				return string_view_type(prior_ptr, prior_size);
			}
		}
	}

	namespace util
	{
		template <typename I, typename F>
		void parallel_for(I begin, I end, F&& body, uint8_t priority = 0)
		{
#ifdef CMTS_DEBUG
			assert(is_task());
#endif

			if (begin == end)
				return;

			struct loop_state
			{
				F function;
				I iterator;
				sync::fence fence;
			};

			loop_state state = { ::std::forward<F>(body), begin };

			uint32_t delta;
			if constexpr (std::is_integral_v<I>)
				delta = end - begin;
			else
				delta = std::distance(begin, end);

#ifdef CMTS_DEBUG
			assert(delta <= UINT32_MAX);
#endif

			auto counter = sync::counter(delta);

			dispatch_options options = {};
			options.flags = dispatch_flags::FORCE;
			options.sync_object_type = sync_type::COUNTER;
			options.sync_object = &counter;
			options.priority = priority;

			for (; state.iterator != end; ++state.iterator)
			{
				state.fence = {};
				dispatch([&](void* param)
				{
					loop_state& state = *(loop_state*)param;
					I it = state.iterator;
					state.fence.signal();
					state.function(it);
				}, options);
				state.fence.await();
			}
			counter.await();
		}

		template <typename I, typename K, typename F>
		void parallel_for(I begin, I end, K step, F&& body, uint8_t priority = 0)
		{
#ifdef CMTS_DEBUG
			assert(is_task());
#endif

			if (begin == end)
				return;

			struct loop_state
			{
				F function;
				I iterator;
				sync::fence fence;
			};

			loop_state state = { ::std::forward<F>(body), begin };

			uint32_t delta;
			if constexpr (std::is_integral_v<I>)
				delta = end - begin;
			else
				delta = std::distance(begin, end);

#ifdef CMTS_DEBUG
			assert(delta <= UINT32_MAX);
#endif

			auto counter = sync::counter(delta);

			dispatch_options options = {};
			options.flags = dispatch_flags::FORCE;
			options.sync_object_type = sync_type::COUNTER;
			options.sync_object = &counter;
			options.priority = priority;

			for (; state.iterator != end; state.iterator += step)
			{
				state.fence = {};
				dispatch([&](void* param)
				{
					loop_state& state = *(loop_state*)param;
					I it = state.iterator;
					state.fence.signal();
					state.function(it);
				}, options);
				state.fence.await();
			}
			counter.await();
		}
	}
}
#endif