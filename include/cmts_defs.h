#define CMTS_MAX_TASKS UINT32_MAX

#ifndef CMTS_CALL
	#define CMTS_CALL
#endif

#ifndef CMTS_ATTR
	#define CMTS_ATTR
#endif

#ifndef CMTS_PTR
	#define CMTS_PTR
#endif

#ifndef CMTS_NODISCARD
	#define CMTS_NODISCARD
	#ifdef __cplusplus
		#if __has_cpp_attribute(nodiscard)
			#undef CMTS_NODISCARD
			#define CMTS_NODISCARD [[nodiscard]]
		#endif
	#endif
#endif

#ifndef CMTS_NORETURN
	#define CMTS_NORETURN
	#ifdef __cplusplus
		#if __has_cpp_attribute(noreturn)
			#undef CMTS_NORETURN
			#define CMTS_NORETURN [[noreturn]]
		#endif
	#endif
#endif

#ifndef CMTS_MAX_PRIORITY
	#define CMTS_MAX_PRIORITY 3
#endif

#if CMTS_MAX_PRIORITY >= 256
	#error "Error, CMTS_MAX_PRIORITY must not exceed 256"
#endif

#ifndef CMTS_DEFAULT_TASKS_PER_PROCESSOR
	#define CMTS_DEFAULT_TASKS_PER_PROCESSOR 256
#endif

#ifndef CMTS_SPIN_THRESHOLD
	#define CMTS_SPIN_THRESHOLD 16
#endif

#ifndef CMTS_EVENT_NO_PADDING
	#define CMTS_EVENT_DATA_SIZE 64
#else
	#define CMTS_EVENT_DATA_SIZE 32
#endif

#ifndef CMTS_COUNTER_NO_PADDING
	#define CMTS_COUNTER_DATA_SIZE 64
#else
	#define CMTS_COUNTER_DATA_SIZE 32
#endif

#ifndef CMTS_SPINLOCK_NO_PADDING
	#define CMTS_SPINLOCK_DATA_SIZE 64
#else
	#define CMTS_SPINLOCK_DATA_SIZE (sizeof(void*))
#endif

#ifndef CMTS_MUTEX_NO_PADDING
	#define CMTS_MUTEX_DATA_SIZE 64
#else
	#define CMTS_MUTEX_DATA_SIZE 4
#endif

#ifndef CMTS_RWLOCK_NO_PADDING
	#define CMTS_RWLOCK_DATA_SIZE 64
#else
	#define CMTS_RWLOCK_DATA_SIZE 32
#endif
#define CMTS_RWLOCK_MAX_READERS ((1U << 31U) - 1U)

#ifndef CMTS_CHAR
	#define CMTS_CHAR char
#endif

#ifndef CMTS_TEXT
	#define CMTS_TEXT(string_literal) string_literal
#endif

#ifndef CMTS_EXTERN_C_BEGIN
	#define CMTS_EXTERN_C_BEGIN extern "C" {
#endif

#ifndef CMTS_EXTERN_C_END
	#define CMTS_EXTERN_C_END }
#endif