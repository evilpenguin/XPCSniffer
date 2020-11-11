/*
 * XPCSniffer
 *
 * Created by EvilPenguin
 */

#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#include <syslog.h>

#include "libproc/libproc.h"
#include "xpc/xpc.h"
#include "substrate.h"

#pragma mark - functions

static NSString *_xpcsniffer_get_timestring();
static NSMutableDictionary *_xpcsniffer_dictionary(xpc_connection_t connection);
static NSString *_xpcsniffer_connection_name(xpc_connection_t connection);
static NSString *_xpcsniffer_proc_name(int pid);
static bool _xpcsniffer_message_dump(const char *key, xpc_object_t value, NSMutableDictionary *logDictionary) ;
static bool _xpcsniffer_dumper(xpc_object_t obj, NSMutableDictionary *logDictionary);

#pragma mark - private

#ifdef DEBUG
	#define DLog(FORMAT, ...) syslog(LOG_ERR, "+[XPCSniffer] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else 
	#define DLog(...) (void)0
#endif

static NSString *_xpcsniffer_get_timestring() {
	time_t now = time(NULL);
	char *timeString = ctime(&now);
	timeString[strlen(timeString) - 1] = '\0';

	return [NSString stringWithUTF8String:timeString];
}

static NSMutableDictionary *_xpcsniffer_dictionary(xpc_connection_t connection) {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
	dictionary[@"connection_address"] = [NSString stringWithFormat:@"%p", connection];
	dictionary[@"connection_time"] = _xpcsniffer_get_timestring();
	dictionary[@"xpc_message"] = [NSMutableDictionary dictionary];

	return dictionary;
}

static NSString *_xpcsniffer_connection_name(xpc_connection_t connection) {
	const char *name = xpc_connection_get_name(connection);
	if (name) return @(name);

	return @"?";
}

static NSString *_xpcsniffer_proc_name(int pid) {
	static char buffer[2048];
	proc_name(pid, buffer, 2048);

	if (strlen(buffer) == 0) {
		buffer[0] = '?';
	}

	return @(buffer);
}

static bool _xpcsniffer_message_dump(const char *key, xpc_object_t value, NSMutableDictionary *logDictionary) {
	NSString *logKey = [NSString stringWithUTF8String:key];
	xpc_type_t type = xpc_get_type(value);

	if (type == XPC_TYPE_NULL)		  logDictionary[logKey] = @"NULL";
	else if (type == XPC_TYPE_ACTIVITY) logDictionary[logKey] = @"Activity";
	else if (type == XPC_TYPE_DATE)	 logDictionary[logKey] = @"Date";
	else if (type == XPC_TYPE_SHMEM)	logDictionary[logKey] = @"Shared memory";
	else if (type == XPC_TYPE_ENDPOINT) logDictionary[logKey] = @"XPC Endpoint";
	else if (type == XPC_TYPE_BOOL)	 logDictionary[logKey] = @(xpc_bool_get_value(value));
	else if (type == XPC_TYPE_DOUBLE)   logDictionary[logKey] = @(xpc_double_get_value(value));
	else if (type == XPC_TYPE_INT64)	logDictionary[logKey] = @(xpc_int64_get_value(value));
	else if (type == XPC_TYPE_UINT64)   logDictionary[logKey] = @(xpc_uint64_get_value(value));
	else if (type == XPC_TYPE_STRING)   logDictionary[logKey] = @(xpc_string_get_string_ptr(value));
	else if (type == XPC_TYPE_UUID) { 
		char buf[256];
		uuid_unparse(xpc_uuid_get_bytes(value), buf);
		logDictionary[logKey] = @(buf);
	}
	else if (type == XPC_TYPE_FD) {
		char buf[4096];
		int fd = xpc_fd_dup(value);
		fcntl(fd, F_GETPATH, buf);

		logDictionary[logKey] = @(buf);
	}
	else if (type == XPC_TYPE_DATA) {
		size_t length = xpc_data_get_length(value);
		const char *bytes = (const char *)xpc_data_get_bytes_ptr(value);

		if (bytes) {
			NSMutableString *hexString = [NSMutableString string];
			for (int i = 0; i < length; i++) [hexString appendFormat:@"%02x ", (unsigned char)bytes[i]];
			logDictionary[logKey] = hexString;
		}
	}
	else if (type == XPC_TYPE_ARRAY) {
		_xpcsniffer_dumper(value, logDictionary);
	}
	else if (type == XPC_TYPE_DICTIONARY) {
		_xpcsniffer_dumper(value, logDictionary);
	}
	else {
		logDictionary[logKey] = [NSString stringWithFormat:@"Unknown: %p", type]; 
	}

	return true;
}

static bool _xpcsniffer_dumper(xpc_object_t obj, NSMutableDictionary *logDictionary) {
	xpc_type_t type = xpc_get_type(obj);

	if (type == XPC_TYPE_CONNECTION) {		
		int pid = xpc_connection_get_pid(obj);
		logDictionary[@"connection_name"] = _xpcsniffer_connection_name(obj);
		logDictionary[@"process_id"] = @(pid);
		logDictionary[@"process_name"] = _xpcsniffer_proc_name(pid);
	}
	else if (type == XPC_TYPE_ARRAY) {
		size_t count = xpc_array_get_count(obj);
		if (count > 0) {
			xpc_array_apply(obj, ^(size_t index, xpc_object_t value) {
				NSString *key = [NSString stringWithFormat:@"array_level_%lu", index];
				logDictionary[key] = [NSMutableDictionary dictionary];

				return _xpcsniffer_dumper(value, logDictionary[key]);
			});
		}
	}
	else if (type == XPC_TYPE_DICTIONARY) {
		size_t count = xpc_dictionary_get_count(obj);
		if (count > 0) {
			xpc_dictionary_apply(obj, ^(const char *key, xpc_object_t value) {
				return _xpcsniffer_message_dump(key, value, logDictionary);
			});
		}
	}

	return true;
}

static void _xpcsniffer_log_to_file(NSDictionary *dictionary) {
	NSString *cachesDirectory = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
	NSString *logPath = [cachesDirectory stringByAppendingPathComponent:@"XPCSniffer.log"];
	NSLog(@"+[XPCSniffer] Writing to %@", logPath);

	if (![NSFileManager.defaultManager fileExistsAtPath:logPath]) {
		[NSData.data writeToFile:logPath atomically:YES];
	} 

	// Make message
	NSError *err = nil;
	NSData *jsonData = [NSJSONSerialization  dataWithJSONObject:dictionary options:0 error:&err];
	NSString *message = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
	message = [message stringByAppendingString:@"\n"];

	// append
	NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:logPath];
	[handle truncateFileAtOffset:handle.seekToEndOfFile];
	[handle writeData:[message dataUsingEncoding:NSUTF8StringEncoding]];
	[handle closeFile];
}

#pragma mark - xpc_connection_create

// xpc_connection_t xpc_connection_create(const char *name, dispatch_queue_t targetq);
__unused static xpc_connection_t (*orig_xpc_connection_create)(const char *name, dispatch_queue_t targetq);
__unused static xpc_connection_t new_xpc_connection_create(const char *name, dispatch_queue_t targetq) {
	DLog(@"xpc_connection_create(\"%s\", targetq=%p);", name, targetq);

	xpc_connection_t returned = orig_xpc_connection_create(name, targetq);
	DLog(@"orig_xpc_connection_create(%p)", returned);

	return returned;
}

#pragma mark - xpc_pipe_routine

// int xpc_pipe_routine(xpc_object_t xpcPipe, xpc_object_t *in, xpc_object_t *out);
__unused static int (*orig_xpc_pipe_routine)(xpc_object_t xpcPipe, xpc_object_t *in, xpc_object_t *out);
__unused static int new_xpc_pipe_routine (xpc_object_t xpcPipe, xpc_object_t *in, xpc_object_t *out) {
	// Call orig
	int returnValue = orig_xpc_pipe_routine(xpcPipe, in, out);

	// Log
	xpc_object_t message = *out;
	NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(message);
	logDictionary[@"pipe_desc"] = @(xpc_copy_description(xpcPipe));
	_xpcsniffer_dumper(message, logDictionary[@"xpc_message"]);
	DLog(@"XPC_PRO %@", logDictionary);

	return returnValue;
}

#pragma mark - xpc_connection_send_message

// void xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message);
__unused static void (*orig_xpc_connection_send_message)(xpc_connection_t connection, xpc_object_t message);
__unused static void new_xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message) {
	NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection);

	_xpcsniffer_dumper(connection, logDictionary);
	_xpcsniffer_dumper(message, logDictionary[@"xpc_message"]);

	DLog(@"XPC_CSM %@", logDictionary);
	_xpcsniffer_log_to_file(logDictionary);

	orig_xpc_connection_send_message(connection, message);
}

#pragma mark - xpc_connection_send_message_with_reply

// void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler);
__unused static void (*orig_xpc_connection_send_message_with_reply)(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler);
__unused static void new_xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler) {
	NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection);

	_xpcsniffer_dumper(connection, logDictionary);
	_xpcsniffer_dumper(message, logDictionary[@"xpc_message"]);
	DLog(@"XPC_CSMR %@", logDictionary);
	_xpcsniffer_log_to_file(logDictionary);

	orig_xpc_connection_send_message_with_reply(connection, message, replyq, handler);
}

#pragma mark - xpc_connection_send_message_with_reply_sync

// xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message);
__unused static xpc_object_t (*orig_xpc_connection_send_message_with_reply_sync)(xpc_connection_t connection, xpc_object_t message);
__unused static xpc_object_t new_xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message) {
	NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection);

	_xpcsniffer_dumper(connection, logDictionary);
	_xpcsniffer_dumper(message, logDictionary[@"xpc_message"]);
	DLog(@"XPC_CSMRS %@", logDictionary);
	_xpcsniffer_log_to_file(logDictionary);

	return orig_xpc_connection_send_message_with_reply_sync(connection, message);
}

#pragma mark - ctor

%ctor {
	@autoreleasepool {	 
		DLog(@"~~ Hooking ~~");
		void *libxpc_handle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW);
		DLog(@"libxpc: %p", libxpc_handle);

		// xpc_connection_create
		void *xpc_connection_create = dlsym(libxpc_handle, "xpc_connection_create");
		if (xpc_connection_create) {
			DLog(@"xpc_connection_create %p", xpc_connection_create);
			MSHookFunction((void *)xpc_connection_create, (void *)new_xpc_connection_create, (void **)&orig_xpc_connection_create);
		}

		// xpc_pipe_routine
		void *xpc_pipe_routine = dlsym(libxpc_handle, "xpc_pipe_routine");
		if (xpc_pipe_routine) {
			DLog(@"xpc_pipe_routine %p", xpc_pipe_routine);
			MSHookFunction((void *)xpc_pipe_routine, (void *)new_xpc_pipe_routine, (void **)&orig_xpc_pipe_routine);
		}

		// xpc_connection_send_message
		void *xpc_connection_send_message = dlsym(libxpc_handle, "xpc_connection_send_message");
		if (xpc_connection_send_message) {
			DLog(@"xpc_connection_send_message %p", xpc_connection_send_message);
			MSHookFunction((void *)xpc_connection_send_message, (void *)new_xpc_connection_send_message, (void **)&orig_xpc_connection_send_message);
		}

		// xpc_connection_send_message_with_reply
		void *xpc_connection_send_message_with_reply = dlsym(libxpc_handle, "xpc_connection_send_message_with_reply");
		if (xpc_connection_send_message_with_reply) {
			DLog(@"xpc_connection_send_message_with_reply %p", xpc_connection_send_message_with_reply);
			MSHookFunction((void *)xpc_connection_send_message_with_reply, (void *)new_xpc_connection_send_message_with_reply, (void **)&orig_xpc_connection_send_message_with_reply);
		}

		// xpc_connection_send_message_with_reply_sync
		void *xpc_connection_send_message_with_reply_sync = dlsym(libxpc_handle, "xpc_connection_send_message_with_reply_sync");
		if (xpc_connection_send_message_with_reply_sync) {
			DLog(@"xpc_connection_send_message_with_reply_sync %p", xpc_connection_send_message_with_reply_sync);
			MSHookFunction((void *)xpc_connection_send_message_with_reply_sync, (void *)new_xpc_connection_send_message_with_reply_sync, (void **)&orig_xpc_connection_send_message_with_reply_sync);
		}
		DLog(@"~~ End Hooking ~~");
	}
}