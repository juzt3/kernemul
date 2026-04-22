#include "flt_misc.hpp"

void redirect_fltmgr_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltAcquirePushLockExclusive called (push_lock=0x{:X})", push_lock);
		},
		mapped_image,
		"FltAcquirePushLockExclusive"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltReleasePushLock called (push_lock=0x{:X})", push_lock);
		},
		mapped_image,
		"FltReleasePushLock"
	);
}
