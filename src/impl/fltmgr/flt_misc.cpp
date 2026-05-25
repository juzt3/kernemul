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

	redirect_function(
		[emulator]
		{
			const auto driver_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto registration = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto ret_filter = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			THREAD_LOG("FltRegisterFilter called (driver=0x{:X}, registration=0x{:X}, ret_filter=0x{:X})",
				driver_object, registration, ret_filter);

			// allocate a fake filter object
			if (ret_filter)
			{
				const auto fake_filter = emulator->heap_allocate(0x100, prot_read_write, true);
				emulator_err_t error = fake_filter.error_or({});
				error.throw_if("FltRegisterFilter: allocate fake filter");

				error = emulator->write_virtual_memory(ret_filter, &fake_filter.value(), sizeof(fake_filter.value()));
				error.throw_if("FltRegisterFilter: write filter pointer");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"FltRegisterFilter"
	);

	redirect_function(
		[emulator]
		{
			const auto filter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltStartFiltering called (filter=0x{:X})", filter);

			write_nt_success(emulator);
		},
		mapped_image,
		"FltStartFiltering"
	);

	redirect_function(
		[emulator]
		{
			const auto filter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltUnregisterFilter called (filter=0x{:X})", filter);
		},
		mapped_image,
		"FltUnregisterFilter"
	);
}
