#pragma once
#include <Windows.h>
#include <WinHvPlatform.h>
#include <unordered_map>
#include <stdexcept>
#include <optional>
#include <vector>
#include <memory>
#include <span>

#include "guest_memory.hpp"
#include "guest_vmexit.hpp"

#define SET_EXTENDED_VMEXIT_EXITING(vmexit_name, field_name)\
	bool set_##vmexit_name##_exiting(const bool state) const\
	{\
		WHV_EXTENDED_VM_EXITS extended_vmexits = query_extended_vmexits();\
		\
		if (extended_vmexits.field_name != state)\
		{\
			extended_vmexits.field_name = state;\
			\
			return set_extended_vmexits(extended_vmexits);\
		}\
		\
		return true;\
	}

#define SET_EXCEPTION_EXITING(exception_name, exception_type)\
	bool set_##exception_name##_exception_exiting(const bool state) const\
	{\
		constexpr std::uint64_t mask = 1ull << exception_type;\
		\
		bitmap_type exception_bitmap = query_exception_exit_bitmap();\
		\
		if (((exception_bitmap & mask) != 0) != state)\
		{\
			if (state)\
			{\
				exception_bitmap |= mask;\
			}\
			else\
			{\
				exception_bitmap &= ~mask;\
			}\
			\
			return set_exception_exit_bitmap(exception_bitmap);\
		}\
		\
		return true;\
	}

namespace hm
{
	class guest_virtual_processor_t;
	struct guest_register_t;

	class guest_partition_t : public std::enable_shared_from_this<guest_partition_t>
	{
	public:
		using address_type = std::uintptr_t;
		using size_type = std::size_t;
		using protection_type = std::uint32_t;
		using handle_type = WHV_PARTITION_HANDLE;
		using bitmap_type = std::uint64_t;

		static constexpr size_type page_size = 0x1000;

		explicit guest_partition_t(size_type processor_count);

		~guest_partition_t();

		[[nodiscard]] bool configure();
	[[nodiscard]] bool finalize();

		[[nodiscard]] handle_type handle() const;

		[[nodiscard]] std::span<guest_virtual_processor_t> virtual_processors();
		[[nodiscard]] std::span<const guest_virtual_processor_t> virtual_processors() const;

		bool run_virtual_processor(guest_virtual_processor_t& virtual_processor, vmexit_context_t& vmexit_context);
		bool stop_virtual_processor(guest_virtual_processor_t& virtual_processor);

		bool map_physical_memory(address_type physical_address, size_type size, protection_type protection);
		bool unmap_physical_memory(address_type physical_address, size_type size);

		[[nodiscard]] bool is_physical_address_valid(address_type physical_address) const;

		[[nodiscard]] std::optional<protection_type> query_physical_memory_protection(address_type physical_address) const;
		bool protect_physical_memory(address_type physical_address, size_type size, protection_type protection);

		bool write_physical_memory(address_type physical_address, const void* buffer, size_type size);
		bool write_physical_memory(address_type physical_address, std::span<const std::uint8_t> buffer);

		bool read_physical_memory(address_type physical_address, void* buffer, size_type size) const;
		bool read_physical_memory(address_type physical_address, std::span<std::uint8_t> buffer) const;

		[[nodiscard]] std::optional<address_type> translate_virtual_address(const guest_virtual_processor_t& virtual_processor, address_type virtual_address) const;

		bool write_virtual_memory(guest_virtual_processor_t& virtual_processor, address_type virtual_address, const void* buffer, size_type size);
		bool write_virtual_memory(guest_virtual_processor_t& virtual_processor, address_type virtual_address, std::span<const std::uint8_t> buffer);

		bool read_virtual_memory(const guest_virtual_processor_t& virtual_processor, address_type virtual_address, void* buffer, size_type size) const;
		bool read_virtual_memory(const guest_virtual_processor_t& virtual_processor, address_type virtual_address, std::span<std::uint8_t> buffer) const;

		bool write_register(guest_virtual_processor_t& virtual_processor, const guest_register_t& guest_register, const void* value, size_type size);
		bool read_register(const guest_virtual_processor_t& virtual_processor, const guest_register_t& guest_register, void* value, size_type size) const;

		bool register_vmexit_callback(vmexit_reason_t reason, const vmexit_callback_t::routine_type& routine);

		bool run_vmexit_callbacks(guest_virtual_processor_t& virtual_processor, vmexit_context_t& context) const;

		bool set_msr_bitmap(const WHV_PARTITION_PROPERTY& property);
		bool set_msr_action_list(std::span<const WHV_MSR_ACTION_ENTRY> entries);
		bool set_unimplemented_msr_action(WHV_MSR_ACTION action);

		SET_EXCEPTION_EXITING(debug, WHvX64ExceptionTypeDebugTrapOrFault)
		SET_EXCEPTION_EXITING(invalid_opcode, WHvX64ExceptionTypeInvalidOpcodeFault)
		SET_EXCEPTION_EXITING(page_fault, WHvX64ExceptionTypePageFault)

		SET_EXTENDED_VMEXIT_EXITING(cpuid, X64CpuidExit)
		SET_EXTENDED_VMEXIT_EXITING(rdtsc, X64RdtscExit)
		SET_EXTENDED_VMEXIT_EXITING(msr_access, X64MsrExit)
		SET_EXTENDED_VMEXIT_EXITING(apic_smi_trap, X64ApicSmiExitTrap)
		SET_EXTENDED_VMEXIT_EXITING(hypercall, HypercallExit)
		SET_EXTENDED_VMEXIT_EXITING(apic_init_sipi_trap, X64ApicInitSipiExitTrap)
		SET_EXTENDED_VMEXIT_EXITING(exception, ExceptionExit)

	protected:
		bool create_partition();
		bool delete_partition();

		bool create_virtual_processors();

		bool set_partition_property(WHV_PARTITION_PROPERTY_CODE code, const WHV_PARTITION_PROPERTY& property) const;
		bool set_code_processor_count(size_type count) const;
		bool set_extended_vmexits(WHV_EXTENDED_VM_EXITS extended_vmexits) const;
		bool set_exception_exit_bitmap(bitmap_type exception_bitmap) const;

		std::optional<WHV_PARTITION_PROPERTY> get_partition_property(WHV_PARTITION_PROPERTY_CODE code) const;

		WHV_EXTENDED_VM_EXITS query_extended_vmexits() const;
		bitmap_type query_exception_exit_bitmap() const;

		bool copy_physical_memory(address_type physical_address, void* buffer, size_type size, memory_copy_direction_t direction) const;
		bool copy_virtual_memory(const guest_virtual_processor_t& virtual_processor, address_type virtual_address, void* buffer, size_type size, memory_copy_direction_t direction) const;

		std::optional<mapped_memory_t> find_physical_mapping(address_type physical_address) const;

		handle_type handle_ = nullptr;
		std::vector<guest_virtual_processor_t> virtual_processors_;
		std::vector<vmexit_callback_t> vmexit_callbacks_;

		// <mapped guest physical address, mapping info>
		std::unordered_map<address_type, mapped_memory_t> physical_page_mappings_;
	};
}
