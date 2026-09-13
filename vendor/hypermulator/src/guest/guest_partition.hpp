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
		std::uint64_t exception_bitmap = query_exception_exit_bitmap();\
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
	class vcpu;
	struct reg_t;

	class partition : public std::enable_shared_from_this<partition>
	{
	public:
		static constexpr std::size_t page_size = 0x1000;

		explicit partition(std::size_t cpu_count);

		~partition();

		[[nodiscard]] bool set_up();

		[[nodiscard]] WHV_PARTITION_HANDLE handle() const;

		[[nodiscard]] std::span<vcpu> cpus();
		[[nodiscard]] std::span<const vcpu> cpus() const;

		bool run_vcpu(vcpu& cpu, vmexit_context& context);
		bool stop_vcpu(vcpu& cpu);

		bool map_phys_mem(addr_t phys_addr, std::size_t size, mem_prot prot);
		bool unmap_phys_mem(addr_t phys_addr, std::size_t size);

		[[nodiscard]] bool is_phys_addr_valid(addr_t phys_addr) const;

		[[nodiscard]] std::optional<mem_prot> query_phys_mem_prot(addr_t phys_addr) const;
		bool prot_phys_mem(addr_t phys_addr, std::size_t size, mem_prot prot);

		bool write_phys_mem(addr_t phys_addr, const void* buf, std::size_t size);
		bool write_phys_mem(addr_t phys_addr, std::span<const std::uint8_t> buf);

		bool read_phys_mem(addr_t phys_addr, void* buf, std::size_t size) const;
		bool read_phys_mem(addr_t phys_addr, std::span<std::uint8_t> buf) const;

		[[nodiscard]] std::optional<addr_t> virt_to_phys(const vcpu& cpu, addr_t virt_addr) const;

		bool write_virt_mem(vcpu& cpu, addr_t virt_addr, const void* buf, std::size_t size);
		bool write_virt_mem(vcpu& cpu, addr_t virt_addr, std::span<const std::uint8_t> buf);

		bool read_virt_mem(const vcpu& cpu, addr_t virt_addr, void* buf, std::size_t size) const;
		bool read_virt_mem(const vcpu& cpu, addr_t virt_addr, std::span<std::uint8_t> buf) const;

		bool reg_write(vcpu& cpu, const reg_t& r, const void* value, std::size_t size);
		bool reg_read(const vcpu& cpu, const reg_t& r, void* value, std::size_t size) const;

		bool register_vmexit_cb(vmexit_reason reason, const vmexit_callback::routine_t& cb);

		bool run_vmexit_cbs(vcpu& cpu, vmexit_context& context) const;

		SET_EXCEPTION_EXITING(debug, WHvX64ExceptionTypeDebugTrapOrFault)
		SET_EXCEPTION_EXITING(invalid_opcode, WHvX64ExceptionTypeInvalidOpcodeFault)
		SET_EXCEPTION_EXITING(page_fault, WHvX64ExceptionTypePageFault)
		SET_EXCEPTION_EXITING(divide_error, WHvX64ExceptionTypeDivideErrorFault)
		SET_EXCEPTION_EXITING(breakpoint, WHvX64ExceptionTypeBreakpointTrap)
		SET_EXCEPTION_EXITING(general_protection, WHvX64ExceptionTypeGeneralProtectionFault)

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

		bool create_vcpus();

		bool set_partition_property(WHV_PARTITION_PROPERTY_CODE code, const WHV_PARTITION_PROPERTY& property) const;
		bool set_cpu_count(std::size_t count) const;
		bool set_extended_vmexits(WHV_EXTENDED_VM_EXITS extended_vmexits) const;
		bool set_exception_exit_bitmap(std::uint64_t exception_bitmap) const;

		std::optional<WHV_PARTITION_PROPERTY> get_partition_property(WHV_PARTITION_PROPERTY_CODE code) const;

		WHV_EXTENDED_VM_EXITS query_extended_vmexits() const;
		std::uint64_t query_exception_exit_bitmap() const;

		bool copy_phys_mem(addr_t phys_addr, void* buf, std::size_t size, mem_copy_dir direction) const;
		bool copy_virt_mem(const vcpu& cpu, addr_t virt_addr, void* buf, std::size_t size, mem_copy_dir direction) const;

		std::optional<mapped_mem> find_phys_mapping(addr_t phys_addr) const;

		WHV_PARTITION_HANDLE handle_ = nullptr;
		std::vector<vcpu> cpus_;
		std::vector<vmexit_callback> vmexit_cbs_;

		// <mapped guest physical address, mapping info>
		std::unordered_map<addr_t, mapped_mem> phys_page_mappings_;
	};
}
