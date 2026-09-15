#pragma once
#include "../guest/guest_partition.hpp"
#include "../guest/guest_register.hpp"
#include "../guest/guest_virtual_processor.hpp"

#include <limits>
#include <variant>

namespace hm
{
	enum class hook_insn_t : std::uint8_t
	{
		rdtsc,
		cpuid
	};

	struct hook_mem_t
	{
		mem_prot prot;

		[[nodiscard]] bool exits_on(const mem_vmexit::access access) const
		{
			return (access == mem_vmexit::access::read && prot & prot_read) ||
				(access == mem_vmexit::access::write && prot & prot_write) ||
				(access == mem_vmexit::access::execute && prot & prot_exec);
		}
	};

	struct hook_basic_block_t
	{

	};

	struct hook_excp_t
	{
		exception_mask mask;

		[[nodiscard]] bool covers(const exception_id id) const
		{
			return (mask & to_exception_mask(id)) != excp_none;
		}
	};

	enum class hook_type : std::uint8_t
	{
		code,
		basic_block,
		insn,
		invalid_mem,
		mem_access,
		exception
	};

	struct emu_hook
	{
		using insn_hk_cb = std::function<bool()>; // returns true = skip insn
		using code_hk_cb = std::function<void()>;
		using mem_hk_cb = std::function<void(addr_t addr, mem_vmexit::access access)>;
		using invalid_mem_hk_cb = std::function<bool(addr_t addr, mem_vmexit::access access)>; // returns true = has handled invalid access properly (e.g. mapping the address in)
		using excp_hk_cb = std::function<bool(exception_id id)>; // returns true = handled, do not deliver to the guest

		using hook_cb = std::variant<insn_hk_cb, code_hk_cb, mem_hk_cb, invalid_mem_hk_cb, excp_hk_cb>;
		using hook_data = std::variant<hook_insn_t, hook_mem_t, hook_basic_block_t, hook_excp_t>;

		hook_cb cb;
		hook_type type;

		addr_t start_addr;
		addr_t end_addr;

		hook_data extra_data;

		[[nodiscard]] bool in_range(addr_t addr) const;
		[[nodiscard]] bool in_aligned_range(addr_t addr, std::size_t size = 0) const;
	};

	class emu
	{
	public:
		constexpr static addr_t reserved_base = 0x1000;
		constexpr static addr_t default_start_addr = 0;
		constexpr static addr_t default_end_addr = std::numeric_limits<addr_t>::max();
		constexpr static std::size_t page_size = partition::page_size;

		explicit emu(machine_mode mode);

		[[nodiscard]] bool run_at(addr_t start_addr, addr_t end_addr = 0);

		bool run();

		void stop();
		void try_stop();
		void cancel_pending_single_step() { pending_single_step_cancelled_ = true; }

		std::shared_ptr<emu_hook> hook_code(const emu_hook::code_hk_cb& cb, addr_t start_phys_addr = default_start_addr, addr_t end_phys_addr = default_end_addr);
		std::shared_ptr<emu_hook> hook_basic_block(const emu_hook::code_hk_cb& cb, addr_t start_phys_addr = default_start_addr, addr_t end_phys_addr = default_end_addr);
		std::shared_ptr<emu_hook> hook_mem(mem_prot prot, const emu_hook::mem_hk_cb& cb, addr_t start_phys_addr = default_start_addr, addr_t end_phys_addr = default_end_addr);
		std::shared_ptr<emu_hook> hook_invalid_mem(mem_prot prot, const emu_hook::invalid_mem_hk_cb& cb, addr_t start_addr = default_start_addr, addr_t end_addr = default_end_addr);
		std::shared_ptr<emu_hook> hook_insn(hook_insn_t insn, const emu_hook::insn_hk_cb& cb, addr_t start_addr = default_start_addr, addr_t end_addr = default_end_addr);

		std::shared_ptr<emu_hook> hook_exception(const emu_hook::excp_hk_cb& cb, exception_mask mask = excp_all);

		bool remove_hook(const std::shared_ptr<emu_hook>& hook);

		bool map_phys_mem(addr_t phys_addr, std::size_t size, mem_prot prot);
		bool unmap_phys_mem(addr_t phys_addr, std::size_t size);

		bool prot_phys_mem(addr_t phys_addr, std::size_t size, mem_prot prot);

		bool write_phys_mem(addr_t phys_addr, const void* buf, std::size_t size);
		bool write_phys_mem(addr_t phys_addr, std::span<const std::uint8_t> buf);

		bool read_phys_mem(addr_t phys_addr, void* buf, std::size_t size) const;
		bool read_phys_mem(addr_t phys_addr, std::span<std::uint8_t> buf) const;

		[[nodiscard]] std::optional<addr_t> virt_to_phys(addr_t addr) const;

		bool reg_write(const reg_t& r, const void* value, std::size_t size);
		bool reg_read(const reg_t& r, void* value, std::size_t size) const;

		[[nodiscard]] addr_t pc() const;
		void set_pc(addr_t pc);

		template <class T>
		[[nodiscard]] T read_phys_mem(const addr_t phys_addr)
		{
			static_assert(std::is_trivially_copyable_v<T>, "reading non trivially copyable type from physical memory");

			T value = { };

			if (!read_phys_mem(phys_addr, &value, sizeof(T)))
			{
				throw std::runtime_error("unable to read physical memory");
			}

			return value;
		}

		template <class T>
		requires (!std::is_convertible_v<const T&, std::span<const std::uint8_t>>)
		void write_phys_mem(const addr_t phys_addr, const T& value)
		{
			static_assert(std::is_trivially_copyable_v<T>, "writing non trivially copyable type to physical memory");

			if (!write_phys_mem(phys_addr, &value, sizeof(T)))
			{
				throw std::runtime_error("unable to write physical memory");
			}
		}

		template <reg_t Register, class T>
		[[nodiscard]] T reg_read() const
		{
			const auto cpu = this->cpu();

			return cpu.reg_read<Register, T>();
		}

		template <reg_t Register, class T>
		void reg_write(const T& value)
		{
			auto cpu = this->cpu();

			cpu.reg_write<Register>(value);
		}

	protected:
		bool configure_single_step();
		void reset_guest_exit_state();

		void reset_step_cbs();

		void single_step(vcpu& cpu, vmexit_context& context);
		bool handle_page_fault(vcpu& cpu, const vmexit_context& context);

		bool handle_exception(vcpu& cpu, vmexit_context& context);
		bool dispatch_excp_hooks(exception_id id);
		bool handle_mem_access(vcpu& cpu, vmexit_context& context);

		void set_block_code_hook_step(const std::shared_ptr<emu_hook>& hook);
		void handle_block_hook_overflow(const std::shared_ptr<emu_hook>& hook, addr_t rip);
		void invoke_block_code_hook_step_cb(const std::shared_ptr<emu_hook>& hook, addr_t rip,
		                                          std::span<const std::uint8_t> insn_bytes);
		bool prot_block_code_hook_mem_range(addr_t start_addr, addr_t end_addr, bool executable);
		bool mem_process_block_code_hook(vcpu& cpu, vmexit_context& context,
		                                    const std::shared_ptr<emu_hook>& hook);

		void set_mem_hook_step(vcpu& cpu, vmexit_context& context,
		                              const std::shared_ptr<emu_hook>& hook, bool& step_handled);
		void resolve_mem_access_addr(vcpu& cpu, vmexit_context& context);
		bool mem_process_mem_hook(vcpu& cpu, vmexit_context& context,
		                                const std::shared_ptr<emu_hook>& hook, bool& step_handled);

		bool raw_process_invalid_mem_hook(const std::shared_ptr<emu_hook>& hook, addr_t accessed_addr, mem_vmexit::access access_type);

		bool handle_cpuid_insn(vcpu& cpu, vmexit_context& context);
		bool handle_rdtsc_insn(vcpu& cpu, vmexit_context& context);

		template <class ...Args>
		std::shared_ptr<emu_hook> add_hook(Args&&... arguments)
		{
			const auto hook = std::make_shared<emu_hook>(std::forward<Args>(arguments)...);

			hooks_.push_back(hook);

			return hook;
		}

		[[nodiscard]] vcpu cpu() const;

		bool load_cpu_mode_default_state();

		[[nodiscard]] bool create_default_page_tables();
		[[nodiscard]] bool create_default_gdt();

		std::shared_ptr<partition> partition_ = { };
		machine_mode mode_ = machine_mode_16;

		// return true = keep in list
		// return false = erase from list
		std::vector<vmexit_callback::routine_t> single_step_cbs_;

		std::vector<std::shared_ptr<emu_hook>> hooks_ = { };

		bool block_hook_was_control_flow_ = false;
		bool pending_single_step_cancelled_ = false;
	};
}
