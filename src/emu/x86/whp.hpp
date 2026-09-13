#pragma once
// Windows Hypervisor Platform backend: the guest runs on the host cpu in a
// Hyper-V partition rather than being interpreted. x86-64 and Windows only,
// and one cpu only -- hypermulator's hook and step state is per partition, so
// a second cpu stepping over a hooked access would unprotect the pages under
// the first. Code, block and memory hooks are physically addressed, so the
// virtual range is translated once when the hook is installed.
#if defined(KERNEMUL_HAS_WHP)
#include "../emu.hpp"
#include "arch.hpp"

#include <memory>
#include <vector>

namespace hm { class emu; }

class x86_whp_emu;

class x86_whp_vcpu final : public vcpu
{
public:
	x86_whp_vcpu(x86_whp_emu* emu, std::shared_ptr<const struct arch> arch, hm::emu& backend,
		std::size_t id);

	void run() override;
	void stop() override;
	void try_stop() override;
	void flush_tlb() override;

	void reg_read(reg_t reg, void* value, std::size_t size) override;
	void reg_write(reg_t reg, const void* value, std::size_t size) override;

private:
	hm::emu& hm_;
};

class x86_whp_emu final : public emu
{
public:
	explicit x86_whp_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {});

	~x86_whp_emu() override;

	hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb) override;
	hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb) override;
	hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb) override;
	hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb) override;
	hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb) override;
	hook_handle hook_exception(exception_hk_cb) override;
	void remove_hook(hook_handle handle) override;

	void map_phys_mem(addr_t addr, std::size_t size, mem_prot prot) override;
	void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot prot) override;
	void read_phys_mem(addr_t addr, void* buf, std::size_t size) override;
	void write_phys_mem(addr_t addr, const void* buf, std::size_t size) override;

	[[nodiscard]] hm::emu& native() const noexcept { return *hm_; }

	// The cpu a hook callback reports. There is only ever the one.
	[[nodiscard]] vcpu* hook_cpu() const;

protected:
	std::shared_ptr<vcpu> create_vcpu(std::size_t id) override;

private:
	struct whp_hook;

	struct phys_run
	{
		addr_t begin, end;
	};

	// The physical runs a virtual range maps to, end exclusive. Contiguous
	// pages coalesce, so a range from one map_virt costs one native hook.
	[[nodiscard]] std::vector<phys_run> phys_runs(addr_t start_addr, addr_t end_addr);

	hook_handle add_hook(std::unique_ptr<whp_hook> hook);

	std::unique_ptr<hm::emu> hm_;
	std::vector<std::unique_ptr<emu_hook>> hooks_;
};

#endif
