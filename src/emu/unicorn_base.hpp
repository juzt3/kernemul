#pragma once
#include "emu.hpp"
#include "../util/log.hpp"

#include <unicorn/unicorn.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <unordered_map>
#include <list>

struct unicorn_hook : emu_hook
{
	int uc_type;

	// UC_<arch>_INS_* for a real instruction hook, or the QEMU exception index
	// to match when insn_via_intr is set.
	int uc_insn;

	// An instruction hook the architecture cannot install directly, served
	// from the exception that instruction raises instead. Both this and
	// hook_exception use UC_HOOK_INTR, so the flag picks the trampoline.
	bool insn_via_intr = false;

	std::vector<uc_hook> handles;
};

class unicorn_vcpu_base : public vcpu
{
public:
	unicorn_vcpu_base(class emu* e, std::shared_ptr<const struct arch> arch, uc_engine* uc,
		const std::size_t id)
		:	vcpu(e, std::move(arch), id), uc_(uc) { }

	~unicorn_vcpu_base() override
	{
		if (uc_) uc_close(uc_);
	}

	// Held for as long as a hook callback runs on this cpu. A cpu inside a hook
	// is not executing guest code, so an engine-wide operation neither has to
	// stop it nor wait for it -- it only has to keep it from resuming, which is
	// what the wait on the way out does.
	struct hook_guard
	{
		explicit hook_guard(vcpu& cpu)
			: cpu_(static_cast<unicorn_vcpu_base&>(cpu)) { ++cpu_.in_hook_; }

		~hook_guard()
		{
			while (cpu_.pending_pause_.load()) {}
			--cpu_.in_hook_;
		}

		unicorn_vcpu_base& cpu_;
	};

	void run() override
	{
		const bool nested = running_.load() != 0;
		for (;;)
		{
			auto pc = reg<addr_t>(arch_->pc());

			// A nested run executes guest code, so for its duration this cpu is
			// not at a hook's safe point, whatever the hook around it says.
			const auto hooks = in_hook_.exchange(0);

			// run_on_all only waits for the cpus that were executing when it
			// looked. Starting now would have it flush this cpu's tlb, or remap
			// its memory, while it runs. Before running_, or it would be
			// waiting on a cpu that is waiting on it.
			while (pending_pause_.load()) {}

			++running_;
			const auto res = uc_emu_start(uc_, pc, 0, 0, 0);
			--running_;
			in_hook_ = hooks;

			// Nothing downstream can tell an engine error from an ordinary stop.
			if (res != UC_ERR_OK)
				LOG_ERR("cpu {}: emulation stopped at 0x{:X}: {}", id(), pc, uc_strerror(res));

			if (redirect_.exchange(false))
			{
				// Some helpers advance pc after the hook returns -- the x86
				// syscall helper adds the instruction length unconditionally,
				// even once uc_emu_stop has been requested. Put back the pc the
				// callback asked for, so "return true" means the same thing on
				// every architecture.
				reg(arch_->pc(), redirect_pc_);
				continue;
			}

			// Stopped for an engine-wide operation rather than by a hook that
			// meant it: wait for it to finish and carry on from the same pc. A
			// nested run has to resume too, or its caller is handed a result
			// that was never produced.
			if (!pending_pause_.load())
				break;

			while (pending_pause_.load()) {}
		}
	}

	void stop() override
	{
		uc_emu_stop(uc_);
	}

	void try_stop() override
	{
		// Only the outermost run can be taken away. A nested one ends at a
		// trampoline its caller installed, and stopping it anywhere else hands
		// that caller a result that was never produced.
		if (running_.load() == 1)
			stop();
	}

	void flush_tlb() override
	{
		uc_ctl_flush_tlb(uc_);
	}

	// Register translation is the only part of driving a uc_engine that
	// depends on the guest architecture; emu/<arch>/unicorn.hpp supplies it.
	void reg_read(reg_t reg, void* value, std::size_t size) override = 0;
	void reg_write(reg_t reg, const void* value, std::size_t size) override = 0;

	uc_engine* native() const { return uc_; }

	// Called from a hook trampoline when the callback wants to take over: it
	// records where the callback left pc so run() can restore it.
	void request_redirect()
	{
		redirect_pc_ = reg<addr_t>(arch_->pc());
		redirect_ = true;
	}

	uc_engine* uc_;

	// uc_emu_start nesting: 0 is not executing, 1 is the outermost run, more
	// than that is a hook that started its own.
	std::atomic<int> running_{0};
	std::atomic<int> in_hook_{0};
	std::atomic<bool> pending_pause_{false};
	std::atomic<bool> redirect_{false};
	addr_t redirect_pc_{0};
};

class unicorn_emu_base : public emu
{
public:
	unicorn_emu_base(std::shared_ptr<struct arch> arch, std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {})
		:	emu(std::move(arch), std::move(mem), std::move(call_conv)) { }

	void map_phys_mem(addr_t addr, std::size_t size) override
	{
		std::unique_lock mem_lk(mem_mtx_);

		auto it = mem_.find(addr);
		std::size_t old_size = (it != mem_.end()) ? it->second.size() : 0;

		auto& buf = mem_[addr];
		buf.resize(size);

		run_on_all([&] {
			for (auto& cpu : cpus_)
			{
				if (old_size)
					uc_mem_unmap(engine(cpu), addr, old_size);
				uc_mem_map_ptr(engine(cpu), addr, size, prot_rwx, buf.data());
			}
		});
	}

	void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot) override
	{
		std::unique_lock mem_lk(mem_mtx_);

		run_on_all([&] {
			for (auto& cpu : cpus_)
				uc_mem_unmap(engine(cpu), addr, size);
		});

		mem_.erase(addr);
	}

	void read_phys_mem(addr_t addr, void* buf, std::size_t size) override
	{
		std::shared_lock mem_lk(mem_mtx_);

		auto [src, avail] = find_backing(addr);
		if (src)
			std::memcpy(buf, src, std::min(size, avail));
	}

	void write_phys_mem(addr_t addr, const void* buf, std::size_t size) override
	{
		std::shared_lock mem_lk(mem_mtx_);

		auto [dst, avail] = find_backing(addr);
		if (dst)
			std::memcpy(dst, buf, std::min(size, avail));
	}

	// Runs fn with no cpu executing guest code. A cpu inside a hook already
	// qualifies: it is asked to pause, which its hook waits on before returning,
	// and it is neither stopped nor waited for. That is what lets a hook itself
	// call in here -- stopping it would end the run it is in the middle of, and
	// waiting for it would be waiting on the caller.
	void run_on_all(const std::function<void()>& fn) override
	{
		std::lock_guard lk(op_mtx_);

		for (auto& cpu : cpus_)
			static_cast<unicorn_vcpu_base*>(cpu.get())->pending_pause_ = true;

		// Only cpus that are executing: uc_emu_stop on an idle engine latches a
		// stop request that its next uc_emu_start consumes, so a cpu parked in
		// the scheduler would come back from its first real run having run
		// nothing.
		for (auto& cpu : cpus_)
		{
			auto* uc = static_cast<unicorn_vcpu_base*>(cpu.get());

			if (uc->running_.load() && !uc->in_hook_.load())
				uc->stop();
		}

		// in_hook_ is re-read every time round: a cpu that was executing when
		// it was stopped can still enter a hook before it gets there, and would
		// then be parked on the way out with running_ never clearing.
		for (auto& cpu : cpus_)
		{
			auto* uc = static_cast<unicorn_vcpu_base*>(cpu.get());
			while (uc->running_.load() && !uc->in_hook_.load()) {}
		}

		fn();

		for (auto& cpu : cpus_)
			static_cast<unicorn_vcpu_base*>(cpu.get())->pending_pause_ = false;
	}

	hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb cb) override
	{
		return add_hook(start_addr, end_addr, prot_to_uc_hook(prot), 0, std::move(cb));
	}

	hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb cb) override
	{
		if (const int uc_insn = to_uc_insn(insn); uc_insn >= 0)
			return add_hook(start_addr, end_addr, UC_HOOK_INSN, uc_insn, std::move(cb));

		// Not every architecture lets Unicorn hook the instruction itself. If
		// it raises a distinguishable exception, the hook is served from that
		// instead -- see insn_as_intr.
		if (const int intno = insn_as_intr(insn); intno >= 0)
			return add_hook(start_addr, end_addr, UC_HOOK_INTR, intno, std::move(cb), true);

		throw std::runtime_error("instruction hook unsupported on this architecture");
	}

	hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		return add_hook(start_addr, end_addr, UC_HOOK_CODE, 0, std::move(cb));
	}

	hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		return add_hook(start_addr, end_addr, UC_HOOK_BLOCK, 0, std::move(cb));
	}

	hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb cb) override
	{
		return add_hook(1, 0, prot_to_uc_hook_unmapped(access), 0, std::move(cb));
	}

	hook_handle hook_exception(exception_hk_cb cb) override
	{
		return add_hook(1, 0, UC_HOOK_INTR, 0, std::move(cb));
	}

	void remove_hook(hook_handle handle) override
	{
		auto* hk = static_cast<unicorn_hook*>(handle);

		for (std::size_t i = 0; i < hk->handles.size(); ++i)
			uc_hook_del(engine(cpus_[i]), hk->handles[i]);

		hooks_.remove_if([hk](const unicorn_hook& h) { return &h == hk; });
	}

protected:
	// Open an engine for the guest architecture, already configured.
	virtual uc_engine* open_engine() = 0;

	// Wrap it in the vcpu type that knows this architecture's registers.
	virtual std::shared_ptr<unicorn_vcpu_base> wrap_engine(uc_engine* uc, std::size_t id) = 0;

	// The UC_<arch>_INS_* value for an instruction hook, or -1 if the
	// architecture cannot hook that instruction.
	virtual int to_uc_insn(hook_insn_t insn) const = 0;

	// For an instruction to_uc_insn cannot hook: the QEMU exception index it
	// raises, or -1 if it does not raise one. Returning a value here makes
	// hook_insn work on this architecture anyway.
	virtual int insn_as_intr(hook_insn_t) const { return -1; }

	// Length of the instruction insn_as_intr describes. The exception is
	// raised with pc already past it, so the trampoline rewinds by this much
	// to hand the callback the instruction's own address.
	virtual addr_t insn_as_intr_len() const { return 0; }

	std::shared_ptr<vcpu> create_vcpu(const std::size_t id) final
	{
		uc_engine* uc = open_engine();

		for (auto& [addr, buf] : mem_)
			uc_mem_map_ptr(uc, addr, buf.size(), prot_rwx, buf.data());

		for (auto& hk : hooks_)
			add_uc_hook(hk, uc);

		// Use the CPU's own MMU, so the guest page tables are actually walked.
		uc_ctl_tlb_mode(uc, UC_TLB_CPU);

		return wrap_engine(uc, id);
	}

private:
	template <typename Cb>
	hook_handle add_hook(addr_t start_addr, addr_t end_addr, int uc_type, int uc_insn, Cb cb,
		bool insn_via_intr = false)
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = uc_type;
		hk.uc_insn = uc_insn;
		hk.insn_via_intr = insn_via_intr;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	static void mem_hook_trampoline(uc_engine* uc, uc_mem_type type, std::uint64_t addr,
		int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
				return;
			}
		}
	}

	static void insn_hook_trampoline(uc_engine* uc, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<insn_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);

				if (cb(*cpu))
				{
					static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
					uc_emu_stop(uc);
				}
				return;
			}
		}
	}

	// Serves a hook_insn request from the exception the instruction raises,
	// presenting the same view an architecture with a real instruction hook
	// would: pc at the instruction, the address range honoured, and execution
	// resuming after it unless the callback redirects.
	static void insn_intr_trampoline(uc_engine* uc, std::uint32_t intno, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);

		if (static_cast<int>(intno) != hk->uc_insn)
			return;

		auto& cb = std::get<insn_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) != uc)
				continue;

			const addr_t len = self->insn_as_intr_len();
			const addr_t insn_pc = cpu->pc() - len;

			// UC_HOOK_INTR ignores the address range Unicorn was given, so it
			// is applied here. start > end means unbounded, as elsewhere.
			if (hk->start <= hk->end && (insn_pc < hk->start || insn_pc > hk->end))
				return;

			cpu->set_pc(insn_pc);

			unicorn_vcpu_base::hook_guard guard(*cpu);

			if (cb(*cpu))
			{
				static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
				uc_emu_stop(uc);
			}
			else
			{
				cpu->set_pc(insn_pc + len);
			}
			return;
		}
	}

	static void code_hook_trampoline(uc_engine* uc, std::uint64_t addr,
		std::uint32_t size, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<code_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				cb(*cpu, addr, static_cast<std::size_t>(size));
				return;
			}
		}
	}

	static bool invalid_mem_hook_trampoline(uc_engine* uc, uc_mem_type type,
		std::uint64_t addr, int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<invalid_mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);
				return cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
			}
		}

		return false;
	}

	// Whether a hook_insn request is being served from this exception index --
	// see insn_as_intr. Both it and hook_exception ride UC_HOOK_INTR and every
	// callback is called for every index, so without this an AArch64 SVC also
	// reaches the OS exception handler and becomes an access violation.
	[[nodiscard]] bool claimed_by_insn_hook(const int intno) const
	{
		for (const auto& hk : hooks_)
		{
			if (hk.insn_via_intr && hk.uc_insn == intno)
				return true;
		}

		return false;
	}

	static void exception_hook_trampoline(uc_engine* uc, std::uint32_t intno, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu_base*>(hk->owner);
		auto& cb = std::get<exception_hk_cb>(hk->cb);

		if (self->claimed_by_insn_hook(static_cast<int>(intno)))
			return;

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				unicorn_vcpu_base::hook_guard guard(*cpu);

				auto ex = cpu->arch()->intr_to_excp(static_cast<int>(intno));
				if (cb(*cpu, ex))
				{
					static_cast<unicorn_vcpu_base*>(cpu.get())->request_redirect();
					uc_emu_stop(uc);
				}
				return;
			}
		}
	}

	static void add_uc_hook(unicorn_hook& hk, uc_engine* uc)
	{
		uc_hook h{};
		if (hk.uc_type == UC_HOOK_INSN)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(insn_hook_trampoline),
				&hk, hk.start, hk.end, hk.uc_insn);
		else if (hk.uc_type == UC_HOOK_INTR)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(
					hk.insn_via_intr ? insn_intr_trampoline : exception_hook_trampoline),
				&hk, hk.start, hk.end);
		else if (hk.uc_type == UC_HOOK_CODE || hk.uc_type == UC_HOOK_BLOCK)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(code_hook_trampoline),
				&hk, hk.start, hk.end);
		else if (hk.uc_type & (UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED))
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(invalid_mem_hook_trampoline),
				&hk, hk.start, hk.end);
		else
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(mem_hook_trampoline),
				&hk, hk.start, hk.end);
		hk.handles.push_back(h);
	}

	static int prot_to_uc_hook(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH;
		return type;
	}

	static int prot_to_uc_hook_unmapped(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ_UNMAPPED;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE_UNMAPPED;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH_UNMAPPED;
		return type;
	}

	static mem_prot uc_type_to_prot(uc_mem_type type)
	{
		switch (type)
		{
		case UC_MEM_READ:       return prot_read;
		case UC_MEM_WRITE:      return prot_write;
		case UC_MEM_FETCH:      return prot_exec;
		case UC_MEM_READ_AFTER: return prot_read;
		default:                return prot_none;
		}
	}

	static uc_engine* engine(const std::shared_ptr<vcpu>& cpu)
	{
		return static_cast<unicorn_vcpu_base*>(cpu.get())->native();
	}

	std::pair<std::uint8_t*, std::size_t> find_backing(addr_t addr)
	{
		for (auto& [base, buf] : mem_)
		{
			if (addr >= base && addr < base + buf.size())
			{
				auto off = addr - base;
				return { buf.data() + off, buf.size() - off };
			}
		}
		return { nullptr, 0 };
	}


	std::unordered_map<addr_t, std::vector<std::uint8_t>> mem_;
	std::list<unicorn_hook> hooks_;
	std::mutex op_mtx_;

	// mem_ is host state. Pausing the engines says nothing about the other host
	// threads walking page tables through read_phys_mem and write_phys_mem.
	// Those two only look the region up, so they share; growing it is exclusive.
	mutable std::shared_mutex mem_mtx_;
};
