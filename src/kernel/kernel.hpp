#pragma once
#include "process.hpp"
#include "map.hpp"
#include "thread_scheduler.hpp"
#include "../sym/symbol.hpp"
#include "../emu/emu.hpp"
#include "../emu/calling_conv.hpp"
#include "../util/log.hpp"
#include <functional>
#include <filesystem>
#include <map>
#include <mutex>
#include <thread>
#include <vector>
#include <unordered_map>

using redirect_fn = std::function<void(vcpu&)>;

struct os_exception
{
	virtual ~os_exception() = default;
	virtual bool handle(vcpu& cpu, cpu_exception ex) = 0;
};

class os_emulator
{
public:
	explicit os_emulator(std::shared_ptr<emu> emu)
		: emu_(std::move(emu))
	{
		emu_->hook_exception([this](vcpu& cpu, cpu_exception ex) {
			return handle_exception(cpu, ex);
		});
	}

	virtual ~os_emulator() = default;

	emu& emu() { return *emu_; }
	thread_scheduler& scheduler() { return scheduler_; }
	std::shared_ptr<os_exception> excp() const { return excp_; }

	bool handle_exception(vcpu& cpu, cpu_exception ex)
	{
		return excp_ && excp_->handle(cpu, ex);
	}

	virtual std::shared_ptr<vcpu> add_vcpu() = 0;
	virtual std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, addr_t start_addr) = 0;

	// The machine's cpus. Each needs a host thread of its own to run anything.
	void create_vcpus(const std::size_t count)
	{
		for (std::size_t i = 0; i < count; ++i)
			add_vcpu();
	}

	[[nodiscard]] std::span<const std::shared_ptr<vcpu>> cpus() const noexcept
	{
		return emu_->cpus();
	}

	// Give every cpu a host thread of its own and let the scheduler spread the
	// guest's threads over them. Returns once they have all run out of work.
	void run_all()
	{
		std::vector<std::thread> hosts;
		hosts.reserve(cpus().size());

		for (const auto& cpu : cpus())
			hosts.emplace_back([this, cpu] { scheduler_.run(*cpu); });

		for (auto& host : hosts)
			host.join();
	}

protected:
	std::shared_ptr<class emu> emu_;
	std::shared_ptr<os_exception> excp_;
	thread_scheduler scheduler_;
};

struct kernel_state
{
	virtual ~kernel_state() = default;

	virtual std::shared_ptr<process> create_process(std::string_view name) = 0;

	std::shared_ptr<process> find_process(const process::id_type id)
	{
		std::scoped_lock lock(proc_mtx_);
		const auto it = processes.find(id);
		return it != processes.end() ? it->second : nullptr;
	}

	std::shared_ptr<proc_module> map_redirect_module(process& proc, const std::filesystem::path& path, bool supervisor)
	{
		auto mod = krnl::map_img(proc, path, supervisor, true);

		if (!mod)
			return nullptr;

		hook_module_redirects(*mod);

		return mod;
	}

	void hook_module_redirects(proc_module& mod)
	{
		auto* redirections = &redirections_;
		auto* m = &mod;
		auto a = emu_->arch();

		emu_->hook_code(mod.addr, mod.addr + mod.size - 1,
			[redirections, m, a](vcpu& cpu, addr_t addr, std::size_t)
			{
				const auto it = redirections->find(addr);

				if (it != redirections->end())
				{
					it->second(cpu);

					if (cpu.pc() == addr)
						cpu.set_pc(a->ret_addr(cpu));

					return;
				}

				const auto sym = m->symbols.resolve(addr);
				if (sym)
					LOG_ERR("unimplemented function {}!{}", m->name, sym->format());
				else
					LOG_ERR("unimplemented function at {}+0x{:X}", m->name, addr - m->addr);
				cpu.stop();
			});
	}

	void redirect(proc_module& mod, const std::string_view name, redirect_fn fn)
	{
		const auto addr = mod.find_symbol(name);

		if (!addr)
		{
			LOG_ERR("symbol '{}' not found in {}", name, mod.name);
			return;
		}

		redirections_[*addr] = std::move(fn);
	}

	template <typename F>
	void redirect(proc_module& mod, const std::string_view name, F&& fn)
	{
		redirect(mod, name, make_redirect(emu_->call_conv(), std::forward<F>(fn)));
	}

protected:
	std::shared_ptr<class emu> emu_;
	std::mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
	std::unordered_map<addr_t, redirect_fn> redirections_;
};
