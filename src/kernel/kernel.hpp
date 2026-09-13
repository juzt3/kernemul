#pragma once
#include "process.hpp"
#include "map.hpp"
#include "thread_scheduler.hpp"
#include "../sym/symbol.hpp"
#include "../emu/emu.hpp"
#include "../emu/calling_conv.hpp"
#include "../util/log.hpp"
#include <atomic>
#include <chrono>
#include <exception>
#include <format>
#include <functional>
#include <filesystem>
#include <map>
#include <mutex>
#include <shared_mutex>
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

	// How long a thread may hold a cpu before it is made to give it up.
	static constexpr auto default_thread_runtime = std::chrono::milliseconds(300);

	// Give every cpu a host thread of its own and let the scheduler spread the
	// guest's threads over them. This thread has nothing to do but wait for
	// them, so it keeps time: once a thread has had its run it asks the cpu to
	// reschedule, or a thread that never returns would own its cpu forever.
	void run_all(const std::chrono::milliseconds runtime = default_thread_runtime)
	{
		std::atomic<std::size_t> live{cpus().size()};
		std::vector<std::thread> hosts;
		hosts.reserve(cpus().size());

		for (const auto& cpu : cpus())
		{
			hosts.emplace_back([this, cpu, &live]
			{
				// This host thread drives this one cpu for as long as it runs,
				// which is what lets a handler say where it is running without
				// being handed the cpu to say it with.
				set_log_cpu(cpu.get());

				scheduler_.run(*cpu);
				--live;
			});
		}

		while (live.load())
		{
			std::this_thread::sleep_for(runtime);

			for (const auto& cpu : cpus())
				cpu->try_stop();
		}

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
		std::shared_lock lock(proc_mtx_);
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

	// What to call an address in a module: its symbol if the module brought one,
	// and an offset if it did not.
	static std::string name_at(const proc_module& mod, const addr_t addr)
	{
		if (const auto sym = mod.symbols.resolve(addr))
			return sym->format();

		return std::format("+0x{:X}", addr - mod.addr);
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
					// A handler reaches into guest memory on the guest's word,
					// and a driver that got a pointer wrong is a thing to
					// report rather than to die of. The throw would otherwise
					// unwind through the emulator's own C frames, which is not
					// something it can be asked to survive.
					try
					{
						it->second(cpu);
					}
					catch (const std::exception& e)
					{
						THREAD_LOG_ERR("{}!{} faulted: {}", m->name,
							name_at(*m, addr), e.what());
					}

					// Either way the thread leaves the function: the result is
					// whatever the handler had written before it faulted, but a
					// pc left where it was would land here again for ever.
					if (cpu.pc() == addr)
						cpu.set_pc(a->ret_addr(cpu));

					return;
				}

				THREAD_LOG_ERR("unimplemented function {}!{}", m->name, name_at(*m, addr));

				// There is nothing to go on to, so the thread ends here. Left
				// running it would be rescheduled onto this address forever.
				if (const auto t = cpu.thread())
					t->finish();

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
	std::shared_mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
	std::unordered_map<addr_t, redirect_fn> redirections_;
};
