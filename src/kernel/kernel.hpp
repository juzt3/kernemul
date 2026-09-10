#pragma once
#include "process.hpp"
#include "map.hpp"
#include "../emu/emu.hpp"
#include "../util/log.hpp"
#include <functional>
#include <filesystem>
#include <map>
#include <mutex>
#include <unordered_map>

using redirect_fn = std::function<void(vcpu&)>;

class os_emulator
{
public:
	explicit os_emulator(std::shared_ptr<emu> emu)
		: emu_(std::move(emu)) { }

	virtual ~os_emulator() = default;

	emu& emu() { return *emu_; }

protected:
	std::shared_ptr<class emu> emu_;
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
		auto mod = krnl::map_img(proc, path, supervisor);

		if (!mod)
			return nullptr;

		hook_module_redirects(*mod);

		return mod;
	}

	void hook_module_redirects(proc_module& mod)
	{
		auto* redirections = &redirections_;
		auto a = emu_->arch();

		emu_->hook_code(mod.addr, mod.addr + mod.size - 1,
			[redirections, a](vcpu& cpu, addr_t addr, std::size_t)
			{
				const auto it = redirections->find(addr);

				if (it != redirections->end())
				{
					it->second(cpu);
					cpu.reg(a->pc(), a->ret_addr(cpu));
					return;
				}

				LOG_ERR("unimplemented function at 0x{:X}", addr);
				cpu.stop();
			});
	}

	void redirect(proc_module& mod, const std::string_view name, redirect_fn fn)
	{
		const auto exp = mod.find_export(name);

		if (!exp)
		{
			LOG_ERR("export '{}' not found in {}", name, mod.name);
			return;
		}

		redirections_[*exp] = std::move(fn);
	}

protected:
	std::shared_ptr<class emu> emu_;
	std::mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
	std::unordered_map<addr_t, redirect_fn> redirections_;
};
