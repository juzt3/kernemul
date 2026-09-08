#pragma once
#include "emu.hpp"

#include <unicorn/unicorn.h>
#include <stdexcept>
#include <format>

inline void check_uc(uc_err err)
{
	if (err != UC_ERR_OK)
		throw std::runtime_error(std::format("unicorn: {}", uc_strerror(err)));
}

class unicorn_vcpu : public vcpu
{
public:
	unicorn_vcpu(emu* emu, std::shared_ptr<const struct arch> arch, uc_engine* uc)
		:	vcpu(emu, std::move(arch)), uc_(uc) { }

	~unicorn_vcpu() override
	{
		if (uc_) uc_close(uc_);
	}

	uc_engine* native() const { return uc_; }

private:
	uc_engine* uc_;
};

class unicorn_emu : public emu
{
public:
	explicit unicorn_emu(std::shared_ptr<const struct arch> arch)
		:	emu(std::move(arch)) { }

	std::shared_ptr<vcpu> create_vcpu() override
	{
		auto* uc = create_backend();
		return std::make_shared<unicorn_vcpu>(this, arch_, uc);
	}

private:
	uc_engine* create_backend()
	{
		uc_engine* uc = nullptr;

		if (dynamic_cast<const x86_arch*>(arch_.get()))
			check_uc(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
		else
			throw std::runtime_error("unsupported architecture for unicorn backend");

		return uc;
	}
};
