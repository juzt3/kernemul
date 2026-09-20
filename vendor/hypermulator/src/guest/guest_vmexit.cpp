#include "guest_vmexit.hpp"
#include "guest_virtual_processor.hpp"

#include <cstring>

hm::vmexit_cpu_state::vmexit_cpu_state(const WHV_VP_EXIT_CONTEXT& whv_context)
		:	rip(whv_context.Rip),
			insn_len(whv_context.InstructionLength)
{

}

std::optional<hm::addr_t> hm::vmexit_cpu_state::phys_rip(
	const vcpu& cpu) const
{
	if (cpu.uses_paging())
	{
		const auto translation = cpu.virt_to_phys(rip);

		if (!translation)
		{
			return { };
		}

		return *translation;
	}

	return rip;
}

hm::mem_vmexit::mem_vmexit(const WHV_MEMORY_ACCESS_CONTEXT& whv_context)
		:	type(static_cast<access>(whv_context.AccessInfo.AccessType)),
			phys_addr_unmapped(whv_context.AccessInfo.GpaUnmapped),
			virt_addr_valid(whv_context.AccessInfo.GvaValid),
			phys_addr(whv_context.Gpa),
			virt_addr(whv_context.Gva)
{
	insn_bytes.fill(0);
	std::memcpy(insn_bytes.data(), whv_context.InstructionBytes, whv_context.InstructionByteCount);
}

hm::cpuid_vmexit::cpuid_vmexit(const WHV_X64_CPUID_ACCESS_CONTEXT& whv_context)
		:	result_rax(whv_context.DefaultResultRax),
			result_rcx(whv_context.DefaultResultRcx),
			result_rdx(whv_context.DefaultResultRdx),
			result_rbx(whv_context.DefaultResultRbx)
{

}

hm::rdtsc_vmexit::rdtsc_vmexit(const WHV_X64_RDTSC_CONTEXT& whv_context)
		:	is_rdtscp(whv_context.RdtscInfo.IsRdtscp),
			tsc(whv_context.Tsc),
			tsc_aux(whv_context.TscAux),
			virt_offset(whv_context.VirtualOffset),
			reference_time(whv_context.ReferenceTime)
{
			
}

hm::exception_vmexit::exception_vmexit(const WHV_VP_EXCEPTION_CONTEXT& whv_context)
		:	id(static_cast<exception_id>(whv_context.ExceptionType)),
			error_code(whv_context.ExceptionInfo.ErrorCodeValid ? whv_context.ErrorCode : std::optional<std::uint32_t>(std::nullopt)),
			exception_parameter(whv_context.ExceptionParameter)
{
	insn_bytes.fill(0);
	std::memcpy(insn_bytes.data(), whv_context.InstructionBytes, whv_context.InstructionByteCount);
}

hm::vmexit_context::vmexit_context(const WHV_RUN_VP_EXIT_CONTEXT& whv_context)
		:	reason(static_cast<vmexit_reason>(whv_context.ExitReason)),
			cpu_state(whv_context.VpContext)
{
	switch (reason)
	{
	case vmexit_reason::mem_access:
		mem_access = mem_vmexit{ whv_context.MemoryAccess };
		break;
	case vmexit_reason::cpuid:
		cpuid = cpuid_vmexit{ whv_context.CpuidAccess };
		break;
	case vmexit_reason::rdtsc:
		rdtsc = rdtsc_vmexit{ whv_context.ReadTsc };
		break;
	case vmexit_reason::exception:
		exception = exception_vmexit{ whv_context.VpException };
		break;
	default:
		break;
	}
}

void hm::vmexit_context::advance_rip(vcpu& cpu)
{
	const std::uint64_t next_rip = cpu_state.rip + cpu_state.insn_len;

	cpu.reg_write<reg::rip>(next_rip);

	cpu_state.rip = next_rip;
}
