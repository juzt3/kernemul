#include "guest_vmexit.hpp"
#include "guest_virtual_processor.hpp"

hm::vmexit_processor_state_t::vmexit_processor_state_t(const WHV_VP_EXIT_CONTEXT& whv_context)
		:	rip(whv_context.Rip),
			instruction_length(whv_context.InstructionLength)
{

}

hm::vmexit_processor_state_t::address_type hm::vmexit_processor_state_t::physical_rip(
	const guest_virtual_processor_t& processor) const
{
	if (processor.uses_paging())
	{
		const auto translation = processor.translate_virtual_address(rip);

		if (!translation)
		{
			throw std::runtime_error("unable to translate rip address");
		}

		return *translation;
	}

	return rip;
}

hm::memory_vmexit_t::memory_vmexit_t(const WHV_MEMORY_ACCESS_CONTEXT& whv_context)
		:	type(static_cast<access>(whv_context.AccessInfo.AccessType)),
			physical_address_unmapped(whv_context.AccessInfo.GpaUnmapped),
			virtual_address_valid(whv_context.AccessInfo.GvaValid),
			physical_address(whv_context.Gpa),
			virtual_address(whv_context.Gva)
{
	std::memcpy(instruction_bytes.data(), whv_context.InstructionBytes, instruction_bytes.size());
}

hm::cpuid_vmexit_t::cpuid_vmexit_t(const WHV_X64_CPUID_ACCESS_CONTEXT& whv_context)
		:	result_rax(whv_context.DefaultResultRax),
			result_rcx(whv_context.DefaultResultRcx),
			result_rdx(whv_context.DefaultResultRdx),
			result_rbx(whv_context.DefaultResultRbx)
{

}

hm::rdtsc_vmexit_t::rdtsc_vmexit_t(const WHV_X64_RDTSC_CONTEXT& whv_context)
		:	is_rdtscp(whv_context.RdtscInfo.IsRdtscp),
			tsc(whv_context.Tsc),
			tsc_aux(whv_context.TscAux),
			virtual_offset(whv_context.VirtualOffset),
			reference_time(whv_context.ReferenceTime)
{
			
}

hm::exception_vmexit_t::exception_vmexit_t(const WHV_VP_EXCEPTION_CONTEXT& whv_context)
		:	id(static_cast<exception_id_t>(whv_context.ExceptionType)),
			error_code(whv_context.ExceptionInfo.ErrorCodeValid ? whv_context.ErrorCode : std::optional<error_code_type>(std::nullopt)),
			exception_parameter(whv_context.ExceptionParameter)
{
	std::memcpy(instruction_bytes.data(), whv_context.InstructionBytes, instruction_bytes.size());
}

hm::vmexit_context_t::vmexit_context_t(const WHV_RUN_VP_EXIT_CONTEXT& whv_context)
		:	reason(static_cast<vmexit_reason_t>(whv_context.ExitReason)),
			processor_state(whv_context.VpContext)
{
	switch (reason)
	{
	case vmexit_reason_t::memory_access:
		memory_access = memory_vmexit_t{ whv_context.MemoryAccess };
		break;
	case vmexit_reason_t::cpuid:
		cpuid = cpuid_vmexit_t{ whv_context.CpuidAccess };
		break;
	case vmexit_reason_t::rdtsc:
		rdtsc = rdtsc_vmexit_t{ whv_context.ReadTsc };
		break;
	case vmexit_reason_t::exception:
		exception = exception_vmexit_t{ whv_context.VpException };
		break;
	default:
		break;
	}
}

void hm::vmexit_context_t::advance_rip(guest_virtual_processor_t& virtual_processor)
{
	const std::uint64_t next_rip = processor_state.rip + processor_state.instruction_length;

	virtual_processor.write_register<reg::rip>(next_rip);

	processor_state.rip = next_rip;
}
