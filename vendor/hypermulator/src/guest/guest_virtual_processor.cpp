#include "guest_virtual_processor.hpp"
#include "guest_partition.hpp"
#include "guest_register.hpp"

#include <ia32.hpp>

std::uint32_t hm::vcpu::id() const
{
	return id_;
}

std::uint32_t hm::vcpu::depth() const
{
	return depth_->load();
}

void hm::vcpu::run()
{
	const std::uint32_t my_depth = depth_->fetch_add(1) + 1;

	vmexit_context context;

	while (true)
	{
		if (!partition_->run_vcpu(*this, context))
		{
			break;
		}

		if (context.reason == vmexit_reason::cancelled)
		{
			if (take_stop(my_depth))
			{
				break;
			}

			// stale cancel - WHvCancelRunVirtualProcessor was issued before this
			// run() started (e.g. from the stop that ended a deeper run), so the
			// cancel was consumed here without a stop being meant for us
			continue;
		}

		if (take_stop(my_depth))
		{
			break;
		}

		if (!process_vmexit(context))
		{
			break;
		}
	}

	// Only the run that owns the exception state tears it down: a nested run
	// returning leaves its caller's pending events alone.
	if (depth_->fetch_sub(1) == 1)
	{
		reset_exception_state();
	}
}

void hm::vcpu::stop()
{
	// Aimed at whichever run is innermost now, so a hook that stops the
	// processor ends the run it is running under and no other.
	stop_depth_->store(depth_->load());

	partition_->stop_vcpu(*this);
}

void hm::vcpu::try_stop()
{
	if (depth_->load() == 1)
	{
		stop();
	}
}

bool hm::vcpu::take_stop(const std::uint32_t depth) const
{
	std::uint32_t requested = depth;

	return stop_depth_->compare_exchange_strong(requested, 0);
}

std::optional<hm::addr_t> hm::vcpu::virt_to_phys(
	const addr_t virt_addr) const
{
	return partition_->virt_to_phys(*this, virt_addr);
}

bool hm::vcpu::write_virt_mem(const addr_t virt_addr, const void* const buf,
                                                         const std::size_t size)
{
	return partition_->write_virt_mem(*this, virt_addr, buf, size);
}

bool hm::vcpu::write_virt_mem(const addr_t virt_addr, const std::span<const std::uint8_t> buf)
{
	return write_virt_mem(virt_addr, buf.data(), buf.size());
}

bool hm::vcpu::read_virt_mem(const addr_t virt_addr, void* const buf,
                                                        const std::size_t size) const
{
	return partition_->read_virt_mem(*this, virt_addr, buf, size);
}

bool hm::vcpu::read_virt_mem(const addr_t virt_addr,
                                                        const std::span<std::uint8_t> buf) const
{
	return read_virt_mem(virt_addr, buf.data(), buf.size());
}

bool hm::vcpu::read_mem(const addr_t addr, void* const buf, const std::size_t size) const
{
	if (!uses_paging())
	{
		return partition_->read_phys_mem(addr, buf, size);
	}

	return read_virt_mem(addr, buf, size);
}

bool hm::vcpu::read_mem(const addr_t addr, const std::span<std::uint8_t> buf) const
{
	return read_mem(addr, buf.data(), buf.size());
}

bool hm::vcpu::write_mem(const addr_t addr, const void* const buf,
                                                 const std::size_t size)
{
	if (!uses_paging())
	{
		return partition_->write_phys_mem(addr, buf, size);
	}

	return write_virt_mem(addr, buf, size);
}

bool hm::vcpu::write_mem(const addr_t addr,
                                                 const std::span<const std::uint8_t> buf)
{
	return write_mem(addr, buf.data(), buf.size());
}

bool hm::vcpu::process_vmexit(vmexit_context& context)
{
	return partition_->run_vmexit_cbs(*this, context);
}

bool hm::vcpu::reg_write(const reg_t& r, const void* const value,
                                                   const std::size_t size)
{
	return partition_->reg_write(*this, r, value, size);
}

bool hm::vcpu::reg_read(const reg_t& r, void* const value,
                                                  const std::size_t size) const
{
	return partition_->reg_read(*this, r, value, size);
}

bool hm::vcpu::uses_paging() const
{
	const cr0 current_cr0 = reg_read<reg::cr0, cr0>();

	return current_cr0.paging_enable;
}

void hm::vcpu::reset_exception_state()
{
	constexpr std::uint64_t zero_8 = 0;
	constexpr std::array<std::uint64_t, 2> zero_16 = { };

	reg_write(reg::pending_interruption, &zero_8, sizeof(zero_8));
	reg_write(reg::pending_event, &zero_16, sizeof(zero_16));
	reg_write(reg::interrupt_state, &zero_8, sizeof(zero_8));
}
