#include "nt_lpc_ops.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr std::size_t alpc_port_body_size = 0x20;

// Bounds what a caller claiming an enormous TotalLength can make this allocate.
constexpr std::size_t maximum_message_length = 0x10000;

// What an LPC connect reports back, and the largest view it will map.
constexpr std::uint32_t default_maximum_message_length = 0x148;
constexpr std::uint64_t maximum_port_view_size = 0x100000;

// A name resolves to a server port; connecting to one makes a client port. The
// two point at each other, so a send goes to the peer's queue.
struct alpc_port_host final : win_object
{
	std::string name;
	bool is_server = false;
	std::weak_ptr<alpc_port_host> peer;

	void post(std::vector<std::uint8_t> message)
	{
		std::scoped_lock lock(mtx_);
		messages_.push_back(std::move(message));
	}

	std::optional<std::vector<std::uint8_t>> take()
	{
		std::scoped_lock lock(mtx_);

		if (messages_.empty())
			return {};

		auto message = std::move(messages_.front());
		messages_.pop_front();

		return message;
	}

	[[nodiscard]] std::size_t queued()
	{
		std::scoped_lock lock(mtx_);
		return messages_.size();
	}

private:
	std::mutex mtx_;
	std::deque<std::vector<std::uint8_t>> messages_;
};

// ClientId is stamped in on the way past: the one field the kernel fills.
std::vector<std::uint8_t> read_message(vcpu& cpu, const emu_object<_PORT_MESSAGE>& message)
{
	auto& space = *cpu.curr_addr_space();

	const auto header = message.read();
	const auto total = static_cast<std::size_t>(header.u1.s1.TotalLength);
	const auto size = std::clamp(total, sizeof(_PORT_MESSAGE), maximum_message_length);

	std::vector<std::uint8_t> bytes(size);
	space.read_mem(message.address(), bytes.data(), bytes.size());

	auto* stamped = reinterpret_cast<_PORT_MESSAGE*>(bytes.data());
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

	stamped->ClientId.UniqueProcess = reinterpret_cast<void*>(
		static_cast<std::uintptr_t>(t ? t->proc()->id() : 0));
	stamped->ClientId.UniqueThread = reinterpret_cast<void*>(
		static_cast<std::uintptr_t>(t ? t->id() : 0));

	return bytes;
}

std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// ALPC works between two things inside the guest, and only there: a port this
// guest did not create belongs to a process that is not running, which is every
// case the older LPC pair sees. Receiving does not block, as in nt_iocp_ops.cpp.
void modules::register_ntoskrnl_lpc_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto port_from_handle = [st](const std::uint64_t handle)
	{
		return st->sys_proc->handle_table().get_object<alpc_port_host>(handle);
	};

	auto create_port_object = [st](std::shared_ptr<alpc_port_host> host,
		const std::uint32_t desired_access) -> std::uint64_t
	{
		const std::array<std::uint8_t, alpc_port_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(), host,
			prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		if (!host->name.empty())
			st->objs.register_named_object(host->name, addr);

		return st->sys_proc->handle_table().create_handle(addr, desired_access);
	};

	state.redirect_ntzw(mod, "AlpcCreatePort",
		[st, create_port_object](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_ALPC_PORT_ATTRIBUTES> port_attributes) -> NTSTATUS
		{
			if (!port_handle)
				return STATUS_INVALID_PARAMETER;

			auto host = std::make_shared<alpc_port_host>();
			host->name = attribute_name(cpu, object_attributes);
			host->is_server = true;

			if (!host->name.empty() && st->objs.lookup_named_object(host->name))
			{
				THREAD_LOG_WARN("NtAlpcCreatePort: '{}' is already in the namespace", host->name);
				return STATUS_OBJECT_NAME_COLLISION;
			}

			const auto handle = create_port_object(host, PORT_ALL_ACCESS);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			port_handle.write(handle);

			THREAD_LOG_INFO("NtAlpcCreatePort('{}', attributes=0x{:X}) -> handle=0x{:X}",
				host->name, port_attributes.address(), handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AlpcConnectPort",
		[st, create_port_object](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			[[maybe_unused]] emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			[[maybe_unused]] emu_object<_ALPC_PORT_ATTRIBUTES> port_attributes,
			const std::uint32_t flags, [[maybe_unused]] const addr_t required_server_sid,
			emu_object<_PORT_MESSAGE> connection_message, emu_object<std::uint64_t> buffer_length,
			[[maybe_unused]] const addr_t out_message_attributes,
			[[maybe_unused]] const addr_t in_message_attributes,
			[[maybe_unused]] emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			if (!port_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = narrow_wstring(win::read_unicode_string(port_name));
			const auto server_addr = st->objs.lookup_named_object(name);
			const auto server = server_addr
				? st->objs.get_object<alpc_port_host>(server_addr) : nullptr;

			if (!server || !server->is_server)
			{
				THREAD_LOG_WARN("NtAlpcConnectPort('{}'): no port of that name here", name);
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			auto client = std::make_shared<alpc_port_host>();
			client->name = name;
			client->peer = server;

			const auto handle = create_port_object(client, PORT_ALL_ACCESS);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			// A second connection replaces the first.
			server->peer = client;

			port_handle.write(handle);

			if (connection_message)
			{
				auto message = read_message(cpu, connection_message);
				const auto size = message.size();

				server->post(std::move(message));

				THREAD_LOG_INFO("NtAlpcConnectPort('{}'): connection message of {} bytes queued "
					"to the server", name, size);
			}

			// Nothing answers a connection, so none of the buffer came back.
			if (buffer_length)
				buffer_length.write(0);

			THREAD_LOG_INFO("NtAlpcConnectPort('{}', flags=0x{:X}) -> handle=0x{:X}",
				name, flags, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AlpcSendWaitReceivePort",
		[port_from_handle](vcpu& cpu, const std::uint64_t port_handle, const std::uint32_t flags,
			emu_object<_PORT_MESSAGE> send_message,
			[[maybe_unused]] const addr_t send_message_attributes,
			emu_object<_PORT_MESSAGE> receive_message, emu_object<std::uint64_t> buffer_length,
			[[maybe_unused]] const addr_t receive_message_attributes,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto port = port_from_handle(port_handle);

			if (!port)
			{
				THREAD_LOG_WARN("NtAlpcSendWaitReceivePort: handle 0x{:X} is not a port",
					port_handle);
				return STATUS_INVALID_HANDLE;
			}

			if (send_message)
			{
				const auto peer = port->peer.lock();

				if (!peer)
				{
					THREAD_LOG_WARN("NtAlpcSendWaitReceivePort(0x{:X}): nothing is connected to "
						"this port", port_handle);
					return STATUS_PORT_DISCONNECTED;
				}

				auto message = read_message(cpu, send_message);
				const auto size = message.size();

				peer->post(std::move(message));

				THREAD_LOG_INFO("NtAlpcSendWaitReceivePort(0x{:X}, flags=0x{:X}): sent {} bytes, "
					"peer now holds {}", port_handle, flags, size, peer->queued());
			}

			if (!receive_message)
				return STATUS_SUCCESS;

			const auto message = port->take();

			if (!message)
			{
				THREAD_LOG_WARN("NtAlpcSendWaitReceivePort(0x{:X}): nothing queued, and nothing "
					"here blocks on a port -> STATUS_TIMEOUT (timeout={})",
					port_handle, win::read_timeout(timeout).timed ? "given" : "none");

				return STATUS_TIMEOUT;
			}

			const auto room = buffer_length
				? static_cast<std::size_t>(buffer_length.read()) : message->size();
			const auto copied = std::min(room, message->size());

			cpu.curr_addr_space()->write_mem(receive_message.address(), message->data(), copied);

			if (buffer_length)
				buffer_length.write(copied);

			THREAD_LOG_INFO("NtAlpcSendWaitReceivePort(0x{:X}): received {} of {} bytes, {} left",
				port_handle, copied, message->size(), port->queued());

			return copied < message->size() ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
		});

	// NtCreatePort is never called here, so there is never a port to find and
	// never a server to answer. The connection is made anyway: the handle is a
	// real handle to a real port, the caller is told how long a message may be,
	// and its view is mapped -- so everything but a reply works.
	auto connect_port = [st, create_port_object](vcpu& cpu,
		emu_object<std::uint64_t> port_handle, emu_object<_UNICODE_STRING> port_name,
		const addr_t client_view, emu_object<_REMOTE_PORT_VIEW> server_view,
		emu_object<std::uint32_t> maximum_message_length,
		const std::string_view who) -> NTSTATUS
	{
		if (!port_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = narrow_wstring(win::read_unicode_string(port_name));

		auto client = std::make_shared<alpc_port_host>();
		client->name = name;

		const auto handle = create_port_object(client, PORT_ALL_ACCESS);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		port_handle.write(handle);

		auto& space = *cpu.curr_addr_space();

		// PORT_VIEW is not in the generated types: ViewSize and the two bases
		// sit past the section handle and offset, at the same offsets on both
		// architectures.
		if (client_view)
		{
			const auto view_size = space.read_mem<std::uint64_t>(client_view + 0x18);

			if (view_size && view_size <= maximum_port_view_size)
			{
				const auto base = space.alloc(static_cast<std::size_t>(view_size), prot_rw);

				space.write_mem<std::uint64_t>(client_view + 0x20, base);
				space.write_mem<std::uint64_t>(client_view + 0x28, base);

				THREAD_LOG_INFO("{}: client view of 0x{:X} bytes at 0x{:X}",
					who, view_size, base);
			}
		}

		if (server_view)
		{
			auto value = server_view.read();
			value.ViewSize = 0;
			value.ViewBase = nullptr;
			server_view.write(value);
		}

		if (maximum_message_length)
			maximum_message_length.write(default_maximum_message_length);

		THREAD_LOG_WARN("{}('{}') -> handle=0x{:X}: nothing here runs an LPC server, so nothing "
			"will answer a message sent to it", who, name, handle);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "ConnectPort",
		[connect_port](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			[[maybe_unused]] const addr_t security_qos, const addr_t client_view,
			emu_object<_REMOTE_PORT_VIEW> server_view,
			emu_object<std::uint32_t> maximum_message_length,
			[[maybe_unused]] const addr_t connection_information,
			emu_object<std::uint32_t> connection_information_length) -> NTSTATUS
		{
			// Nothing answered, so none of the connection information came back.
			if (connection_information_length)
				connection_information_length.write(0);

			return connect_port(cpu, std::move(port_handle), std::move(port_name), client_view,
				std::move(server_view), std::move(maximum_message_length), "NtConnectPort");
		});

	state.redirect_ntzw(mod, "SecureConnectPort",
		[connect_port](vcpu& cpu, emu_object<std::uint64_t> port_handle,
			emu_object<_UNICODE_STRING> port_name,
			[[maybe_unused]] const addr_t security_qos, const addr_t client_view,
			[[maybe_unused]] const addr_t server_sid,
			emu_object<_REMOTE_PORT_VIEW> server_view,
			emu_object<std::uint32_t> maximum_message_length,
			[[maybe_unused]] const addr_t connection_information,
			emu_object<std::uint32_t> connection_information_length) -> NTSTATUS
		{
			if (connection_information_length)
				connection_information_length.write(0);

			return connect_port(cpu, std::move(port_handle), std::move(port_name), client_view,
				std::move(server_view), std::move(maximum_message_length),
				"NtSecureConnectPort");
		});
}
