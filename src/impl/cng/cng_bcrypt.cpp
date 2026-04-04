#include "cng_bcrypt.hpp"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

void redirect_cng_bcrypt_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto handle_out_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto alg_id_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto implementation_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto alg_id_string = kernel::read_guest_wstring(*emulator, alg_id_address);
			const auto alg_id_narrow = util::narrow_wstring(alg_id_string);

			std::wstring implementation_string;
			std::string implementation_narrow;

			if (implementation_address)
			{
				implementation_string = kernel::read_guest_wstring(*emulator, implementation_address);
				implementation_narrow = util::narrow_wstring(implementation_string);
			}

			THREAD_LOG("BCryptOpenAlgorithmProvider called (handle_out=0x{:X}, alg_id='{}', implementation='{}', flags=0x{:X})",
				handle_out_address, alg_id_narrow,
				implementation_address ? implementation_narrow : "null",
				flags);

			BCRYPT_ALG_HANDLE host_handle = nullptr;

			const auto status = BCryptOpenAlgorithmProvider(
				&host_handle,
				alg_id_string.c_str(),
				implementation_address ? implementation_string.c_str() : nullptr,
				flags & ~BCRYPT_PROV_DISPATCH
			);

			if (status == 0)
			{
				const auto handle_value = reinterpret_cast<emulator_t::address_type>(host_handle);

				static_cast<void>(emulator->write_virtual_memory(
					handle_out_address, &handle_value, sizeof(handle_value)));

				THREAD_LOG("BCryptOpenAlgorithmProvider: success (host_handle=0x{:X})", handle_value);
			}
			else
			{
				THREAD_WARN_LOG("BCryptOpenAlgorithmProvider: host returned 0x{:X}", static_cast<std::uint32_t>(status));
			}

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptOpenAlgorithmProvider"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto property_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto output_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto output_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type result_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &result_address, sizeof(result_address)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &flags, sizeof(flags)));

			const auto property_string = kernel::read_guest_wstring(*emulator, property_address);
			const auto property_narrow = util::narrow_wstring(property_string);

			THREAD_LOG("BCryptGetProperty called (handle=0x{:X}, property='{}', output=0x{:X}, size=0x{:X}, result=0x{:X}, flags=0x{:X})",
				handle, property_narrow, output_address, output_size, result_address, flags);

			std::vector<std::uint8_t> buffer(output_size);
			ULONG result_size = 0;

			const auto status = BCryptGetProperty(
				reinterpret_cast<BCRYPT_HANDLE>(handle),
				property_string.c_str(),
				output_address ? buffer.data() : nullptr,
				output_size,
				&result_size,
				flags
			);

			if (result_address)
			{
				static_cast<void>(emulator->write_virtual_memory(result_address, &result_size, sizeof(result_size)));
			}

			if (status == 0 && output_address && result_size > 0)
			{
				static_cast<void>(emulator->write_virtual_memory(output_address, buffer.data(), result_size));
			}

			THREAD_LOG("BCryptGetProperty: status=0x{:X}, result_size=0x{:X}", static_cast<std::uint32_t>(status), result_size);

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptGetProperty"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto hash_handle_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto hash_object_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto hash_object_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type secret_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &secret_address, sizeof(secret_address)));

			std::uint32_t secret_size = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &secret_size, sizeof(secret_size)));

			std::uint32_t flags = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &flags, sizeof(flags)));

			THREAD_LOG("BCryptCreateHash called (algorithm=0x{:X}, hash_out=0x{:X}, hash_object=0x{:X}, hash_object_size=0x{:X}, secret=0x{:X}, secret_size=0x{:X}, flags=0x{:X})",
				algorithm_handle, hash_handle_out, hash_object_address, hash_object_size, secret_address, secret_size, flags);

			std::vector<std::uint8_t> secret_buffer;

			if (secret_address && secret_size)
			{
				secret_buffer.resize(secret_size);

				emulator_err_t error = emulator->read_virtual_memory(secret_address, secret_buffer.data(), secret_size);
				error.throw_if("BCryptCreateHash: read secret");
			}

			BCRYPT_HASH_HANDLE host_hash_handle = nullptr;

			const auto status = BCryptCreateHash(
				reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
				&host_hash_handle,
				nullptr,
				0,
				secret_buffer.empty() ? nullptr : secret_buffer.data(),
				static_cast<ULONG>(secret_buffer.size()),
				flags & ~BCRYPT_HASH_REUSABLE_FLAG
			);

			if (status == 0)
			{
				const auto handle_value = reinterpret_cast<emulator_t::address_type>(host_hash_handle);

				static_cast<void>(emulator->write_virtual_memory(hash_handle_out, &handle_value, sizeof(handle_value)));

				THREAD_LOG("BCryptCreateHash: success (host_handle=0x{:X})", handle_value);
			}
			else
			{
				THREAD_WARN_LOG("BCryptCreateHash: host returned 0x{:X}", static_cast<std::uint32_t>(status));
			}

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptCreateHash"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto input_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto input_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

			THREAD_LOG("BCryptHashData called (handle=0x{:X}, input=0x{:X}, size=0x{:X}, flags=0x{:X})",
				hash_handle, input_address, input_size, flags);

			std::vector<std::uint8_t> input_buffer(input_size);

			if (input_size)
			{
				emulator_err_t error = emulator->read_virtual_memory(input_address, input_buffer.data(), input_size);
				error.throw_if("BCryptHashData: read input");
			}

			const auto status = BCryptHashData(
				reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle),
				input_buffer.data(),
				input_size,
				flags
			);

			THREAD_LOG("BCryptHashData: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptHashData"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto output_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto output_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto flags = emulator->read_register<x86::reg::r9, std::uint32_t>();

			THREAD_LOG("BCryptFinishHash called (handle=0x{:X}, output=0x{:X}, size=0x{:X}, flags=0x{:X})",
				hash_handle, output_address, output_size, flags);

			std::vector<std::uint8_t> output_buffer(output_size);

			const auto status = BCryptFinishHash(
				reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle),
				output_buffer.data(),
				output_size,
				flags
			);

			if (status == 0 && output_address && output_size)
			{
				static_cast<void>(emulator->write_virtual_memory(output_address, output_buffer.data(), output_size));
			}

			THREAD_LOG("BCryptFinishHash: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptFinishHash"
	);

	redirect_function(
		[emulator]
		{
			const auto hash_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("BCryptDestroyHash called (handle=0x{:X})", hash_handle);

			const auto status = BCryptDestroyHash(reinterpret_cast<BCRYPT_HASH_HANDLE>(hash_handle));

			THREAD_LOG("BCryptDestroyHash: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptDestroyHash"
	);

	redirect_function(
		[emulator]
		{
			const auto algorithm_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			THREAD_LOG("BCryptCloseAlgorithmProvider called (handle=0x{:X}, flags=0x{:X})", algorithm_handle, flags);

			const auto status = BCryptCloseAlgorithmProvider(
				reinterpret_cast<BCRYPT_ALG_HANDLE>(algorithm_handle),
				flags
			);

			THREAD_LOG("BCryptCloseAlgorithmProvider: status=0x{:X}", static_cast<std::uint32_t>(status));

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(status));
		},
		mapped_image,
		"BCryptCloseAlgorithmProvider"
	);
}
