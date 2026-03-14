#include "symbol_server.hpp"

#include <portable_executable/file.hpp>
#include <portable_executable/image.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <format>
#include <limits>
#include <stdexcept>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

static constexpr std::string_view symbol_server_host = "msdl.microsoft.com";
static constexpr std::string_view symbol_server_base = "/download/symbols";

static void close_stream(beast::ssl_stream<beast::tcp_stream>& stream)
{
	beast::error_code ec;
	beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ec);
	beast::get_lowest_layer(stream).close();
}

static void parse_redirect_url(
	const std::string_view location,
	std::string& host,
	std::string& target)
{
	const auto scheme_end = location.find("://");

	if (scheme_end == std::string_view::npos)
	{
		target = location;
		return;
	}

	const auto host_start = scheme_end + 3;
	const auto path_start = location.find('/', host_start);

	if (path_start == std::string_view::npos)
	{
		host = location.substr(host_start);
		target = "/";
	}
	else
	{
		host = location.substr(host_start, path_start - host_start);
		target = location.substr(path_start);
	}
}

static std::string_view extract_filename(const std::string_view path)
{
	const auto last_sep = path.find_last_of("\\/");
	return last_sep != std::string_view::npos ? path.substr(last_sep + 1) : path;
}

static std::vector<std::uint8_t> https_get(
	const std::string_view host,
	const std::string_view target,
	const std::uint32_t max_redirects = 5)
{
	net::io_context ioc;

	ssl::context ctx(ssl::context::tlsv12_client);
	ctx.set_default_verify_paths();
	ctx.set_verify_mode(ssl::verify_none);

	std::string current_host(host);
	std::string current_target(target);

	for (std::uint32_t redirect = 0; redirect <= max_redirects; ++redirect)
	{
		tcp::resolver resolver(ioc);
		beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

		if (!SSL_set_tlsext_host_name(stream.native_handle(), current_host.c_str()))
		{
			throw std::runtime_error(std::format("SSL_set_tlsext_host_name failed for '{}'", current_host));
		}

		beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
		beast::get_lowest_layer(stream).connect(resolver.resolve(current_host, "443"));
		stream.handshake(ssl::stream_base::client);

		beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(120));

		http::request<http::empty_body> request(http::verb::get, current_target, 11);
		request.set(http::field::host, current_host);
		request.set(http::field::user_agent, "Microsoft-Symbol-Server/10.0.0.0");
		http::write(stream, request);

		beast::flat_buffer buffer;
		http::response_parser<http::dynamic_body> parser;
		parser.body_limit(std::numeric_limits<std::uint64_t>::max());
		http::read(stream, buffer, parser);

		auto response = parser.release();
		const auto status = response.result_int();

		if (status >= 300 && status < 400)
		{
			const auto location = response[http::field::location];

			if (location.empty())
			{
				throw std::runtime_error("redirect with no Location header");
			}

			parse_redirect_url(std::string_view(location), current_host, current_target);
			close_stream(stream);

			continue;
		}

		if (response.result() != http::status::ok)
		{
			throw std::runtime_error(std::format("HTTP {} from {}{}", status, current_host, current_target));
		}

		const auto body_str = beast::buffers_to_string(response.body().data());
		close_stream(stream);

		return { body_str.begin(), body_str.end() };
	}

	throw std::runtime_error("too many redirects");
}

const pdb::cv_info_pdb70_t* pdb::extract_cv_info(const void* const image_base)
{
	const auto image = static_cast<const portable_executable::image_t*>(image_base);

	for (const auto& entry : image->debug_info())
	{
		if (entry.type != portable_executable::debug_directory_type_t::codeview)
		{
			continue;
		}

		const auto cv_data = reinterpret_cast<const std::uint8_t*>(image_base) + entry.virtual_address;
		const auto cv_info = reinterpret_cast<const cv_info_pdb70_t*>(cv_data);

		if (cv_info->cv_signature != 0x53445352)
		{
			continue;
		}

		return cv_info;
	}

	return nullptr;
}

std::string pdb::format_symbol_hash(const cv_info_pdb70_t& cv_info)
{
	const auto& g = cv_info.guid;

	return std::format(
		"{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X}",
		g.data1, g.data2, g.data3,
		g.data4[0], g.data4[1], g.data4[2], g.data4[3],
		g.data4[4], g.data4[5], g.data4[6], g.data4[7],
		cv_info.age);
}

std::string pdb::build_symbol_url(const std::string_view pdb_name, const std::string_view hash)
{
	return std::format("{}/{}/{}/{}", symbol_server_base, pdb_name, hash, pdb_name);
}

std::vector<std::uint8_t> pdb::download_pdb(
	const std::string_view pdb_name,
	const cv_info_pdb70_t& cv_info)
{
	return https_get(symbol_server_host, build_symbol_url(pdb_name, format_symbol_hash(cv_info)));
}

std::vector<std::uint8_t> pdb::download_pdb_for_image(const std::string_view image_path)
{
	portable_executable::file_t pe_file(image_path);

	if (!pe_file.load())
	{
		throw std::runtime_error(std::format("failed to load PE file '{}'", image_path));
	}

	const auto cv_info = extract_cv_info(pe_file.image());

	if (!cv_info)
	{
		throw std::runtime_error(std::format("no CodeView debug info found in '{}'", image_path));
	}

	return download_pdb(extract_filename(cv_info->pdb_file_name), *cv_info);
}
