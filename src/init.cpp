/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "init.hpp"

#include "dtlstransport.hpp"
#include "sctptransport.hpp"
#include "tls.hpp"

#ifdef _WIN32
#include <winsock2.h>
#endif

using std::shared_ptr;

namespace rtc {

std::weak_ptr<Init> Init::Weak;
init_token Init::Global;
std::mutex Init::Mutex;

init_token Init::Token() {
	std::lock_guard lock(Mutex);

	if (!Global) {
		if (auto token = Weak.lock())
			Global = token;
		else
			Global = shared_ptr<Init>(new Init());
	}
	return Global;
}

void Init::Cleanup() { Global.reset(); }

Init::Init() {
#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
		throw std::runtime_error("WSAStartup failed, error=" + std::to_string(WSAGetLastError()));
#endif

#if USE_GNUTLS
		// Nothing to do
#else
	openssl::init();
#endif

	DtlsTransport::Init();
	SctpTransport::Init();
}

Init::~Init() {
	DtlsTransport::Cleanup();
	SctpTransport::Cleanup();

#ifdef _WIN32
	WSACleanup();
#endif
}

} // namespace rtc

