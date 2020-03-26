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

#if ENABLE_WEBSOCKET

#include "tlstransport.hpp"
#include "tcptransport.hpp"

#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>

using namespace std::chrono;

using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::weak_ptr;

#if USE_GNUTLS

namespace {

static bool check_gnutls(int ret, const string &message = "GnuTLS error") {
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret)) {
			PLOG_INFO << gnutls_strerror(ret);
			return false;
		}
		PLOG_ERROR << message << ": " << gnutls_strerror(ret);
		throw std::runtime_error(message + ": " + gnutls_strerror(ret));
	}
	return true;
}

} // namespace

namespace rtc {

TlsTransport::TlsTransport(shared_ptr<TcpTransport> lower, string host, state_callback callback)
    : Transport(lower, std::move(callback)) {

	PLOG_DEBUG << "Initializing TLS transport (GnuTLS)";

	check_gnutls(gnutls_init(&mSession, GNUTLS_CLIENT));

	try {
		const char *priorities = "SECURE128:-VERS-SSL3.0:-ARCFOUR-128";
		const char *err_pos = NULL;
		check_gnutls(gnutls_priority_set_direct(mSession, priorities, &err_pos),
		             "Failed to set TLS priorities");

		gnutls_session_set_ptr(mSession, this);
		gnutls_transport_set_ptr(mSession, this);
		gnutls_transport_set_push_function(mSession, WriteCallback);
		gnutls_transport_set_pull_function(mSession, ReadCallback);
		gnutls_transport_set_pull_timeout_function(mSession, TimeoutCallback);

		gnutls_server_name_set(mSession, GNUTLS_NAME_DNS, host.data(), host.size());

		mRecvThread = std::thread(&TlsTransport::runRecvLoop, this);

	} catch (...) {

		gnutls_deinit(mSession);
		throw;
	}
}

TlsTransport::~TlsTransport() {
	stop();
	gnutls_deinit(mSession);
}

void TlsTransport::stop() {
	Transport::stop();

	if (mRecvThread.joinable()) {
		PLOG_DEBUG << "Stopping TLS recv thread";
		mIncomingQueue.stop();
		gnutls_bye(mSession, GNUTLS_SHUT_RDWR);
		mRecvThread.join();
	}
}

bool TlsTransport::send(message_ptr message) {
	if (!message)
		return false;

	ssize_t ret;
	do {
		ret = gnutls_record_send(mSession, message->data(), message->size());
	} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

	return check_gnutls(ret);
}

void TlsTransport::incoming(message_ptr message) {
	if (message)
		mIncomingQueue.push(message);
	else
		mIncomingQueue.stop();
}

void TlsTransport::runRecvLoop() {
	const size_t bufferSize = 4096;

	// Handshake loop
	try {
		int ret;
		do {
			ret = gnutls_handshake(mSession);
		} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN ||
		         !check_gnutls(ret, "TLS handshake failed"));

	} catch (const std::exception &e) {
		PLOG_ERROR << "TLS handshake: " << e.what();
		return;
	}

	// Receive loop
	try {
		while (true) {
			char buffer[bufferSize];
			ssize_t ret;
			do {
				ret = gnutls_record_recv(mSession, buffer, bufferSize);
			} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

			// Consider premature termination as remote closing
			if (ret == GNUTLS_E_PREMATURE_TERMINATION) {
				PLOG_DEBUG << "TLS connection terminated";
				break;
			}

			if (check_gnutls(ret)) {
				if (ret == 0) {
					// Closed
					PLOG_DEBUG << "TLS connection cleanly closed";
					break;
				}
				auto *b = reinterpret_cast<byte *>(buffer);
				recv(make_message(b, b + ret));
			}
		}

	} catch (const std::exception &e) {
		PLOG_ERROR << "TLS recv: " << e.what();
	}

	PLOG_INFO << "TLS disconnected";
	recv(nullptr);
}

ssize_t TlsTransport::WriteCallback(gnutls_transport_ptr_t ptr, const void *data, size_t len) {
	TlsTransport *t = static_cast<TlsTransport *>(ptr);
	if (len > 0) {
		auto b = reinterpret_cast<const byte *>(data);
		t->outgoing(make_message(b, b + len));
	}
	gnutls_transport_set_errno(t->mSession, 0);
	return ssize_t(len);
}

ssize_t TlsTransport::ReadCallback(gnutls_transport_ptr_t ptr, void *data, size_t maxlen) {
	TlsTransport *t = static_cast<TlsTransport *>(ptr);
	if (auto next = t->mIncomingQueue.pop()) {
		auto message = *next;
		ssize_t len = std::min(maxlen, message->size());
		std::memcpy(data, message->data(), len);
		gnutls_transport_set_errno(t->mSession, 0);
		return len;
	}
	// Closed
	gnutls_transport_set_errno(t->mSession, 0);
	return 0;
}

int TlsTransport::TimeoutCallback(gnutls_transport_ptr_t ptr, unsigned int ms) {
	TlsTransport *t = static_cast<TlsTransport *>(ptr);
	if (ms != GNUTLS_INDEFINITE_TIMEOUT)
		t->mIncomingQueue.wait(milliseconds(ms));
	else
		t->mIncomingQueue.wait();
	return !t->mIncomingQueue.empty() ? 1 : 0;
}

} // namespace rtc

#else // USE_GNUTLS==0

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace {

const int BIO_EOF = -1;

string openssl_error_string(unsigned long err) {
	const size_t bufferSize = 256;
	char buffer[bufferSize];
	ERR_error_string_n(err, buffer, bufferSize);
	return string(buffer);
}

bool check_openssl(int success, const string &message = "OpenSSL error") {
	if (success)
		return true;

	string str = openssl_error_string(ERR_get_error());
	PLOG_ERROR << message << ": " << str;
	throw std::runtime_error(message + ": " + str);
}

bool check_openssl_ret(SSL *ssl, int ret, const string &message = "OpenSSL error") {
	if (ret == BIO_EOF)
		return true;

	unsigned long err = SSL_get_error(ssl, ret);
	if (err == SSL_ERROR_NONE || err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		return true;
	}
	if (err == SSL_ERROR_ZERO_RETURN) {
		PLOG_DEBUG << "TLS connection cleanly closed";
		return false;
	}
	string str = openssl_error_string(err);
	PLOG_ERROR << str;
	throw std::runtime_error(message + ": " + str);
}

} // namespace

namespace rtc {

int TlsTransport::TransportExIndex = -1;
std::mutex TlsTransport::GlobalMutex;

void TlsTransport::GlobalInit() {
	std::lock_guard lock(GlobalMutex);
	if (TransportExIndex < 0) {
		TransportExIndex = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	}
}

TlsTransport::TlsTransport(shared_ptr<TcpTransport> lower, string host, state_callback callback)
    : Transport(lower, std::move(callback)) {

	PLOG_DEBUG << "Initializing TLS transport (OpenSSL)";
	GlobalInit();

	if (!(mCtx = SSL_CTX_new(SSLv23_method()))) // version-flexible
		throw std::runtime_error("Failed to create SSL context");

	check_openssl(SSL_CTX_set_cipher_list(mCtx, "ALL:!LOW:!EXP:!RC4:!MD5:@STRENGTH"),
	              "Failed to set SSL priorities");

	SSL_CTX_set_options(mCtx, SSL_OP_NO_SSLv3);
	SSL_CTX_set_min_proto_version(mCtx, TLS1_VERSION);
	SSL_CTX_set_read_ahead(mCtx, 1);
	SSL_CTX_set_quiet_shutdown(mCtx, 1);
	SSL_CTX_set_info_callback(mCtx, InfoCallback);

	SSL_CTX_set_default_verify_paths(mCtx);
	SSL_CTX_set_verify(mCtx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(mCtx, 4);

	if (!(mSsl = SSL_new(mCtx)))
		throw std::runtime_error("Failed to create SSL instance");

	SSL_set_ex_data(mSsl, TransportExIndex, this);
	SSL_set_tlsext_host_name(mSsl, host.c_str());

	SSL_set_connect_state(mSsl);

	if (!(mInBio = BIO_new(BIO_s_mem())) || !(mOutBio = BIO_new(Bio_s_mem())))
		throw std::runtime_error("Failed to create BIO");

	BIO_set_mem_eof_return(mInBio, BIO_EOF);
	BIO_set_mem_eof_return(mOutBio, BIO_EOF);
	SSL_set_bio(mSsl, mInBio, mOutBio);

	auto ecdh = unique_ptr<EC_KEY, decltype(&EC_KEY_free)>(
	    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
	SSL_set_options(mSsl, SSL_OP_SINGLE_ECDH_USE);
	SSL_set_tmp_ecdh(mSsl, ecdh.get());

	mRecvThread = std::thread(&TlsTransport::runRecvLoop, this);
}

TlsTransport::~TlsTransport() {
	stop();

	SSL_free(mSsl);
	SSL_CTX_free(mCtx);
}

void TlsTransport::stop() {
	Transport::stop();

	if (mRecvThread.joinable()) {
		PLOG_DEBUG << "Stopping TLS recv thread";
		mIncomingQueue.stop();
		mRecvThread.join();

		SSL_shutdown(mSsl);
	}
}

bool TlsTransport::send(message_ptr message) {
	if (!message)
		return false;

	int ret = SSL_write(mSsl, message->data(), message->size());
	if(!check_openssl_ret(mSsl, ret)
			return false;

	while (int len = BIO_read(mOutBio, buffer, bufferSize); len > 0)
		outgoing(make_message(buffer, buffer + len));

	return true;
}

void TlsTransport::incoming(message_ptr message) {
	if (message)
		mIncomingQueue.push(message);
	else
		mIncomingQueue.stop();
}

void TlsTransport::runRecvLoop() {
	const size_t bufferSize = 4096;

	byte buffer[bufferSize];
	bool initFinished = false;
	try {
		SSL_do_handshake(mSsl);
		while (int len = BIO_read(mOutBio, buffer, bufferSize); len > 0)
			outgoing(make_message(buffer, buffer + len));

		while (auto next = mIncomingQueue.pop()) {
			auto message = *next;
			BIO_write(mInBio, message->data(), message->size());
			int ret = SSL_read(mSsl, buffer, bufferSize);
			if (!check_openssl_ret(mSsl, ret))
				break;

			auto received = ret > 0 ? make_message(buffer, buffer + ret) : nullptr;

			while (int len = BIO_read(mOutBio, buffer, bufferSize); len > 0)
				outgoing(make_message(buffer, buffer + len));

			if (!initFinished && SSL_is_init_finished(mSsl))
				initFinished = true;

			if (received)
				recv(received);
		}
	} catch (const std::exception &e) {
		PLOG_ERROR << "TLS recv: " << e.what();
	}

	if (initFinished) {
		PLOG_INFO << "TLS disconnected";
		recv(nullptr);
	} else {
		PLOG_ERROR << "TLS handshake failed";
	}
}

void TlsTransport::InfoCallback(const SSL *ssl, int where, int ret) {
	TlsTransport *t =
	    static_cast<TlsTransport *>(SSL_get_ex_data(ssl, TlsTransport::TransportExIndex));

	if (where & SSL_CB_ALERT) {
		if (ret != 256) // Close Notify
			PLOG_ERROR << "TLS alert: " << SSL_alert_desc_string_long(ret);

		t->mIncomingQueue.stop(); // Close the connection
	}
}

} // namespace rtc

#endif

#endif
