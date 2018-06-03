/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file Transaction.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <libdevcore/vector_ref.h>
#include <libdevcore/Log.h>
#include <libdevcore/CommonIO.h>
#include <libdevcrypto/Common.h>
#include <libethcore/Exceptions.h>
#include <libevm/VMFace.h>
#include "Interface.h"
#include "Transaction.h"
#include <curl/curl.h>
#include <boost/filesystem.hpp>

using namespace std;
using namespace dev;
using namespace dev::eth;

#define ETH_ADDRESS_DEBUG 0

std::ostream& dev::eth::operator<<(std::ostream& _out, ExecutionResult const& _er)
{
	_out << "{" << _er.gasUsed << ", " << _er.newAddress << ", " << toHex(_er.output) << "}";
	return _out;
}

TransactionException dev::eth::toTransactionException(Exception const& _e)
{
	// Basic Transaction exceptions
	if (!!dynamic_cast<RLPException const*>(&_e))
		return TransactionException::BadRLP;
	if (!!dynamic_cast<OutOfGasIntrinsic const*>(&_e))
		return TransactionException::OutOfGasIntrinsic;
	if (!!dynamic_cast<InvalidSignature const*>(&_e))
		return TransactionException::InvalidSignature;
	// Executive exceptions
	if (!!dynamic_cast<OutOfGasBase const*>(&_e))
		return TransactionException::OutOfGasBase;
	if (!!dynamic_cast<InvalidNonce const*>(&_e))
		return TransactionException::InvalidNonce;
	if (!!dynamic_cast<NotEnoughCash const*>(&_e))
		return TransactionException::NotEnoughCash;
	if (!!dynamic_cast<BlockGasLimitReached const*>(&_e))
		return TransactionException::BlockGasLimitReached;
	if (!!dynamic_cast<AddressAlreadyUsed const*>(&_e))
		return TransactionException::AddressAlreadyUsed;
	// VM execution exceptions
	if (!!dynamic_cast<BadInstruction const*>(&_e))
		return TransactionException::BadInstruction;
	if (!!dynamic_cast<BadJumpDestination const*>(&_e))
		return TransactionException::BadJumpDestination;
	if (!!dynamic_cast<OutOfGas const*>(&_e))
		return TransactionException::OutOfGas;
	if (!!dynamic_cast<OutOfStack const*>(&_e))
		return TransactionException::OutOfStack;
	if (!!dynamic_cast<StackUnderflow const*>(&_e))
		return TransactionException::StackUnderflow;
	return TransactionException::Unknown;
}

std::ostream& dev::eth::operator<<(std::ostream& _out, TransactionException const& _er)
{
	switch (_er)
	{
		case TransactionException::None: _out << "None"; break;
		case TransactionException::BadRLP: _out << "BadRLP"; break;
		case TransactionException::InvalidFormat: _out << "InvalidFormat"; break;
		case TransactionException::OutOfGasIntrinsic: _out << "OutOfGasIntrinsic"; break;
		case TransactionException::InvalidSignature: _out << "InvalidSignature"; break;
		case TransactionException::InvalidNonce: _out << "InvalidNonce"; break;
		case TransactionException::NotEnoughCash: _out << "NotEnoughCash"; break;
		case TransactionException::OutOfGasBase: _out << "OutOfGasBase"; break;
		case TransactionException::BlockGasLimitReached: _out << "BlockGasLimitReached"; break;
		case TransactionException::BadInstruction: _out << "BadInstruction"; break;
		case TransactionException::BadJumpDestination: _out << "BadJumpDestination"; break;
		case TransactionException::OutOfGas: _out << "OutOfGas"; break;
		case TransactionException::OutOfStack: _out << "OutOfStack"; break;
		case TransactionException::StackUnderflow: _out << "StackUnderflow"; break;
		default: _out << "Unknown"; break;
	}
	return _out;
}

Transaction::Transaction(bytesConstRef _rlpData, CheckTransaction _checkSig):
	TransactionBase(_rlpData, _checkSig)
{
}

boost::optional<dev::SignatureStruct> const& dev::eth::Transaction::updateSignature(Secret const& _priv)
{
	//curl for image
	if (m_evidence.size < 1)
	{
		CURL *curl_;
		CURLcode res_;
		std::string url_;
		url_.insert(url_.begin(), m_data.begin(), m_data.end());
		ctrace << "Evidence url: " << url_;
		curl_ = curl_easy_init();
		if (NULL == curl_)
			BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
		curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
		curl_easy_setopt(curl_, CURLOPT_HEADER, 0);
		curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, NULL);
		curl_easy_setopt(curl_, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 1500);
		curl_easy_setopt(curl_, CURLOPT_DNS_CACHE_TIMEOUT, 60 * 60 * 72);
		curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteEvidenceCallback);
		curl_easy_setopt(curl_, CURLOPT_WRITEDATA, (void*)&m_evidence);
		/* some servers don't like requests that are made without a user-agent field, so we provide one */
		curl_easy_setopt(curl_, CURLOPT_USERAGENT, "libcurl-agent/1.0");

		res_ = curl_easy_perform(curl_);
		if (res_ != CURLE_OK) {
			curl_easy_cleanup(curl_);
			BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
		}
		curl_easy_cleanup(curl_);

#if 0
		FILE* fp = fopen("d:\\evidence.jpg", "wb");
		fwrite(m_evidence.buffer, 1, m_evidence.size, fp);
		fclose(fp);
#endif

		//接下来应该验证MD5
		char md5sum[33];
		md5(m_evidence.buffer, m_evidence.size, md5sum);
		boost::filesystem::path urlPath(url_);
		boost::filesystem::path stem_ = urlPath.stem();
		if (stem_.compare(std::string(md5sum)) != 0) 
			BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
	}


	bytes data_(m_data);

	m_data.clear();
	m_data.reserve(m_evidence.size);
	for (unsigned i = 0; i < m_evidence.size; i += 1)
	{
		m_data.push_back((byte)m_evidence.buffer[i]);
	}

	m_hash4Evidence = sha3(WithoutSignature); 
	//cnote << "hash 4 evidence is " << toString(m_hash4Evidence);
	//cnote << "Before m_vrs is " << toString(m_vrs->r) << toString(m_vrs->s) << toString(m_vrs->v);
	sign(_priv);
	//cnote << "After m_vrs is " << toString(m_vrs->r) << toString(m_vrs->s) << toString(m_vrs->v);

	m_data.clear(); 
	m_data = data_;

	return m_vrs;
}
