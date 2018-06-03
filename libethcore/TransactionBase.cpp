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
/** @file TransactionBase.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <libdevcore/vector_ref.h>
#include <libdevcore/Log.h>
#include <libdevcrypto/Common.h>
#include <libethcore/Exceptions.h>
#include "TransactionBase.h"
#include "EVMSchedule.h"
#include <utils/zmd5.h>
#include <curl/curl.h>

using namespace std;
using namespace dev;
using namespace dev::eth;

TransactionBase::TransactionBase(TransactionSkeleton const& _ts, Secret const& _s):
	m_type(_ts.creation ? ContractCreation : MessageCall),
	m_nonce(_ts.nonce),
	m_value(_ts.value),
	m_receiveAddress(_ts.to),
	m_gasPrice(_ts.gasPrice),
	m_gas(_ts.gas),
	m_data(_ts.data),
	m_sender(_ts.from)
{
	if (_ts.evidence)
		m_type = TransactionBase::EvidenceAppend;
	
	if (_s)
		sign(_s);
}

TransactionBase::TransactionBase(bytesConstRef _rlpData, CheckTransaction _checkSig)
{
	RLP const rlp(_rlpData);
	try
	{
		if (!rlp.isList())
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("transaction RLP must be a list"));

		m_nonce = rlp[0].toInt<u256>();
		m_gasPrice = rlp[1].toInt<u256>();
		m_gas = rlp[2].toInt<u256>();
		if (!rlp[3].isEmpty())
			m_type = EvidenceAppend;
		else
			m_type = rlp[4].isEmpty() ? ContractCreation : MessageCall;

		m_receiveAddress = rlp[4].isEmpty() ? Address() : rlp[4].toHash<Address>(RLP::VeryStrict);
		
		m_value = rlp[5].toInt<u256>();

		if (!rlp[6].isData())
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("transaction data RLP must be an array"));

		m_data = rlp[6].toBytes();

		int const v = rlp[7].toInt<int>();
		h256 const r = rlp[8].toInt<u256>();
		h256 const s = rlp[9].toInt<u256>();

		if (isZeroSignature(r, s))
		{
			m_chainId = v;
			m_vrs = SignatureStruct{r, s, 0};
		}
		else
		{
			if (v > 36)
				m_chainId = (v - 35) / 2; 
			else if (v == 27 || v == 28)
				m_chainId = -4;
			else
				BOOST_THROW_EXCEPTION(InvalidSignature());

			m_vrs = SignatureStruct{r, s, static_cast<byte>(v - (m_chainId * 2 + 35))};

			if (_checkSig >= CheckTransaction::Cheap && !m_vrs->isValid())
				BOOST_THROW_EXCEPTION(InvalidSignature());
		}

		if (m_type == EvidenceAppend)
			m_hash4Evidence = rlp[10].toInt<u256>();

		if (_checkSig == CheckTransaction::Everything)
			m_sender = sender();

		if (rlp.itemCount() > 11)
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("too many fields in the transaction RLP"));
	}
	catch (Exception& _e)
	{
		_e << errinfo_name("invalid transaction format: " + toString(rlp) + " RLP: " + toHex(rlp.data()));
		throw;
	}
}

Address const& TransactionBase::safeSender() const noexcept
{
	try
	{
		return sender();
	}
	catch (...)
	{
		return ZeroAddress;
	}
}

Address const& TransactionBase::sender() const
{
	if (!m_sender)
	{
		if (hasZeroSignature())
			m_sender = MaxAddress;
		else
		{
			if (!m_vrs)
				BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

			auto p = recover(*m_vrs, sha3(WithoutSignature));
			if (!p)
				BOOST_THROW_EXCEPTION(InvalidSignature());
			m_sender = right160(dev::sha3(bytesConstRef(p.data(), sizeof(p))));
		}
	}
	return m_sender;
}

SignatureStruct const& TransactionBase::signature() const
{ 
	if (!m_vrs)
		BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

	return *m_vrs;
}

void TransactionBase::sign(Secret const& _priv)
{
	auto sig = dev::sign(_priv, sha3(WithoutSignature));
	SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
	if (sigStruct.isValid())
		m_vrs = sigStruct;
}

void TransactionBase::streamRLP(RLPStream& _s, IncludeSignature _sig, bool _forEip155hash) const
{
	if (m_type == NullTransaction)
		return;

	_s.appendList((_sig || _forEip155hash ? 4 : 0) + 7);
	_s << m_nonce << m_gasPrice << m_gas;
	
	if (m_type == EvidenceAppend)
		_s << 1;
	else
		_s << "";

	if (m_type == MessageCall || m_type == EvidenceAppend)
		_s << m_receiveAddress;
	else
		_s << "";

	_s << m_value << m_data;

	if (_sig)
	{
		if (!m_vrs)
			BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

		if (hasZeroSignature())
			_s << m_chainId;
		else
		{
			int const vOffset = m_chainId * 2 + 35;
			_s << (m_vrs->v + vOffset);
		}
		_s << (u256)m_vrs->r << (u256)m_vrs->s;

		_s << m_hash4Evidence;
	}
	else if (_forEip155hash)
		_s << m_chainId << 0 << 0 << 0;

}

static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");

void TransactionBase::checkLowS() const
{
	if (!m_vrs)
		BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

	if (m_vrs->s > c_secp256k1n / 2)
		BOOST_THROW_EXCEPTION(InvalidSignature());
}

void TransactionBase::checkChainId(int chainId) const
{
	if (m_chainId != chainId && m_chainId != -4)
		BOOST_THROW_EXCEPTION(InvalidSignature());
}

int64_t TransactionBase::baseGasRequired(bool _contractCreation, bytesConstRef _data, EVMSchedule const& _es)
{
	int64_t g = _contractCreation ? _es.txCreateGas : _es.txGas;

	// Calculate the cost of input data.
	// No risk of overflow by using int64 until txDataNonZeroGas is quite small
	// (the value not in billions).
	for (auto i: _data)
		g += i ? _es.txDataNonZeroGas : _es.txDataZeroGas;
	return g;
}

h256 TransactionBase::sha3(IncludeSignature _sig) const
{
	if (_sig == WithSignature && m_hashWith)
		return m_hashWith;

	if (m_type == EvidenceAppend && m_hash4Evidence)
		return m_hash4Evidence;

	RLPStream s;
	streamRLP(s, _sig, m_chainId > 0 && _sig == WithoutSignature);

	auto ret = dev::sha3(s.out());
	if (_sig == WithSignature)
		m_hashWith = ret;
	return ret;
}

#if 1
#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif
boost::optional<SignatureStruct> const& dev::eth::TransactionBase::updateEvidence(Secret const& UNUSED(_priv))
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
#if 1
		//接下来应该验证MD5
		char md5sum[33];
		md5(m_evidence.buffer, m_evidence.size, md5sum);
		boost::filesystem::path urlPath(url_);
		boost::filesystem::path stem_ = urlPath.stem();
		if (stem_.compare(std::string(md5sum)) != 0)
			BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
#endif
	}
#if 0
	if (m_evidence.size > 2) {
		if ((m_evidence.buffer[0] == 52) && (m_evidence.buffer[1] == 48))
			BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
	}
	else
		BOOST_THROW_EXCEPTION(GetEvidenceFromUrlFailed());
#endif

	m_data.clear();
	m_data.reserve(m_evidence.size);
	for (unsigned i = 0; i < m_evidence.size; i += 1)
	{
		m_data.push_back((byte)m_evidence.buffer[i]);
	}

	//m_hash4Evidence = sha3(WithoutSignature);
	//cnote << "hash 4 evidence is " << toString(m_hash4Evidence);
	//cnote << "m_vrs is " << toString(m_vrs->r) << toString(m_vrs->s) << toString(m_vrs->v);
	//sign(_priv);

	return m_vrs;
}


void dev::eth::TransactionBase::md5(byte* _buffer, size_t _len, char* _md5)
{
	md5_state_t mdctx;
	md5_byte_t md_value[16];
	char md5sum[33];
	int i;
	int h, l;
	md5_init(&mdctx);
	md5_append(&mdctx, (const unsigned char*)(_buffer), _len);
	md5_finish(&mdctx, md_value);

	for (i = 0; i < 16; ++i) {
		h = md_value[i] & 0xf0;
		h >>= 4;
		l = md_value[i] & 0x0f;
		md5sum[i * 2] = (char)((h >= 0x0 && h <= 0x9) ? (h + 0x30) : (h + 0x57));
		md5sum[i * 2 + 1] = (char)((l >= 0x0 && l <= 0x9) ? (l + 0x30) : (l + 0x57));
	}
	md5sum[32] = '\0';
	strncpy(_md5, md5sum, 33);
}

size_t dev::eth::WriteEvidenceCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct EvidenceStruct *mem = (struct EvidenceStruct *)userp;

	mem->buffer = (byte*)realloc(mem->buffer, mem->size + realsize + 1);
	if (mem->buffer == NULL) {
		/* out of memory! */
		ctrace << "Not enough memory (realloc returned NULL) for writing evidence back.";
		return 0;
	}

	memcpy(&(mem->buffer[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->buffer[mem->size] = 0;

	return realsize;
}
#endif
