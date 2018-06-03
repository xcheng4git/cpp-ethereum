#include <csignal>
#include <jsonrpccpp/common/exception.h>
#include <libdevcore/CommonData.h>
#include <libethereum/Client.h>
#include <libethashseal/EthashClient.h>
#include <libwebthree/WebThree.h>
#include <libethcore/CommonJS.h>
#include "JsonHelper.h"
#include "Thing.h"
#include "AccountHolder.h"

using namespace std;
using namespace jsonrpc;
using namespace dev;
using namespace eth;
using namespace shh;
using namespace dev::rpc;

Thing::Thing(eth::Interface& _eth, eth::AccountHolder& _ethAccounts) :
	m_eth(_eth),
	m_ethAccounts(_ethAccounts)
{
}

std::string dev::rpc::Thing::thing_sendEvidence(const Json::Value& _json)
{
	try
	{
		TransactionSkeleton t = toTransactionSkeleton(_json);
		setEvidenceDefaults(t);
		TransactionNotification n = m_ethAccounts.authenticate(t);
		switch (n.r)
		{
		case TransactionRepercussion::Success:
			return toJS(n.hash);
		case TransactionRepercussion::ProxySuccess:
			return toJS(n.hash);// TODO: give back something more useful than an empty hash.
		case TransactionRepercussion::UnknownAccount:
			BOOST_THROW_EXCEPTION(JsonRpcException("Account unknown."));
		case TransactionRepercussion::Locked:
			BOOST_THROW_EXCEPTION(JsonRpcException("Account is locked."));
		case TransactionRepercussion::Refused:
			BOOST_THROW_EXCEPTION(JsonRpcException("Transaction rejected by user."));
		case TransactionRepercussion::Unknown:
			BOOST_THROW_EXCEPTION(JsonRpcException("Unknown reason."));
		}
	}
	catch (JsonRpcException&)
	{
		throw;
	}
	catch (...)
	{
		BOOST_THROW_EXCEPTION(JsonRpcException(Errors::ERROR_RPC_INVALID_PARAMS));
	}
	BOOST_THROW_EXCEPTION(JsonRpcException(Errors::ERROR_RPC_INVALID_PARAMS));
	return string();
}


Json::Value dev::rpc::Thing::thing_getEvidenceByHash(const std::string& _evidenceHash)
{
	try
	{
		h256 h = jsToFixed<32>(_evidenceHash);
		if (!client()->isKnownTransaction(h))
			return Json::Value(Json::nullValue);

		return toJson(client()->localisedTransaction(h));
	}
	catch (...)
	{
		BOOST_THROW_EXCEPTION(JsonRpcException(Errors::ERROR_RPC_INVALID_PARAMS));
	}
}

Json::Value dev::rpc::Thing::thing_pendingEvidences()
{
	//Return list of transaction that being sent by local accounts
	Transactions ours;
	//for (Transaction const& pending:client()->pending())
	for (Transaction const& pending : dynamic_cast<Client*>(client())->pendingEvidences())
	{
		for (Address const& account : m_ethAccounts.allAccounts())
		{
			if (pending.sender() == account)
			{
				ours.push_back(pending);
				break;
			}
		}
	}

	return toJson(ours);
}

void dev::rpc::Thing::setEvidenceDefaults(eth::TransactionSkeleton& _t)
{
	if (!_t.from)
		_t.from = m_ethAccounts.defaultTransactAccount();
}
