#pragma once

#include <memory>
#include <iosfwd>
#include <jsonrpccpp/server.h>
#include <jsonrpccpp/common/exception.h>
#include <libdevcore/Common.h>
#include "SessionManager.h"
#include "ThingFace.h"

namespace dev
{
	class NetworkFace;
	class KeyPair;
	namespace eth
	{
		class AccountHolder;
		struct TransactionSkeleton;
		class Interface;
	}

}

namespace dev {
	namespace rpc{
		class Thing :public dev::rpc::ThingFace
		{
		public:
			Thing(eth::Interface& _eth, eth::AccountHolder& _ethAccounts);

			virtual RPCModules implementedModules() const override
			{
				return RPCModules{ RPCModule{ "eth", "1.0" } };
			}

			eth::AccountHolder const& ethAccounts() const { return m_ethAccounts; }

			virtual std::string thing_sendEvidence(const Json::Value& param1) override;
			virtual Json::Value thing_getEvidenceByHash(const std::string& param1) override;
			virtual Json::Value thing_pendingEvidences() override;

			void setEvidenceDefaults(eth::TransactionSkeleton& _t);
		protected:

			eth::Interface* client() { return &m_eth; }

			eth::Interface& m_eth;
			eth::AccountHolder& m_ethAccounts;
		};
	}
}