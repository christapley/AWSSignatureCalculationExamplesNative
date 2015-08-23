#ifndef AWS_UTIL_AUTH_H
#define AWS_UTIL_AUTH_H

#include <string>
#include <map>
#include <vector>
#include <list>

#ifdef AWSUTIL_EXPORTS
#    define AWSUTIL_IMPEX __declspec(dllexport)
#    define AWSUTIL_TEMPLATE
#else
#    define AWSUTIL_IMPEX __declspec(dllimport)
#    define AWSUTIL_TEMPLATE extern
#endif

#ifdef WIN32
#define AWSgmtime(a,b) gmtime_s(a,b)
#else
#define AWSgmtime(a,b) gmtime_r(b,a)
#endif

namespace AWS {
	namespace Auth {
		class AWSUTIL_IMPEX AWS4SignerBase {
		public:
			AWS4SignerBase(const std::string &sEndPointURL,
				const std::string &sHTTPMethod,
				const std::string &sServiceName,
				const std::string &sRegionName);
			virtual ~AWS4SignerBase();

			static std::string GetCanonicalizedQueryString(const std::map<std::string, std::string> &Parameters);
			static std::string Hash(const std::string &sText);
			static std::string Hash(const char *sData);
			
			static const std::string &EmptyBodySHA256();
			static const std::string &UnsignedPayload();
			static const std::string &Scheme();
			static const std::string &Algorithm();
			static const std::string &Terminator();

		protected:
			static std::string GetCanonicalizedHeaderNames(const std::map<std::string, std::string> &Headers);
			static std::string GetCanonicalizedHeaderString(const std::map<std::string, std::string> &Headers);
			static std::string GetCanonicalRequest(const std::string &sEndPointURL,
				const std::string &sHTTPMethod,
				const std::string &sQueryParameters,
				const std::string &sCanonicalizedHeaderNames,
				const std::string &sCanonicalizedHeaders,
				const std::string &sBodyHash);
			static std::string GetCanonicalizedResourcePath(const std::string &sEndPointURL);
			static std::string GetStringToSign(const std::string &sScheme, const std::string &sAlgorithm, const std::string &sDateTime, const std::string &sScope, const std::string &sCanonicalRequest);

			static std::vector<unsigned char> Sign(const std::string & sStringData, const std::string &sKey);
			static std::vector<unsigned char> Sign(const std::string & sStringData, const std::vector<unsigned char> &Key);

			const std::string &EndPointURL() const;
			const std::string &HTTPMethod() const;
			const std::string &ServiceName() const;
			const std::string &RegionName() const;
		private:
			AWS4SignerBase() {}
			AWS4SignerBase &operator=(const AWS4SignerBase &s) { return *this; }
			class Impl;
			Impl *m_pImpl;
		};

		class AWSUTIL_IMPEX AWS4SignerForAuthorizationHeader : AWS4SignerBase {
		public:
			AWS4SignerForAuthorizationHeader(const std::string &sEndpointUrl, const std::string &sHttpMethod, const std::string &sServiceName, const std::string &sRegionName);
			
			/**
			* Computes an AWS4 signature for a request, ready for inclusion as an
			* 'Authorization' header.
			*
			* @param headers
			*            The request headers; 'Host' and 'X-Amz-Date' will be added to
			*            this set.
			* @param queryParameters
			*            Any query parameters that will be added to the endpoint. The
			*            parameters should be specified in canonical format.
			* @param bodyHash
			*            Precomputed SHA256 hash of the request body content; this
			*            value should also be set as the header 'X-Amz-Content-SHA256'
			*            for non-streaming uploads.
			* @param awsAccessKey
			*            The user's AWS Access Key.
			* @param awsSecretKey
			*            The user's AWS Secret Key.
			* @return The computed authorization string for the request. This value
			*         needs to be set as the header 'Authorization' on the subsequent
			*         HTTP request.
			*/
			std::string ComputeSignature(std::map<std::string, std::string> &Headers,
				const std::map<std::string, std::string> &QueryParameters,
				const std::string &sBodyHash,
				const std::string &awsAccessKey,
				const std::string &awsSecretKey);
		};

	}
}

#endif // #define AWS_UTIL_AUTH_H
