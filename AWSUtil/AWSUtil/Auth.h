#ifndef AWS_UTIL_AUTH_H
#define AWS_UTIL_AUTH_H

#include <string>
#include <map>
#include <vector>
#include <list>

#ifdef WIN32
#define AWSgmtime(a,b) gmtime_s(a,b)

#ifdef AWSUTIL_EXPORTS
#define AWSUTIL_IMPEX __declspec(dllexport)
#else
#define AWSUTIL_IMPEX __declspec(dllimport)
#endif

#else
#define AWSgmtime(a,b) gmtime_r(b,a)
#define AWSUTIL_IMPEX
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
			static std::string Hash(const std::vector<unsigned char> &Data);
			static std::string Hash(const char *sData);

			static const std::string &EmptyBodySHA256();
			static const std::string &UnsignedPayload();
			static const std::string &Scheme();
			static const std::string &Algorithm();
			static const std::string &Terminator();

			static void GetFormattedTimes(std::string &sDateTime, std::string &sDate);

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

		class AWSUTIL_IMPEX AWS4SignerForAuthorizationHeader : public AWS4SignerBase {
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
		class AWS4SignerForQueryParameterAuth : public AWS4SignerBase {

			AWS4SignerForQueryParameterAuth(const std::string &sEndpointUrl, const std::string &sHTTPMethod, const std::string &sServiceName, const std::string &sRegionName);

			/**
			* Computes an AWS4 authorization for a request, suitable for embedding in
			* query parameters.
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
			std::string computeSignature(std::map<std::string, std::string> &Headers,
				std::map<std::string, std::string> &QueryParameters,
				const std::string &bodyHash,
				const std::string &awsAccessKey,
				const std::string &awsSecretKey);

		};

		class AWS4SignerForChunkedUpload : public AWS4SignerBase {
		public:
			/**
			* SHA256 substitute marker used in place of x-amz-content-sha256 when
			* employing chunked uploads
			*/
			static const std::string &StreamingBodySHA256();

			AWS4SignerForChunkedUpload(
				const std::string &sEndpointUrl,
				const std::string &sHttpMethod,
				const std::string &sServiceName,
				const std::string &sRegionName);

			/**
			* Computes an AWS4 signature for a request, ready for inclusion as an
			* 'Authorization' header.
			*
			* @param Headers
			*            The request headers; 'Host' and 'X-Amz-Date' will be added to
			*            this set.
			* @param QueryParameters
			*            Any query parameters that will be added to the endpoint. The
			*            parameters should be specified in canonical format.
			* @param sBodyHash
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
			std::string ComputeSignature(
				std::map<std::string, std::string> &Headers,
				std::map<std::string, std::string> &QueryParameters,
				const std::string &sBodyHash,
				const std::string &awsAccessKey,
				const std::string &awsSecretKey);

			/**
			* Calculates the expanded payload size of our data when it is chunked
			*
			* @param nOriginalLength
			*            The true size of the data payload to be uploaded
			* @param nChunkSize
			*            The size of each chunk we intend to send; each chunk will be
			*            prefixed with signed header data, expanding the overall size
			*            by a determinable amount
			* @return The overall payload size to use as content-length on a chunked
			*         upload
			*/
			static int64_t CalculateChunkedContentLength(int64_t nOriginalLength, int64_t nChunkSize);
			
			/**
			* Returns a chunk for upload consisting of the signed 'header' or chunk
			* prefix plus the user data. The signature of the chunk incorporates the
			* signature of the previous chunk (or, if the first chunk, the signature of
			* the headers portion of the request).
			*
			* @param nUserDataLen
			*            The length of the user data contained in userData
			* @param UserData
			*            Contains the user data to be sent in the upload chunk
			* @param SignedChunk A new buffer of data for upload containing the chunk header plus
			*         user data
			*/
			void ConstructSignedChunk(int nUserDataLen, const std::vector<unsigned char> &UserData, std::vector<unsigned char> &SignedChunk);
			
		private:
			/**
			* Returns the size of a chunk header, which only varies depending on the
			* selected chunk size
			*
			* @param nChunkDataSize
			*            The intended size of each chunk; this is placed into the chunk
			*            header
			* @return The overall size of the header that will prefix the user data in
			*         each chunk
			*/
			static int64_t CalculateChunkHeaderLength(int64_t nChunkDataSize);

			AWS4SignerForChunkedUpload() : AWS4SignerBase(std::string(), std::string(), std::string(), std::string()) {}
			AWS4SignerForChunkedUpload(const AWS4SignerForChunkedUpload &s) : AWS4SignerBase(std::string(), std::string(), std::string(), std::string()) {}
			AWS4SignerForChunkedUpload &operator=(const AWS4SignerForChunkedUpload &s) { return *this; }

			class Impl;
			Impl *m_pImpl;
		};
	}
}

#endif // #define AWS_UTIL_AUTH_H

#ifdef NOT_DEF
public class AWS4SignerForChunkedUpload extends AWS4SignerBase {

	
}
#endif
