// AWSUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../AWSUtil/Auth.h"
#include <ctime>
#include <iomanip>
#include <iostream>
#include <curl/curl.h>
#include <algorithm>

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	printf("%s\n", static_cast<char*>(contents));
	return nmemb;
}

void GetS3Object(const std::string &sBucketName, const std::string &sFileKey, const std::string &sRegionName, const std::string &awsAccessKey, const std::string &awsSecretKey)
{
	printf("*******************************************************\n");
	printf("*  Executing sample 'GetObjectUsingHostedAddressing'  *\n");
	printf("*******************************************************\n");

	// the region-specific endpoint to the target object expressed in path style
	std::string sEndpointUrl = "http://" + sBucketName + ".s3.amazonaws.com/" + sFileKey;

	// for a simple GET, we have no body so supply the precomputed 'empty' hash
	std::map<std::string, std::string> Headers;
	Headers["x-amz-content-sha256"] = AWS::Auth::AWS4SignerBase::EmptyBodySHA256();
	Headers["Accept"] = "*/*"; //curl adds this


	std::map<std::string, std::string> QueryParameters;

	AWS::Auth::AWS4SignerForAuthorizationHeader Signer(sEndpointUrl, "GET", "s3", sRegionName);
	std::string authorization = Signer.ComputeSignature(Headers,
		QueryParameters,
		AWS::Auth::AWS4SignerBase::EmptyBodySHA256(),
		awsAccessKey,
		awsSecretKey);

	// place the computed signature into a formatted 'Authorization' header
	// and call S3
	Headers["Authorization"] = authorization;

	CURL *curl_handle;
	CURLcode res;

	

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, sEndpointUrl.c_str());
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
	struct curl_slist *headerlist = NULL;

	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	
	std::list<std::string> HeadersList;
	for (auto it = Headers.cbegin(); it != Headers.cend(); ++it) {
		HeadersList.push_back(it->first + ": " + it->second);
	}
	for (auto it = HeadersList.cbegin(); it != HeadersList.cend(); ++it) {
		headerlist = curl_slist_append(headerlist, it->c_str());
	}

	res = curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headerlist);

	printf("--------- Response content ---------\n");
	res = curl_easy_perform(curl_handle);
	if (res != CURLE_OK)
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
	printf("------------------------------------\n");

	curl_easy_cleanup(curl_handle);
}

/**
* Construct a basic presigned url to the object '/ExampleObject.txt' in the
* given bucket and region using path-style object addressing. The signature
* V4 authorization data is embedded in the url as query parameters.
*/
void GetPresignedUrlToS3Object(const std::string &sBucketName, const std::string &sFileKey, const std::string &sRegionName, const std::string &awsAccessKey, const std::string &awsSecretKey)
{
	printf("*******************************************************\n");
	printf("*    Executing sample 'GetPresignedUrlToS3Object'     *\n");
	printf("*******************************************************\n");

	std::string sEndpointUrl;
	if (sRegionName.compare("us-east-1") == 0) {
		sEndpointUrl = "https://s3.amazonaws.com/" + sBucketName + "/" + sFileKey;
	}
	else {
		sEndpointUrl = "https://s3-" + sRegionName + ".amazonaws.com/" + sBucketName + "/" + sFileKey;
	}
	
	// construct the query parameter string to accompany the url
	std::map<std::string, std::string> QueryParameters;

	// for SignatureV4, the max expiry for a presigned url is 7 days,
	// expressed in seconds
	int nExpiresIn = 7 * 24 * 60 * 60;
	
	QueryParameters["X-Amz-Expires"] = std::to_string(nExpiresIn);

	// we have no headers for this sample, but the signer will add 'host'
	std::map<std::string, std::string> Headers;

	//Headers["Accept"] = "*/*"; //curl adds this

	AWS::Auth::AWS4SignerForQueryParameterAuth Signer(sEndpointUrl, "GET", "s3", sRegionName);
	std::string sAuthorizationQueryParameters = Signer.ComputeSignature(Headers,
		QueryParameters,
		AWS::Auth::AWS4SignerBase::UnsignedPayload(),
		awsAccessKey,
		awsSecretKey);

	// build the presigned url to incorporate the authorization elements as query parameters
	std::string sPresignedUrl = sEndpointUrl + "?" + sAuthorizationQueryParameters;
	printf("--------- Computed presigned url ---------\n");
	printf("%s\n", sPresignedUrl.c_str());
	printf("------------------------------------------\n");
}


void PutS3ObjectSample(const std::string &sBucketName, const std::string &sFileKey, const std::string &sRegionName, const std::string &awsAccessKey, const std::string &awsSecretKey)
{
	printf("************************************************\n");
	printf("*        Executing sample 'PutS3Object'        *\n");
	printf("************************************************\n");
	
	std::string sEndpointUrl;
	if (sRegionName.compare("us-east-1") == 0) {
		sEndpointUrl = "http://s3.amazonaws.com/" + sBucketName + "/" + sFileKey;
	}
	else {
		sEndpointUrl = "http://s3-" + sRegionName + ".amazonaws.com/" + sBucketName + "/" + sFileKey;
	}

	std::string sObjectContent =
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc tortor metus, sagittis eget augue ut,\n"
		"feugiat vehicula risus. Integer tortor mauris, vehicula nec mollis et, consectetur eget tortor. In ut\n"
		"elit sagittis, ultrices est ut, iaculis turpis. In hac habitasse platea dictumst. Donec laoreet tellus\n"
		"at auctor tempus. Praesent nec diam sed urna sollicitudin vehicula eget id est. Vivamus sed laoreet\n"
		"lectus. Aliquam convallis condimentum risus, vitae porta justo venenatis vitae. Phasellus vitae nunc\n"
		"varius, volutpat quam nec, mollis urna. Donec tempus, nisi vitae gravida facilisis, sapien sem malesuada\n"
		"purus, id semper libero ipsum condimentum nulla. Suspendisse vel mi leo. Morbi pellentesque placerat congue.\n"
		"Nunc sollicitudin nunc diam, nec hendrerit dui commodo sed. Duis dapibus commodo elit, id commodo erat\n"
		"congue id. Aliquam erat volutpat.\n";

	// precompute hash of the body content
	std::string sObjectContentHash = AWS::Auth::AWS4SignerBase::Hash(sObjectContent);

	std::map<std::string, std::string> Headers, QueryParameters;
	Headers["x-amz-content-sha256"] = sObjectContentHash;
	Headers["content-length"] = std::to_string(sObjectContent.length());
	Headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY";
	Headers["Accept"] = "*/*";
	//Headers["Expect"] = "100-continue";

	AWS::Auth::AWS4SignerForAuthorizationHeader Signer(sEndpointUrl, "PUT", "s3", sRegionName);

	std::string sAuthorization = Signer.ComputeSignature(Headers,
		QueryParameters, // no query parameters
		sObjectContentHash,
		awsAccessKey,
		awsSecretKey);

	// express authorization for this as a header
	Headers["Authorization"] = sAuthorization;


	CURL *curl;
	CURLcode res;
	// make the call to Amazon S3
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, [](void *ptr, size_t size, size_t nmemb, void *pData) {
			std::string *pStr = static_cast<std::string *>(pData);
			size_t nReadSize = pStr->length() < size*nmemb ? pStr->length() : size*nmemb;
			memcpy(ptr, pStr->c_str(), nReadSize);
			return nReadSize;
		});
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_PUT, 1L);
		curl_easy_setopt(curl, CURLOPT_URL, sEndpointUrl.c_str());
		curl_easy_setopt(curl, CURLOPT_READDATA, &sObjectContent);
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)sObjectContent.length());

		struct curl_slist *headerlist = NULL;
		std::list<std::string> HeadersList;
		for (auto it = Headers.cbegin(); it != Headers.cend(); ++it) {
			HeadersList.push_back(it->first + ": " + it->second);
		}
		for (auto it = HeadersList.cbegin(); it != HeadersList.cend(); ++it) {
			headerlist = curl_slist_append(headerlist, it->c_str());
		}
		headerlist = curl_slist_append(headerlist, "Expect:");
	

		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		curl_easy_cleanup(curl);
	}
}


/**
* Want sample to upload 3 chunks for our selected chunk size of 64K; one
* full size chunk, one partial chunk and then the 0-byte terminator chunk.
* This routine just takes 1K of seed text and turns it into a 65K-or-so
* string for sample use.
*/
void Make65KPayload(const std::string &sSeed, std::string &sPayload65K) {
	
	std::string sPayload1K;
	while (sPayload1K.length() < 1024) {
		sPayload1K.append(sSeed);
	}

	// now scale up to meet/exceed our requirement
	sPayload65K.clear();
	for (int i = 0; i < 66; i++) {
		sPayload65K.append(sPayload1K);
	}
}

class ChunkedPut {
public:
	ChunkedPut(const std::string &sContent, int nUserDataBlockSize, AWS::Auth::AWS4SignerForChunkedUpload &Signer) : 
		m_sContent(sContent), 
		m_nUserDataBlockSize(nUserDataBlockSize), 
		m_CurrentChunk(), 
		m_nCurrentChunkOffset(0), 
		m_Signer(Signer),
		m_nChunkNumber(0) {}
	const std::string &m_sContent;
	int m_nUserDataBlockSize;
	std::vector<unsigned char> m_CurrentChunk;
	size_t m_nCurrentChunkOffset;
	AWS::Auth::AWS4SignerForChunkedUpload &m_Signer;
	int m_nChunkNumber;
};


class Data {
public:
	Data() : Offset(0) {}
	std::vector<unsigned char> AllChunks;
	size_t Offset;
};

int64_t ReadChunked(void *ptr, size_t size, size_t nmemb, void *pDataIn) {
	Data *pData = static_cast<Data *>(pDataIn);
	size_t nDataLeft = pData->AllChunks.size() - pData->Offset;
	size_t nReadSize = nDataLeft < size*nmemb ? nDataLeft : size*nmemb;
	memcpy(ptr, &pData->AllChunks[pData->Offset], nReadSize);
	pData->Offset += nReadSize;
	return nReadSize;
}

/**
* Uploads content to an Amazon S3 object in a series of signed 'chunks' using Signature V4 authorization.
*/
void PutS3ObjectChunked(const std::string &sBucketName, const std::string &sFileKey, const std::string &sRegionName, const std::string &awsAccessKey, const std::string &awsSecretKey) {
	printf("***************************************************\n");
	printf("*      Executing sample 'PutS3ObjectChunked'      *\n");
	printf("***************************************************\n");

	std::string sEndpointUrl;
	if (sRegionName.compare("us-east-1") == 0) {
		sEndpointUrl = "http://s3.amazonaws.com/" + sBucketName + "/" + sFileKey;
	}
	else {
		sEndpointUrl = "http://s3-" + sRegionName + ".amazonaws.com/" + sBucketName + "/" + sFileKey;
	}

	std::string sObjectContent =
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc tortor metus, sagittis eget augue ut,\n"
		"feugiat vehicula risus. Integer tortor mauris, vehicula nec mollis et, consectetur eget tortor. In ut\n"
		"elit sagittis, ultrices est ut, iaculis turpis. In hac habitasse platea dictumst. Donec laoreet tellus\n"
		"at auctor tempus. Praesent nec diam sed urna sollicitudin vehicula eget id est. Vivamus sed laoreet\n"
		"lectus. Aliquam convallis condimentum risus, vitae porta justo venenatis vitae. Phasellus vitae nunc\n"
		"varius, volutpat quam nec, mollis urna. Donec tempus, nisi vitae gravida facilisis, sapien sem malesuada\n"
		"purus, id semper libero ipsum condimentum nulla. Suspendisse vel mi leo. Morbi pellentesque placerat congue.\n"
		"Nunc sollicitudin nunc diam, nec hendrerit dui commodo sed. Duis dapibus commodo elit, id commodo erat\n"
		"congue id. Aliquam erat volutpat.\n";

	// this sample uses a chunk data length of 64K; this should yield one
	// 64K chunk, one partial chunk and the final 0 byte payload terminator chunk
	int nUserDataBlockSize = 64 * 1024;

	std::string s65KPayload;
	Make65KPayload(sObjectContent, s65KPayload);

	// set the markers indicating we're going to send the upload as a series 
	// of chunks:
	//   -- 'x-amz-content-sha256' is the fixed marker indicating chunked
	//      upload
	//   -- 'content-length' becomes the total size in bytes of the upload 
	//      (including chunk headers), 
	//   -- 'x-amz-decoded-content-length' is used to transmit the actual 
	//      length of the data payload, less chunk headers

	std::map<std::string, std::string> Headers, QueryParameters;
	Headers["x-amz-storage-class"] = "REDUCED_REDUNDANCY";
	Headers["x-amz-content-sha256"] = AWS::Auth::AWS4SignerForChunkedUpload::StreamingBodySHA256();
	Headers["content-encoding"] = "aws-chunked";
	Headers["x-amz-decoded-content-length"] = std::to_string(s65KPayload.length());
	//Headers["Accept"] = "*/*";

	AWS::Auth::AWS4SignerForChunkedUpload Signer(sEndpointUrl, "PUT", "s3", sRegionName);

	// how big is the overall request stream going to be once we add the signature 
	// 'headers' to each chunk?
	int64_t nTotalLength = AWS::Auth::AWS4SignerForChunkedUpload::CalculateChunkedContentLength(s65KPayload.length(), nUserDataBlockSize);
	Headers["content-length"] = std::to_string(nTotalLength);

	std::string sAuthorization = Signer.ComputeSignature(Headers,
		QueryParameters, // no query parameters
		AWS::Auth::AWS4SignerForChunkedUpload::StreamingBodySHA256(),
		awsAccessKey,
		awsSecretKey);

	// place the computed signature into a formatted 'Authorization' header 
	// and call S3
	Headers["Authorization"] = sAuthorization;

	// start consuming the data payload in blocks which we subsequently chunk; this prefixes
	// the data with a 'chunk header' containing signature data from the prior chunk (or header
	// signing, if the first chunk) plus length and other data. Each completed chunk is
	// written to the request stream and to complete the upload, we send a final chunk with
	// a zero-length data payload.

	CURL *curl;
	CURLcode res;
	// make the call to Amazon S3
	curl = curl_easy_init();
	if (curl) {

		int nI = 0;
		size_t nContentOffset = 0;
		size_t nBufferOffset = 0;
		Data D;
		D.AllChunks.resize(nTotalLength);
		while (nBufferOffset <= s65KPayload.length()) {
			std::vector<unsigned char> Chunk;
			nContentOffset += Signer.ConstructSignedChunk(nUserDataBlockSize, s65KPayload.length() - nContentOffset, s65KPayload.c_str() + nContentOffset, Chunk);
			if (!Chunk.empty()) {
				memcpy(&D.AllChunks[nBufferOffset], &Chunk[0], Chunk.size());
			}
			nBufferOffset += Chunk.size();
		}
		{
			std::vector<unsigned char> Chunk;
			Signer.ConstructSignedChunk(nUserDataBlockSize, 0, s65KPayload.c_str() + nContentOffset, Chunk);
			memcpy(&D.AllChunks[nBufferOffset], &Chunk[0], Chunk.size());
		}
		

		curl_easy_setopt(curl, CURLOPT_READDATA, &D);
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadChunked);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(curl, CURLOPT_PUT, 1L);
		curl_easy_setopt(curl, CURLOPT_URL, sEndpointUrl.c_str());

		ChunkedPut Data(s65KPayload, nUserDataBlockSize, Signer);

		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)nTotalLength);

		struct curl_slist *headerlist = NULL;
		std::list<std::string> HeadersList;
		for (auto it = Headers.cbegin(); it != Headers.cend(); ++it) {
			HeadersList.push_back(it->first + ": " + it->second);
		}
		for (auto it = HeadersList.cbegin(); it != HeadersList.cend(); ++it) {
			headerlist = curl_slist_append(headerlist, it->c_str());
		}
		headerlist = curl_slist_append(headerlist, "Expect:");
		headerlist = curl_slist_append(headerlist, "Accept:");


		res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		curl_easy_cleanup(curl);
	}
}




int main(int argc, char **argv)
{
	if (argc != 6) {
		printf("%s key secret region bucket filekey\n", argv[0]);
		return 1;
	}

	std::string sKey = argv[1];
	std::string sSecret = argv[2];
	std::string sRegion = argv[3];
	std::string sBucket = argv[4];
	std::string sFileKey = argv[5];
	
	curl_global_init(CURL_GLOBAL_ALL);
	PutS3ObjectSample(sBucket, sFileKey, sRegion, sKey, sSecret);
	GetS3Object(sBucket, sFileKey, sRegion, sKey, sSecret);
	GetPresignedUrlToS3Object(sBucket, sFileKey, sRegion, sKey, sSecret);
	PutS3ObjectChunked(sBucket, sFileKey, sRegion, sKey, sSecret);
	curl_global_cleanup();
    return 0;
}

