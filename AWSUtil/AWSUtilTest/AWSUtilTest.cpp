// AWSUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../AWSUtil/Auth.h"
#include <ctime>
#include <iomanip>
#include <iostream>
#include <curl/curl.h>

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



static size_t ReadCallback(void *ptr, size_t size, size_t nmemb, void *pData)
{
	std::string *pStr = static_cast<std::string *>(pData);
	size_t nReadSize = pStr->length() < size*nmemb ? pStr->length() : size*nmemb;
	memcpy(ptr, pStr->c_str(), nReadSize);
	return nReadSize;
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
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, ReadCallback);
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
	
	curl_global_cleanup();
    return 0;
}

