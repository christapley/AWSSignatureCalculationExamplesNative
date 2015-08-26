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
	Headers["Accept"] = "*/*";


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

	curl_global_init(CURL_GLOBAL_ALL);

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
	
	GetS3Object(sBucket, sFileKey, sRegion, sKey, sSecret);

    return 0;
}

