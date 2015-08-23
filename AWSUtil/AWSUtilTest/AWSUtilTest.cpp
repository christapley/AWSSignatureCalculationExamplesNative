// AWSUtilTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "../AWSUtil/Auth.h"
#include <ctime>
#include <iomanip>
#include <iostream>
#include "../AWSUtil/hmac/hmac_sha2.h"

void GetS3Object(const std::string &sBucketName, const std::string &sRegionName, const std::string &awsAccessKey, const std::string &awsSecretKey)
{
	printf("*******************************************************\n");
	printf("*  Executing sample 'GetObjectUsingHostedAddressing'  *\n");
	printf("*******************************************************\n");

	// the region-specific endpoint to the target object expressed in path style
	std::string sEndpointUrl = "https://" + sBucketName + ".s3.amazonaws.com/ExampleObject.txt";
	
	// for a simple GET, we have no body so supply the precomputed 'empty' hash
	std::map<std::string, std::string> Headers;
	Headers["x-amz-content-sha256"] = AWS::Auth::AWS4SignerBase::EmptyBodySHA256();

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
	//String response = HttpUtils.invokeHttpRequest(endpointUrl, "GET", headers, null);
	printf("--------- Response content ---------\n");
	//printf("%s\n", response.c_str());
	printf("------------------------------------\n");
}


int main()
{
	GetS3Object("bucket", "us-west-2", "chris", "tapley");

		
    return 0;
}

