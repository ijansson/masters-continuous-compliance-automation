import boto3
import os
import json

class ComplianceResult:
    CORRECTED = 1
    NOT_CORRECTABLE = 2
    ERROR = 3
    def result_to_str(result):
        switch = {
            1: 'CORRECTED',
            2: 'NOT_CORRECTABLE',
            3: 'ERROR'
        }
        return switch.get(result, '')

def lambda_handler(event, context):
    print("Event: {}".format(event))
    if 'Type' in event['detail']['findings'][0]['Resources'][0].keys():
        iamPolicy = str(event['detail']['findings'][0]['Resources'][0]['Id'])
        findingId = str(event['detail']['findings'][0]['Id'])
        region = str(event['detail']['findings'][0]['Resources'][0]['Region'])
        lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
        generatorId = str(event['detail']['findings'][0]['GeneratorId'])
        recordState = str(event['detail']['findings'][0]['RecordState'])
        result = ComplianceResult.NOT_CORRECTABLE
        result_msg = 'Not correctable'
        if recordState != "ARCHIVED" :
            try:
                iam = boto3.client('iam')
                policy = iam.list_policy_versions(PolicyArn=iamPolicy)
                print(policy)
                # DeletePolicyVersion
                for pol in policy['Versions']:
                    if pol['IsDefaultVersion'] == False:
                        iam.delete_policy_version(PolicyArn=iamPolicy, VersionId=pol['VersionId'])
                    
                #TODO  need to detach ListEntitiesForPolicy, DetachUserPolicy, DetachGroupPolicy, DetachRolePolicy
                response = iam.delete_policy(PolicyArn=iamPolicy)
                
                if response ['ResponseMetadata']['HTTPStatusCode'] == 200:
                    result_msg = 'IAM Policy Updated :' + iamPolicy
                    result = ComplianceResult.CORRECTED
                else:
                    result_msg = str(response)
            except Exception as e:
                print(e)
                result_msg = str(e)
                result = ComplianceResult.ERROR
                
            if result == ComplianceResult.CORRECTED:
                try:
                    securityhub = boto3.client('securityhub')
                    response = securityhub.update_findings(
                        Filters={'Id': [{
                                    'Value': findingId,
                                    'Comparison': 'EQUALS'}]
                        },
                        Note={'Text': 'Automatic Remidiation was invoked. Refer to Automation results to determine efficacy'+'IAM Policy Updated :' + iamPolicy,
                              'UpdatedBy': lambdaFunctionName
                        },
                        RecordState='ACTIVE'
                    )
                    print(response)
                except Exception as e:
                    print(e)
                    raise
        print('{}/{}/{}'.format(lambdaFunctionName, ComplianceResult.result_to_str(result), result_msg)) 
        statusCode = 200   
        if result == ComplianceResult.ERROR:
            statusCode = 500
        return {
            'statusCode': statusCode,
            'body': {
                "function":lambdaFunctionName,
                "result": ComplianceResult.result_to_str(result),
                "message": result_msg,
                "event": event
            }
        }  
    else:
        print('Compliance event cannot be fixed')