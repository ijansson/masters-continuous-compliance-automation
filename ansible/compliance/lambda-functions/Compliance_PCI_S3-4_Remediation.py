import boto3
import json
import os
import time

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

def fix_encryption(noncompliantS3Bucket, lambdaFunctionName):
    ssm = boto3.client('ssm')
    try:
        enableS3BucketEncryption = ssm.start_automation_execution(
            DocumentName='AWS-EnableS3BucketEncryption',
            DocumentVersion='1', # default
            Parameters={
                'BucketName': [ noncompliantS3Bucket ]
            }
        )
        count = 5 # wait for reslult max 5 seconds 
        while count > 0:
            --count 
            automationExecutionResponse = ssm.get_automation_execution(
                AutomationExecutionId= enableS3BucketEncryption['AutomationExecutionId']
            )
            time.sleep(1) # wait on ssm result 
            print(automationExecutionResponse)
            status = automationExecutionResponse['AutomationExecution']['AutomationExecutionStatus']
            if status != 'Pending' and status != 'InProgress' and status != 'Cancelling' and status != 'Waiting':
                break
        
        if status == 'Success' :
            result = ComplianceResult.CORRECTED 
            result_msg = 'Compliance Corrected for ' + noncompliantS3Bucket
        else:
            result_msg = 'Cant create compliance, refere to lambda '+lambdaFunctionName+' loggs'
            if 'FailureMessage' in automationExecutionResponse['AutomationExecution'].keys():
                result_msg =  automationExecutionResponse['AutomationExecution']['FailureMessage']
            result = ComplianceResult.ERROR 

    except Exception as e:
        result_msg = 'SSM automation failed' + str(e)
        result = ComplianceResult.ERROR
    return result, result_msg

def lambda_handler(event, context):
    if 'Details' in event['detail']['findings'][0]['Resources'][0].keys():
        rawBucketInfo = str(event['detail']['findings'][0]['Resources'][0]['Id'])
        findingId = str(event['detail']['findings'][0]['Id'])
        lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
        noncompliantS3Bucket = rawBucketInfo.replace("arn:aws:s3:::", "")
        result = ComplianceResult.NOT_CORRECTABLE
        result_msg = 'Not correctable'
        securityhub = boto3.client('securityhub')
        if 'TEMP' in noncompliantS3Bucket:
            #TODO Tag in stead of name based filtering
            result, result_msg = fix_encryption(noncompliantS3Bucket, lambdaFunctionName)
        else:
            result_msg = 'Not compliance LAB security group'

        if result == ComplianceResult.CORRECTED:
            try:
                response = securityhub.update_findings(
                    Filters={'Id': [{
                                'Value': findingId,
                                'Comparison': 'EQUALS'}]
                    },
                    Note={'Text': 'Systems Manager Automation add encryption to s3 was successfully invoked:'+,noncompliantS3Bucket
                        'UpdatedBy': lambdaFunctionName
                    },
                    RecordState='ACTIVE'
                )
            except Exception as e:
                print(e)
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
