import boto3
import json
import sys
import traceback
import string
import time
import os

FORBIDDEN_PORTS = [22,3389]

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

def fix_security_group(region, nonCompliantSgId,nonCompliantSgIdName):
    aws_session = boto3.Session(region_name=region)
    ec2 = aws_session.resource('ec2')

    print ('Attempting to create compliance...')
    sg = ec2.SecurityGroup(nonCompliantSgId)
    result = ComplianceResult.NOT_CORRECTABLE
    result_msg = 'No port found, ' + nonCompliantSgId 
    try:
        for rule in sg.ip_permissions:
            if [cidr for cidr in rule['IpRanges'] if cidr['CidrIp'] == '0.0.0.0/0']:
                if rule['FromPort'] != rule['ToPort']:
                    port_range = range(rule['FromPort'], rule['ToPort']+1)
                    for port in port_range:
                        if port in FORBIDDEN_PORTS:
                            result_msg = 'Using port range, cannot create compliance.'+nonCompliantSgId+' '+nonCompliantSgIdName
                    if result == ComplianceResult.NOT_CORRECTABLE:
                        continue
                port = rule['ToPort']
                if port in FORBIDDEN_PORTS:
                    sg.revoke_ingress(IpProtocol=rule['IpProtocol'], FromPort=port, ToPort=port, CidrIp='0.0.0.0/0')
                    time.sleep(1)
                    result = ComplianceResult.CORRECTED
                    result_msg = 'Non compliant security group removed '+nonCompliantSgId +' '+nonCompliantSgIdName
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        result_msg = ''.join('!! ' + line for line in lines)
        result = ComplianceResult.ERROR
    return result, result_msg

def lambda_handler(event, context):
    print('Event: {}'.format(event))
    if 'Details' in event['detail']['findings'][0]['Resources'][0].keys():
        det = event['detail']['findings'][0]['Resources'][0]['Details']
        nonCompliantSgId = str(det['AwsEc2SecurityGroup']['GroupId'])
        nonCompliantSgIdName = str(det['AwsEc2SecurityGroup']['GroupName'])
        findingId = str(event['detail']['findings'][0]['Id'])
        region = str(event['detail']['findings'][0]['Resources'][0]['Region'])
        lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
        result = ComplianceResult.NOT_CORRECTABLE
        if 'TEMP' in nonCompliantSgIdName:
            #TODO Add tags to filter out allowed security groups
            result,result_msg = fix_security_group(region, nonCompliantSgId,nonCompliantSgIdName)
        else:
            result_msg = 'Not compliance LAB security group'
        
        if result == ComplianceResult.CORRECTED:
            try:
                securityhub = boto3.client('securityhub')
                response = securityhub.update_findings(Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]
                    },Note={'Text': 'Automatic Remidiation was invoked. Refer to Automation results to determine efficacy:' + result_msg,
                    'UpdatedBy': lambdaFunctionName},RecordState='ACTIVE')
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
