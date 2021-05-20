import json
import boto3

def publish_compliance_sns(message):
    sns = boto3.client('sns')
    a = sns.list_topics()
    dicts = a['Topics']
    # TODO sns topic should be linked not found by hardcoded string 
    arn = next((item for item in dicts if (item["TopicArn"]).find("sns-teams-compliance-topic") != -1), None)
    print(arn)
    if arn is not None:
        try:
            response = sns.publish(
                TargetArn=arn['TopicArn'],
                Message=json.dumps({'default': json.dumps(message)}),
                MessageStructure='json'
            )
            print(response)
        except Exception as e:
            print(e)
    else:
        print('No topic found')

def lambda_handler(event, context):
    print('Event: {}'.format(event))
    if event is not None:
        # Get alias for account
        alias = boto3.client('iam').list_account_aliases()['AccountAliases'][0]
        print(alias)
        if 'error' in event.keys():
            error = event['error']['Error']
            cause = event['error']['Cause']
            print (cause)
            # TODO notification about a unexpected error in the lambda that exectuded the compliance check 

        elif 'deafult' in event.keys():
            print(event['deafult']['Deafult']) 
            rule = str(event['detail']['findings'][0]['GeneratorId'])
            region  = str(event['region'])
            url =  "https://"+region+".console.aws.amazon.com/securityhub/home?region="+region+"#/findings"
            message = {
                'summary': "Automated Compliance",
                'title': "Compliance problem found by Deafult action. For account "+ alias +" in region "+ region, 
                'text': "Remediation needs to be created. For rule " + rule,
                'urlName': "AWS Security Hub findings",
                'url': url
            }
            message.update({'status': 'Alarm'})
            publish_compliance_sns(message)
            return message

        elif 'statusCode' in event.keys():
            function = event['body']['function']
            result = event['body']['result']
            if event['statusCode'] == 200:
                result_msg = event['body']['message']# the compliance could be corrected or is non correctable 
            elif event['statusCode'] == 500 :
                result_msg = event['body']['error']# unexpected but handled error 
 
            rule = str(event['body']['event']['detail']['findings'][0]['GeneratorId'])
            region  = str(event['body']['event']['region'])
            url =  "https://"+region+".console.aws.amazon.com/securityhub/home?region="+region+"#/findings"

            message = {
                'summary': "Automated Compliance",
                'title': "Compliance " + result + " by " + function + ". For account "+ alias +" in region "+ region, 
                'text': result_msg + ". For rule " + rule,
                'urlName': "AWS Security Hub findings" ,
                'url': url
            }
            if result != "CORRECTED":
                message.update({'status': 'Alarm'})
            else:
                message.update({'status': 'No'})
            
            publish_compliance_sns(message)
            return message
