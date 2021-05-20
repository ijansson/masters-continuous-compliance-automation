import json
import logging
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

TEAMS_HOOK_URL = os.environ['TeamsHookUrl']

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    snsmessage = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Message: " + str(snsmessage))
    summary = snsmessage['summary']
    title = snsmessage['title'] 
    text = snsmessage['text'] 
    url = snsmessage['url']
    urlName = snsmessage['urlName'] 
    status = snsmessage['status']
    data = {
        "colour": "64a837"
    }
    if status == "Alarm":
        data['colour'] = "d63333"
        
    message = {
      "@context": "https://schema.org/extensions",
      "@type": "MessageCard",
      "summary": summary, 
      "themeColor": data["colour"],
      "title": title,
      "text": text,
      "potentialAction": [
    		{
    			"@type": "OpenUri",
    			"name": "Log in to AWS Console",
    			"targets": [{
    					"os": "default",
                         "uri": "TEMP"}]
    		},
    		{
    			"@type": "OpenUri",
    			"name": urlName,
    			"targets": [{
    					"os": "default",
    					"uri": str(url)}]
    		}
    	]
    }
    req = Request(TEAMS_HOOK_URL, json.dumps(message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
