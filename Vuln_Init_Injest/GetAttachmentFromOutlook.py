"""
The configuration file would look like this (sans those // comments):

{
    "authority": "https://login.microsoftonline.com/Enter_the_Tenant_Name_Here",
    "client_id": "your_client_id",
    "scope": ["https://graph.microsoft.com/.default"],
        // For more information about scopes for an app, refer:
        // https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#second-case-access-token-request-with-a-certificate"

    "secret": "The secret generated by AAD during your confidential app registration",
        // For information about generating client secret, refer:
        // https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Client-Credentials#registering-client-secrets-using-the-application-registration-portal

    "endpoint": "https://graph.microsoft.com/v1.0/users"

}

You can then run this script with a JSON configuration file:

    python GetAttachmentFromOutlook.py
"""

import json
import logging
import requests
import msal
import base64
import csv
from datetime import date
from io import StringIO
from jira import JIRA


def GetCSVAttachment():
    # Optional logging
    # logging.basicConfig(level=logging.DEBUG)
    config = json.load(open('./parameters.json'))
    #Current date to search for
    today = date.today()
    TodaysDate = today.strftime("%Y-%m-%d")
    #TodaysDate = "2020-05-21"
    subject = config["subject"]
    email = config["email"]
    query = "https://graph.microsoft.com/v1.0/users/"+email+"/messages?$select=Id&$filter=HasAttachments eq true and createdDateTime ge "+TodaysDate+" and startswith(Subject,'"+subject+"')"

    # Create a preferably long-lived app instance which maintains a token cache.
    app = msal.ConfidentialClientApplication(
        config["client_id"], authority=config["authority"],
        client_credential=config["secret"],
        # token_cache=...  # Default cache is in memory only.
                           # You can learn how to use SerializableTokenCache from
                           # https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
        )


    # The pattern to acquire a token looks like this.
    result = None

    # Firstly, looks up a token from cache
    # Since we are looking for token for the current app, NOT for an end user,
    # notice we give account parameter as None.
    result = app.acquire_token_silent(config["scope"], account=None)

    if not result:
        logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
        result = app.acquire_token_for_client(scopes=config["scope"])

    if "access_token" in result:
        # Calling graph using the access token
        email_data = requests.get(  # Use token to call downstream service
            query,
            headers={'Authorization': 'Bearer ' + result['access_token']}, ).json()
        #print("Graph API call result: ")
        #print(json.dumps(email_data, indent=2))
        ID = email_data['value'][0]['id']
        #print("\nID: " + email_data['value'][0]['id'])

        AttachmentQuery = "https://graph.microsoft.com/v1.0/users/"+email+"/messages/"+ID+"/attachments"
        attachment_data = requests.get(  # Use token to call downstream service
            AttachmentQuery,
            headers={'Authorization': 'Bearer ' + result['access_token']}, ).json()
        #print("Attachment call result: ")
        #print(json.dumps(attachment_data, indent=2))

        base64_content = attachment_data['value'][0]['contentBytes']
        base64_bytes = base64_content.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')
        CSVReport = open("./output/NewVulns-" + TodaysDate + ".csv", "w")
        CSVReport.write(message)
        CSVReport.close()
        #print(result['access_token'])
        return message
    else:
        print(result.get("error"))
        print(result.get("error_description"))
        print(result.get("correlation_id"))  # You may need this when reporting a bug


def CreateTicket(data):
    config = json.load(open('./parameters.json'))
    CyberInventoryFile = open("Inventory/Cyber.txt")
    NetworkInventoryFile = open("Inventory/NetworkDevices.txt")
    WorkstationInventoryFile = open("Inventory/Workstation.txt")
    ServerInventoryFile = open("Inventory/Servers.txt")
    CyberInventory = CyberInventoryFile.read().strip().split()
    NetworkInventory = NetworkInventoryFile.read().strip().split()
    WorkstationInventory = WorkstationInventoryFile.read().strip().split()
    ServerInventory = ServerInventoryFile.read().strip().split()
    NVDLink = "https://nvd.nist.gov/vuln/detail/"
    userid1 = config['userid1']
    userid2 = config['userid2']
    userid3 = config['userid3']
    userid4 = config['userid4']
    userid5 = config['userid5']
    userid6 = config['userid6']

    with StringIO(data) as csvdata:
        ReadData = csv.DictReader(csvdata, delimiter=',', quotechar='"')
        #Expected rows: Asset Name,CVE,Device ID,IP Address,Issue Description,Issue Family,Issue Name,Risk Score,Threat,Date
        for row in ReadData:
            #print(row)
            AssetName = row['Asset Name']
            CVE = row['CVE']
            DeviceID = row['Device ID']
            IPAddress = row['IP Address']
            IssueDescription = row['Issue Description']
            IssueFamily = row['Issue Family']
            IssueName = row['Issue Name']
            RiskScore = row['Risk Score']
            Threat = row['Threat']
            Date = row['Date']
            Reporter = "user1"
            ReporterID = userid1
            if row['IP Address'] in CyberInventory:
                Assignee = "user2"
                AssigneeID = userid2
            elif row['IP Address'] in NetworkInventory:
                Assignee = "user3"
                AssigneeID = userid3
            elif row['IP Address'] in WorkstationInventory:
                Assignee = "user4"
                AssigneeID = userid4
            elif row['IP Address'] in ServerInventory:
                Assignee = "user5"
                AssigneeID = userid5
            else: #(Default Assignee)
                Assignee = "user6"
                AssigneeID = userid6
            if '[' in row["CVE"]: # Formating how CVE lists are ingested
                comment = ""
                CVEBlock = ''
                NVDBlock = ''
                CVEBlock = row["CVE"].replace(" ", "")
                CVEBlock = CVEBlock.replace('["', '(')
                CVEBlock = CVEBlock.replace('"]', ')')
                CVEBlock = CVEBlock.replace('""', '\n')
                CVEBlock1 = CVEBlock.split('\n')
                for row in CVEBlock1:
                    row = row.replace('(', '')
                    row = row.replace(')', '')
                    NVDBlock = NVDBlock + NVDLink + row + '\n'
            elif row["CVE"] == 'NOCVE':
                CVEBlock = ''
                NVDBlock = ''
                CVEBlock = 'NOCVE'
                Assignee = "user1"
                AssigneeID = userid1 # Provide more details before assigning another person.
                comment = "This product is end of life.\n\n" # Provide more details before assigning another person.
            else:
                NVDBlock = ''
                CVEBlock = ''
                CVEBlock = row["CVE"]
                CVEBlock = CVEBlock.replace(' ', '')
                NVDBlock = NVDLink + row["CVE"]
                comment = ""
            #print('################################')
            #print(IPAddress)
            #print(RiskScore)
            #print(Assignee)
            #print(NVDBlock)
            #print(CVEBlock)
            jira_description = comment + IPAddress + '\n' + CVEBlock + '\n' + '\n' + IssueFamily + '\n' + IssueName + '\n' + IssueDescription + '\n' + '\n' + 'Severity Level: ' + RiskScore + '\n' + NVDBlock
            search_query = IPAddress + '\n' + CVEBlock + '\n' + 'Severity Level: ' + RiskScore + '\n' + NVDBlock
            auth_jira = JIRA(config['jiraurl'], basic_auth=(config["jirauser"], config["jiraapitoken"]))
            SearchForExisting = auth_jira.search_issues('project = VULN AND summary ~ "\\\"'+IPAddress+'\\\"" AND description ~ "\\\"'+search_query+'\\\"" ')
            try:
                IssueKey = SearchForExisting[0]
            except:
                pass
            if SearchForExisting == []:
                new_issue = auth_jira.create_issue(project='VULN', summary=IPAddress, description=jira_description, issuetype={'name': 'Vulnerability'}, reporter={'accountId': ReporterID}, assignee={'accountId': AssigneeID})
            else:
                #print IssueKey
                auth_jira.add_comment(IssueKey, "Vulnerability still present.")
            #new_issue.update(reporter={'accountId': ReporterID})
            #new_issue.update(assignee={'accountId': AssigneeID})


CreateTicket(GetCSVAttachment())
