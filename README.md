# Auvant
AUtomated VulnerAbility huNTer

Automate vulnerability scanning utilizing OpenVas

### Starting OpenVas
OpenVas needs to be configured and running when running adhoc scans, and the WebAPI. 
To quick start openvas on [Kali Linux](https://www.hackingtutorials.org/scanning-tutorials/installing-openvas-kali-linux/):
```
# apt-get install openvas
# openvas-setup
# openvas-start
# openvasmd --user=admin --new-password=new_password
```


### Running adhoc scans and return CSV.
Configure Auvant/Solo/config.ini to point to your OpenVas Server. Make sure to create appropriate credentials, and enter their config id's accordingingly. If you attempt to run Auvant on a different server than where OpenVas is running, you will need to install 'omp'.
Once omp is installed, here's how to get start running adhoc scans through command line with OpenVas and output to CSV.

```
# git clone https://github.com/infosecwatchman/Auvant.git
# cd Auvant/Solo
```
To run an uncredentialed scan:

```# python ./runScan.py NameOfScan 127.0.0.1 Standard```

To run a credentialed scan against a Windows device:

```# python ./runScan.py NameOfScan 127.0.0.1 Windows```

To run a credentialed scan against a Linux device:

```# python ./runScan.py NameOfScan 127.0.0.1 Linux```


### Pulling Vulnerabilities from Outlook Mail and upload to Jira
This process searches for the attachment on the current day. As of now, it can only injest one attachment.
Using the [sample file](Vuln_Init_Injest/sample_parameters.json) create a parameters.json file under Vuln_Init_Injest. Create an app and register it in a [Azure](https://aad.portal.azure.com/). Once you have created an app in Azure, click into your app, and under the Getting-Started page, download the package for Python. In "ms-identity-python-daemon-master\1-Call-MsGraph-WithSecret", there is a parameter.json that will help setting up the correct information. 
Set the correct email to search in, and set the appropriate subject. 
Expected rows in CSV: Asset Name,CVE,Device ID,IP Address,Issue Description,Issue Family,Issue Name,Risk Score,Threat,Date
Depending on your setup for Jira Service Desk, you will need to create a API token, and set it appropriately. Modify the userids as needed to set them correctly for proper assignment. 
There are four text files in the Inventory directory, that are checked to set the different Assignees. See [Lines 136-150](https://github.com/infosecwatchman/Auvant/blob/e430dc4e68033154877ccca512d614e2bc559393/Vuln_Init_Injest/GetAttachmentFromOutlook.py#L136) to configure the Inventory and assigneeId's correctly. 

##### To start:
Once the parameters.json file is present and configured correctly. Pull CSV from email by these commands:
```
# git clone https://github.com/infosecwatchman/Auvant.git
# cd Auvant/Vuln_Init_Injest
# python GetAttachmentFromOutlook.py
```
