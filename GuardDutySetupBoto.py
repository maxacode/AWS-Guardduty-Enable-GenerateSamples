#Enable Guardduty and create Sample findings and download them.  - https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/guardduty.html#GuardDuty.Client.create_detector


import boto3
from botocore import signers
import json
import os

client = boto3.client('guardduty')
 
#Just dashes to visual appearances
def dashes():
    print("\n -----------------------------------\n")


#Get the detectorID of the current Guardduty instance.
def getDetectorFunc():
    dashes()
    global detectorID
    print(" \nGetting Guardduty Detector ID! ")
    #Getting the ID of this accounts Guard Duty Detector. 
    listAllDetectorsResponse = client.list_detectors(
        MaxResults=1,
        NextToken='string'
    )

    #Parsing out the response to only have the Full ID of GD Detector. 
    detectorID = str(listAllDetectorsResponse['DetectorIds'])
    detectorID = detectorID[2:-2]

    #If empty response then GD is not enabled on this account if not then it will go enable it. 
    if detectorID == '':
        print("GuardDuty Not Setup! Will set it up now. ")
        dashes()
        enableGDFunc()
    #If GD is enabled it will prompt user to delete it and create a new one or proceed with generating sample findings. d
    else: 
        cont = input(f"Guardduty Detector is Running, with ID: {detectorID} \n\n Would you like to: 1) Generate Sample Finding or 2) Delete current GD and create new one:  ")
        #print(detectorID)
        if cont == '1':
            #getFindingIDs()
            createAllSampleFindings()
        elif cont == '2':
            deleteDetectorFunc()
        dashes()



#Funciton to delete guard duty based on detectorID - so to start fresh
def deleteDetectorFunc():
    dashes()
    print("Deleting Detector ID ")
    deleteGDResponse = client.delete_detector(
        DetectorId=detectorID
    )

   # print(deleteGDResponse)
    print("DELETE COMPLETE!")
    dashes()
    enableGDFunc()


#Function to enable Guardduty to
def enableGDFunc():
    print("Enableing Guardduty: ")
    enableGDResponse = client.create_detector(
        Enable=True,
        ClientToken='string',
        FindingPublishingFrequency='FIFTEEN_MINUTES',
        DataSources={
            'S3Logs': {
                'Enable': True
            }
        },
        Tags={
            'name': 'Freddy SME'
        }
    )
    getDetectorFunc()

#Create sample finding in GD
def createAllSampleFindings():
    dashes()
    print("Generating Sample Findings! ")
    generateAllSampleFindingsResponse = client.create_sample_findings(
        DetectorId=detectorID,
        FindingTypes=['Backdoor:EC2/C&CActivity.B', 'Backdoor:EC2/C&CActivity.B!DNS', 'Backdoor:EC2/DenialOfService.Dns', 'Backdoor:EC2/DenialOfService.Tcp', 'Backdoor:EC2/DenialOfService.Udp','Backdoor:EC2/DenialOfService.UdpOnTcpPorts','Backdoor:EC2/DenialOfService.UnusualProtocol','Backdoor:EC2/Spambot','Behavior:EC2/NetworkPortUnusual', 'Behavior:EC2/TrafficVolumeUnusual', 'CredentialAccess:IAMUser/AnomalousBehavior','CryptoCurrency:EC2/BitcoinTool.B','CryptoCurrency:EC2/BitcoinTool.B!DNS','DefenseEvasion:IAMUser/AnomalousBehavior','Discovery:IAMUser/AnomalousBehavior','Discovery:S3/MaliciousIPCaller','Discovery:S3/MaliciousIPCaller.Custom','Discovery:S3/TorIPCaller','Exfiltration:IAMUser/AnomalousBehavior','Exfiltration:S3/MaliciousIPCaller','Exfiltration:S3/ObjectRead.Unusual','Impact:EC2/AbusedDomainRequest.Reputation','Impact:EC2/BitcoinDomainRequest.Reputation','Impact:EC2/MaliciousDomainRequest.Reputation','Impact:EC2/PortSweep','Impact:EC2/SuspiciousDomainRequest.Reputation','Impact:EC2/WinRMBruteForce','Impact:IAMUser/AnomalousBehavior','Impact:S3/MaliciousIPCaller','InitialAccess:IAMUser/AnomalousBehavior','PenTest:IAMUser/KaliLinux','PenTest:IAMUser/ParrotLinux','PenTest:IAMUser/PentooLinux','PenTest:S3/KaliLinux','PenTest:S3/ParrotLinux','PenTest:S3/PentooLinux','Persistence:IAMUser/AnomalousBehavior','Policy:IAMUser/RootCredentialUsage','Policy:S3/AccountBlockPublicAccessDisabled','Policy:S3/BucketAnonymousAccessGranted','Policy:S3/BucketBlockPublicAccessDisabled','Policy:S3/BucketPublicAccessGranted','PrivilegeEscalation:IAMUser/AnomalousBehavior','Recon:EC2/PortProbeEMRUnprotectedPort','Recon:EC2/PortProbeUnprotectedPort','Recon:EC2/Portscan','Recon:IAMUser/MaliciousIPCaller','Recon:IAMUser/MaliciousIPCaller.Custom','Recon:IAMUser/TorIPCaller','Stealth:IAMUser/CloudTrailLoggingDisabled','Stealth:IAMUser/PasswordPolicyChange','Stealth:S3/ServerAccessLoggingDisabled','Trojan:EC2/BlackholeTraffic','Trojan:EC2/BlackholeTraffic!DNS','Trojan:EC2/DGADomainRequest.B','Trojan:EC2/DGADomainRequest.C!DNS','Trojan:EC2/DNSDataExfiltration','Trojan:EC2/DriveBySourceTraffic!DNS','Trojan:EC2/DropPoint','Trojan:EC2/DropPoint!DNS','Trojan:EC2/PhishingDomainRequest!DNS','UnauthorizedAccess:EC2/MaliciousIPCaller.Custom','UnauthorizedAccess:EC2/MetadataDNSRebind','UnauthorizedAccess:EC2/RDPBruteForce','UnauthorizedAccess:EC2/SSHBruteForce','UnauthorizedAccess:EC2/TorClient','UnauthorizedAccess:EC2/TorRelay','UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B','UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration','UnauthorizedAccess:IAMUser/MaliciousIPCaller','UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom','UnauthorizedAccess:IAMUser/TorIPCaller','UnauthorizedAccess:S3/MaliciousIPCaller.Custom','UnauthorizedAccess:S3/TorIPCaller']
    ) 
    print("Done Generatings Sample Findings ")
    #print(generateAllSampleFindingsResponse)
    getFindingIDs()

#get all finding id's
def getFindingIDs():
    global allFindingsIDs
    findingIDs = client.list_findings(
        DetectorId=detectorID,
        SortCriteria={
            'AttributeName': 'accountId',
            'OrderBy': 'ASC'
        },
        MaxResults=50,
    )
    allFindingsIDs = findingIDs['FindingIds']
    #allFindingsIDs = str(allFindingsIDs[1:-1])
    #dashes()
    #print(findingIDs)
    #print(f"Findings ID retrieved: {allFindingsIDs} \n Getting the Finidngs Now: ")
    getFindingsResults()

#get All findings results
def getFindingsResults():
    dashes()
    folderName = '/Guardduty-Findings/'

    print(f"Exporting all Findings to JSON into folder: {folderName}")
    #Looping through all the findings so to export them out as JSON into indivual file names.
    for singleFinding in allFindingsIDs:

        #print(f"Getting Finidngs Results for Find: {singleFinding}")
        getFindingsResponse = client.get_findings(
            DetectorId=detectorID,
            FindingIds=[
                singleFinding,
            ],
            SortCriteria={
                'AttributeName': 'accountId',
                'OrderBy': 'ASC'
            }
        )

        #Parsing out and replacing to use finding name as file nam.e 
        findingName = getFindingsResponse['Findings'][0]['Type']
        findingName = findingName.replace('/', '-')
        findingName = findingName.replace(':', '-')
        #print(findingName)
        currentPath = os.getcwd()
        
        #Checking if the folder of guardduty findings exists already, if not then will create it, if it does then will create the JSON file. 
        if os.path.exists(currentPath + folderName):
            findingName = currentPath + folderName + findingName + ".json"
            with open(findingName, 'w+') as file:
                #file.write(str(getFindingsResponse))
                json.dump(getFindingsResponse, file, indent=4, sort_keys=True, default=str)
                #print("Wrote to New File. ")
        else:
            os.mkdir(currentPath+folderName)
    
    print(f"DONE! Check the {folderName} Folder!" )
    



#Main Program 
getDetectorFunc()

