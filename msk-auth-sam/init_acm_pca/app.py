import json
import http.client
import boto3
import time

def send_response(status, message, event):
    msg = {
        'Status': status,
        'Reason': message,
        'PhysicalResourceId': event['LogicalResourceId']+'001',
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
    }
    presigned = event['ResponseURL']
    splits = presigned.split("/")
    server = splits[2]
    parms = "/".join(splits[3:])
    parms = "/"+parms
    print("Response Server: "+server)
    print("Response parameters: "+parms)
    print("Response message: "+json.dumps(msg))
    msgStr = json.dumps(msg)
    headers = {"Content-Type": "", "Content-Length": len(msgStr)}
    connection = http.client.HTTPSConnection(server)
    connection.request("PUT", parms,body=msgStr,headers=headers)
    response = connection.getresponse()
    print("S3 status response: {} reason: {}".format(response.status, response.reason))


def lambda_handler(event, context):
    acmpca = boto3.client("acm-pca")
    csrResponse = acmpca.get_certificate_authority_csr(CertificateAuthorityArn=event['ResourceProperties']['CertificateAuthorityArn'])
    csrString = csrResponse['Csr']
    print(csrString)
    csrBytes = csrString.encode('utf-8')

    certIssueResponse = acmpca.issue_certificate(
        CertificateAuthorityArn=event['ResourceProperties']['CertificateAuthorityArn'],
        Csr=csrBytes,
        SigningAlgorithm="SHA256WITHRSA",
        TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity= {"Type": "DAYS", "Value": 90}
    )

    certArn = certIssueResponse['CertificateArn']
    print("Issued Certificate Arn: {}".format(certArn))

    notDone = True
    while(notDone):
        try:
            certResponse = acmpca.get_certificate(
                CertificateAuthorityArn=event['ResourceProperties']['CertificateAuthorityArn'],
                CertificateArn=certArn
            )
            notDone = False
        except acmpca.exceptions.RequestInProgressException as e:
            print("Certificate isn't ready yet. Sleeping a bit.")
            time.sleep(10)

    print("Cert response: {}".format(certResponse))
    certString = certResponse['Certificate']
    print("Certificate: {}".format(certString))

    certBytes = certString.encode('utf-8')

    importResponse = acmpca.import_certificate_authority_certificate(
        CertificateAuthorityArn=event['ResourceProperties']['CertificateAuthorityArn'],
        Certificate=certBytes
    )

    print("Import response: {}".format(importResponse))
    
    send_response("SUCCESSFUL", "Activated.", event)
