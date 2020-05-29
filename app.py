#!/usr/bin/python
import boto3
import json
import logging
import time
import sys
import click


client = boto3.client('iam')
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

iam_output = dict()

# Generating credentials report
def get_credentials_report_data():
    client.generate_credential_report()
    while client.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(5)

    info = client.get_credential_report()["Content"]
    output = info.decode("utf-8").split("\n")
    data = []
    for item in output:
        data.append(item.split(","))

    res = []
    for i in range(len(data)):
        if i == 0:
            continue
        result = {}
        for j in range(len(data[i])):
            result[data[0][j]] = data[i][j]
        res.append(result)

    iam_output["credential_report"] = res

# Generating the users data
def get_users_data():
    response = client.list_users()['Users']
    for user in response:
        list_of_checks = {
            "LoginProfile" : client.get_login_profile,
            "PolicyNames" : client.list_user_policies,
            "AttachedPolicies" : client.list_attached_user_policies,
            "AccessKeyMetadata" : client.list_access_keys,
            "Groups" : client.list_groups_for_user,
            "MFADevices" : client.list_mfa_devices,
            "Certificates" : client.list_signing_certificates,
            "SSHPublicKeys" : client.list_ssh_public_keys,
            "User" : client.get_user,
        }
        for key in list_of_checks:
            try:
                user[key] = list_of_checks[key](UserName=user['UserName'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['Users'] = response

# Generating the groups data
def get_groups_data():
    response = client.list_groups()['Groups']
    for group in response:
        list_of_checks = {
            "Group" : client.get_group,
            "PolicyNames": client.list_group_policies,
            "AttachedPolicies": client.list_attached_group_policies,
        }
        for key in list_of_checks:
            try:
                group[key] = list_of_checks[key](GroupName=group['GroupName'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['Groups'] = response

# Generating the roles data
def get_roles_data():
    response = client.list_roles()['Roles']
    for role in response:
        list_of_checks = {
            "Role" : client.get_role,
            "PolicyNames" : client.list_role_policies,
            "Tags" : client.list_role_tags,
            "AttachedPolicies" : client.list_attached_role_policies,
            "InstanceProfiles" : client.list_instance_profiles_for_role,
        }
        for key in list_of_checks:
            try:
                role[key] = list_of_checks[key](RoleName=role['RoleName'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['Roles'] = response

# Generating the policies data
def get_policies_data():
    response = client.list_policies()['Policies']
    for policy in response:
        list_of_checks = {
            "Policy" : client.get_policy,
            "Versions" : client.list_policy_versions,
        }
        for key in list_of_checks:
            try:
                policy[key] = list_of_checks[key](PolicyArn=policy['Arn'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['Policies'] = response

# Generating the instance profile data
def get_instance_profiles_data():
    response = client.list_instance_profiles()['InstanceProfiles']
    for profile in response:
        list_of_checks = {
            "InstanceProfile" : client.get_instance_profile,
        }
        for key in list_of_checks:
            try:
                profile[key] = list_of_checks[key](InstanceProfileName=profile['InstanceProfileName'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['InstanceProfiles'] = response

# Generating the account aliases data
def get_account_aliases_data():
    response = client.list_account_aliases()['AccountAliases']
    iam_output['AccountAliases'] = response

# Generating the open id connection providers data
def get_open_id_connection_providers_data():
    response = client.list_open_id_connect_providers()['OpenIDConnectProviderList']
    iam_output['OpenIDConnectProviderList'] = response


# def get_open_id_connection_providers_data():
#     response = client.list_open_id_connect_providers()['OpenIDConnectProviderList']
#     for provider in response:
#         list_of_checks = {
#             "Arn" : client.get_open_id_connect_provider,
#         }
#         for key in list_of_checks:
#             try:
#                 provider[key] = list_of_checks[key](OpenIDConnectProviderArn=provider['Arn'])
#             except Exception as e:
#                 logging.warning("Failed with %s; skipping.", e)

#     iam_output['OpenIDConnectProviderList'] = response

# Generating the saml providers data
def get_saml_providers_data():
    response = client.list_saml_providers()['SAMLProviderList']
    iam_output['SAMLProviderList'] = response


# def get_saml_providers_data():
#     response = client.list_saml_providers()['SAMLProviderList']
#     for provider in response:
#         list_of_checks = {
#             "Arn" : client.get_saml_provider,
#         }
#         for key in list_of_checks:
#             try:
#                 provider[key] = list_of_checks[key](SAMLProviderArn=provider['Arn'])
#             except Exception as e:
#                 logging.warning("Failed with %s; skipping.", e)

#     iam_output['SAMLProviderList'] = response

# Generating the server certificates data
def get_server_certificates_data():
    response = client.list_server_certificates()['ServerCertificateMetadataList']
    for certificate in response:
        list_of_checks = {
            "ServerCertificate" : client.get_server_certificate,
        }
        for key in list_of_checks:
            try:
                certificate[key] = list_of_checks[key](ServerCertificateName=certificate['ServerCertificateName'])[key]
            except Exception as e:
                logging.warning("Failed with %s; skipping.", e)

    iam_output['ServerCertificateMetadataList'] = response

# Generating the virtual mfa providers data
def get_virtual_mfa_devices_data():
    response = client.list_virtual_mfa_devices()['VirtualMFADevices']
    iam_output['VirtualMFADevices'] = response

# Generating the account authorization data
def get_account_authorization_data():
    response = dict()
    output = client.get_account_authorization_details()
    response['UserDetailList'] = output['UserDetailList']
    response['GroupDetailList'] = output['GroupDetailList']
    response['RoleDetailList'] = output['RoleDetailList']
    response['Policies'] = output['Policies']

    iam_output['AccountAuthorizationDetails'] = response

# Generating the account password policy data
def get_account_password_policy_data():
    response = client.get_account_password_policy()['PasswordPolicy']
    iam_output['PasswordPolicy'] = response

# Generating the account summary data
def get_account_summary_data():
    response = client.get_account_summary()['SummaryMap']
    iam_output['SummaryMap'] = response

# Calling all the funcions to generate data
def iam_analysis(output_file_path):
    print("Starting your AWS IAM Analysis...")
    get_users_data()
    get_groups_data()
    get_roles_data()
    # Currently we are getting used policies via get_account_summary_data and later will try to handle this to keep 6xx policies locally rather fetching from AWS as it's time consuming and making unnecessary requests to the AWS API
    # get_policies_data()
    get_instance_profiles_data()
    get_account_aliases_data()
    get_open_id_connection_providers_data()
    get_saml_providers_data()
    get_server_certificates_data()
    get_virtual_mfa_devices_data()
    get_account_authorization_data()
    get_account_password_policy_data()
    get_account_summary_data()

    f = open(output_file_path, "w")
    f.write(json.dumps(iam_output, indent=4, sort_keys=True, default=str))
    print("Successfully written output to : %s" %(output_file_path))
    f.close()


@click.group()
def main():
    """
    Simple CLI for AWS IAM access rights
    """
    pass

@main.command('extract')
@click.option('--outputpath', default="output.json", help="File to store the results")
def extract(outputpath):
    """Extract policies from designated AWS account to which you are logged into"""
    iam_analysis(outputpath)
    

if __name__ == "__main__":
    main()

