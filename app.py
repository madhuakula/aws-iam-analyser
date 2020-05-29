#!/usr/bin/python
"""This is an AWS IAM analytics utility to gather all related information to an AWS account."""

# Standard libraries imports
import json
import logging
import sys
import time

# 3rd party libraries import
import boto3
import click


client = boto3.client('iam')
logging.basicConfig(filename='output.log', level=logging.INFO, format='{asctime} - {name} - {levelname} - {message}', style='{')

iam_output = dict()

def get_credentials_report_data():
    """Generate the credentials report"""
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

def get_users_data():
    """Generate the users' data"""
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
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['Users'] = response

def get_groups_data():
    """Generate the groups' data"""
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
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['Groups'] = response

def get_roles_data():
    """Generate the roles' data"""
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
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['Roles'] = response

def get_policies_data():
    """Generate the policies' data"""
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
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['Policies'] = response

def get_instance_profiles_data():
    """Generate the instance profile data"""
    response = client.list_instance_profiles()['InstanceProfiles']
    for profile in response:
        list_of_checks = {
            "InstanceProfile" : client.get_instance_profile,
        }
        for key in list_of_checks:
            try:
                profile[key] = list_of_checks[key](InstanceProfileName=profile['InstanceProfileName'])[key]
            except Exception as e:
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['InstanceProfiles'] = response

def get_account_aliases_data():
    """Generate the account aliases' data"""
    response = client.list_account_aliases()['AccountAliases']
    iam_output['AccountAliases'] = response

def get_open_id_connection_providers_data():
    """Generate the OpenID connection providers' data"""
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

def get_saml_providers_data():
    """Generate the SAML providers' data"""
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

def get_server_certificates_data():
    """Generate the server certificates' data"""
    response = client.list_server_certificates()['ServerCertificateMetadataList']
    for certificate in response:
        list_of_checks = {
            "ServerCertificate" : client.get_server_certificate,
        }
        for key in list_of_checks:
            try:
                certificate[key] = list_of_checks[key](ServerCertificateName=certificate['ServerCertificateName'])[key]
            except Exception as e:
                logging.warning(f"Failed with {e}; skipping.")

    iam_output['ServerCertificateMetadataList'] = response

def get_virtual_mfa_devices_data():
    """Generate the virtual MFA providers' data"""
    response = client.list_virtual_mfa_devices()['VirtualMFADevices']
    iam_output['VirtualMFADevices'] = response

def get_account_authorization_data():
    """Generate the account authorization data"""
    response = dict()
    output = client.get_account_authorization_details()
    response['UserDetailList'] = output['UserDetailList']
    response['GroupDetailList'] = output['GroupDetailList']
    response['RoleDetailList'] = output['RoleDetailList']
    response['Policies'] = output['Policies']

    iam_output['AccountAuthorizationDetails'] = response

def get_account_password_policy_data():
    """Generate the account password policy data"""
    response = client.get_account_password_policy()['PasswordPolicy']
    iam_output['PasswordPolicy'] = response

def get_account_summary_data():
    """Generate the account summary data"""
    response = client.get_account_summary()['SummaryMap']
    iam_output['SummaryMap'] = response

def iam_analysis(output_file_path):
    """Call all functions to generate data"""
    print("Starting your AWS IAM Analysis...")
    get_users_data()
    get_groups_data()
    get_roles_data()
    # Currently we are getting used policies via get_account_summary_data and later will try to handle this to keep 6xx policies
    # locally rather fetching from AWS as it's time consuming and making unnecessary requests to the AWS API
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

    with open(output_file_path, "w") as json_output_file:
        json_output_file.write(json.dumps(iam_output, indent=4, sort_keys=True, default=str))
        print(f"Successfully written output to : {output_file_path}")

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

