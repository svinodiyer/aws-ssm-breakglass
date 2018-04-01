from __future__ import print_function
 
import logging
from botocore.exceptions import ClientError
import boto3
import os
import random
import string
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sts_client = boto3.client('sts')
 
def send_tag_run_command(session, document_name, commands, target_key, tag_value, comment):
    """
        Tries to queue a RunCommand job.  If a ThrottlingException is encountered
        recursively calls itself until success.
        """
    try:
        ssm = session.client('ssm')
    except ClientError as err:
        logger.error("Run Command Failed!\n%s", str(err))
        return False
 
    try:
        resp = ssm.send_command(
            Targets=[
                {
                    'Key': target_key,
                    'Values': [
                        tag_value,
                    ]
                },
            ],
            DocumentName=document_name,
            Parameters={
                'commands': commands,
                'executionTimeout': ['600']  # Seconds all commands have to complete in
            },
            Comment=comment
        )
        logger.info('============RunCommand using Tag Name sent successfully, CommandID: ' + resp['Command']['CommandId'])
        return resp['Command']['CommandId']
    except ClientError as err:
        if 'ThrottlingException' in str(err):
            logger.info("RunCommand throttled, automatically retrying...")
            send_tag_run_command(session, document_name, commands, target_key, tag_value, comment)
        else:
            logger.error("Run Tag Command Failed!\n%s", str(err))
    return False
 
 
def send_instance_run_command(session, document_name, commands, instance_id_list, comment):
    """
        Tries to queue a RunCommand job.  If a ThrottlingException is encountered
        recursively calls itself until success.
        """
    try:
        ssm = session.client('ssm')
    except ClientError as err:
        logger.error("Run Command Failed!\n%s", str(err))
        return False
 
    try:
        
        resp = ssm.send_command(
            InstanceIds=instance_id_list,
            DocumentName=document_name,
            Parameters={
                'commands': commands,
                'executionTimeout': ['600']  # Seconds all commands have to complete in
            },
            Comment=comment
        )
        logger.info('============RunCommand Using Instances sent successfully, CommandID:' + resp['Command']['CommandId'])
        
        return resp['Command']['CommandId']
    except ClientError as err:
        if 'ThrottlingException' in str(err):
            logger.info("RunCommand throttled, automatically retrying...")
            send_instance_run_command(session, document_name, commands, instance_id_list, comment)
        else:
            logger.error("Run Instance Command Failed!\n%s", str(err))
    return False
 
def ssm_put_parameter(session, username, password, parameter_name):
    """
        Tries to queue a Put Parameter job.  If a ThrottlingException is encountered
        recursively calls itself until success.
        """
    parameter_name = 'break-glass-'+parameter_name
    try:
        ssm = session.client('ssm')
    except ClientError as err:
        logger.error("Run Command Failed!\n%s", str(err))
        return False
 
    try:
        resp = ssm.put_parameter(
            Name=parameter_name,
            Description='password for breakglass',
            Value=password,
            Type='SecureString', 
            Overwrite=False
        )
        logger.info('============SSM Put Parameter success')
        return parameter_name
        
    except ClientError as err:
        if 'ThrottlingException' in str(err):
            logger.info("SSM Put Paramter throttled, automatically retrying...")
            return ssm_put_parameter(session, username, password, command_id)
        else:
            logger.error("SSM Put Parameter!\n%s", str(err))
    return False
 
def ssm_delete_parameter(session, parameter_name):
    """
        Tries to queue a Delete Parameter job.  If a ThrottlingException is encountered
        recursively calls itself until success.
        """
    try:
        ssm = session.client('ssm')
    except ClientError as err:
        logger.error("Run Command Failed!\n%s", str(err))
        return False
 
    try:
        resp = ssm.delete_parameter(Name=parameter_name)
        logger.info('============SSM Delete Parameter success')
        
        return True
    except ClientError as err:
        if 'ThrottlingException' in str(err):
            logger.info("SSM Delete Paramter throttled, automatically retrying...")
            ssm_delete_parameter(session, parameter_name)
        else:
            logger.error("SSM Delete Parameter!\n%s", str(err))
    return False
 
 
 
def getPassword():
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10)) +'#'
 
def getRandomParameterName():
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(24))
 
def getInstanceList(instance_id_list, elb_type, elb_name, session):
    if str(elb_type) == 'elbv2':
        elb_client = session.client('elbv2')
        elb_details = elb_client.describe_load_balancers(Names=[
            elb_name,
        ])
        logger.info(elb_details.get('LoadBalancers')[0].get('LoadBalancerArn'))
        target_groups = elb_client.describe_target_groups(
            LoadBalancerArn=elb_details.get('LoadBalancers')[0].get('LoadBalancerArn')
        )
 
        logger.info(target_groups.get('TargetGroups')[0].get('TargetGroupArn'))
 
        targets = elb_client.describe_target_health(
            TargetGroupArn=target_groups.get('TargetGroups')[0].get('TargetGroupArn'),
 
        )
        for key in targets['TargetHealthDescriptions']:
            instance_id_list.append(key.get('Target').get('Id'))
    else:
        elb_client = session.client('elb')
        elb_details = elb_client.describe_load_balancers(
            LoadBalancerNames=[
                elb_name,
            ],
        )
        logger.info(elb_details.get('LoadBalancerDescriptions')[0].get('Instances'))
        for key in elb_details.get('LoadBalancerDescriptions')[0].get('Instances'):
            instance_id_list.append(key.get('InstanceId'))
 
    return instance_id_list
  
def linux_execution(session, elb_name, elb_type, command_type, instance_id_list, tag_value, platform_type, username, password_parameter_name):
    """ Issue Break Glass commands on an SSH bastion for enabling or disabling a user
 
    :param session: a boto session, usually from assume role to run commands with
    :param elb_name: the name of the elb for the jumphost
    :param elb_type: the type of elb for the jumphost
    :param command_type: string containing the command type, either ENABLE or DISABLE
    :param username: the username to manage
    :param password: the password of the user to manage
    :return:
    """ 
 
    document_name = 'AWS-RunShellScript'
    if str(elb_name) != 'None' and str(tag_value)=='None':
        instance_id_list = []
        instance_id_list = getInstanceList(instance_id_list, elb_type, elb_name, session)
        
    logger.info(instance_id_list)
    
    comment = 'Break glass for Linux Hosts'
    password = "$(aws ssm get-parameters --names "+ password_parameter_name + " --with-decryption --query 'Parameters[*].{Value:Value}' --output text --region ap-southeast-2)"
 
    if str(command_type) == 'ENABLE':
        commands = [
            # Add a new user, create their homedir if it doesn't exist
            "useradd --create-home {username}".format(username=username),
            # Change the password for a user
            # We shouldn't the password in clear text, hence using cli to get from parameter store
            "echo '{username}':{password} | chpasswd".format(username=username, password=password),
            # Below provides sudo access
            "echo '{username} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/999-break-glass-{username}".format(username=username)
        ]
    elif str(command_type) == 'DISABLE':
        commands = [
            "killall -KILL -u {username}".format(username=username),
            "userdel -r {username}".format(username=username),
            # If we want to clean up that user's homedir, uncomment the following
            "[ -d /home/{username} ] && rm -rf /home/{username}".format(username=username),
            # Remove sudo access
            "rm -rf /etc/sudoers.d/999-break-glass-{username}".format(username=username)
        ]
    else:
        raise Exception("Called with invalid command_type")
    
    if str(tag_value) == 'None':
        logger.info('============RunCommand Using Instances')
        return send_instance_run_command(session, document_name, commands, instance_id_list, comment)
    else:
        logger.info('============RunCommand Using Target Value Pair or All instance with the tag passed')
        return send_tag_run_command(session, document_name, commands, 'tag:Name', tag_value, comment)
         
  
def windows_execution(session, elb_name, elb_type, command_type, instance_id_list, tag_value, platform_type, username, password_parameter_name):
    """ Issue Break Glass commands on the remote desktop gateway for enabling or disabling a user
 
    :param session: a boto session, usually from assume role to run commands with
    :param elb_name: the name of the elb for the jumphost
    :param elb_type: the type of elb for the jumphost
    :param command_type: string containing the command type, either ENABLE or DISABLE
    :param username: the username to manage
    :param password: the password of the user to manage
    :return:
    """
    document_name = 'AWS-RunPowerShellScript'
    if str(elb_name) != 'None' and str(tag_value)=='None':
        instance_id_list = []
        instance_id_list = getInstanceList(instance_id_list, elb_type, elb_name, session)

    logger.info(instance_id_list)
        
    if command_type == 'ENABLE':
        commands = [
            """ try
                {
                  $breakglassUser = '""" + username + """'
                  $breakglassPass =  (Get-SSMParameterValue -Name """ + password_parameter_name + """ -WithDecryption $True).Parameters[0].Value
                  $allFeatures = Get-WindowsFeature
                  $rdsGatewayInstalled = ($allFeatures | Where-Object {$_.Name -eq 'RDS-Gateway'}).Installed
                  $domainServicesInstalled = ($allFeatures | Where-Object {$_.Name -eq 'AD-Domain-Services'}).Installed
               
                  # If the instance is a domain controller, the breakglass script should not run.
                  if (-Not $domainServicesInstalled)
                  {
                      # Add a breakglass user and give it Administrator level access (PowerShell user management cmdlets are not used for Windows backward compatability).
                      Write-Output 'Creating breakglass user and adding it to Administrators group'
                      net user $breakglassUser $breakglassPass /add
                      net localgroup 'Administrators' $breakglassUser /add
               
                      # If the instance is also an RDS Gateway, configure it to allow access to the breakglass user
                      if ($rdsGatewayInstalled)
                      {
                        Write-Output 'RDS Gateway role detected. Configuring RDS Gateway to allow breakglass access.'
                        Import-Module RemoteDesktopServices
                        New-Item -Path RDS:\GatewayServer\CAP -Name $breakglassUser -UserGroups 'Administrators@BUILTIN' -AuthMethod 1
                        New-Item -Path RDS:\GatewayServer\RAP -Name $breakglassUser -UserGroups 'Administrators@BUILTIN' -ComputerGroupType 2
                      }
                  }
                  else
                  {
                      Write-Output 'Domain controller role detected. Breakglass script will not execute'
                  }
                }
               
                # If anything fails in the commands, SSM run command should fail too
                catch
                {
                  Write-Output 'Exception block reached'
                  Write-Output $_.Exception.Message
                  Exit -1
                }"""
        ]
        comment = 'Break Glass Command - Enable Windows Local Administrator'
        
    elif command_type == 'DISABLE':
        commands = [
            """ try
                {
                  $breakglassUser = '""" + username + """'
                  $allFeatures = Get-WindowsFeature
                  $rdsGatewayInstalled = ($allFeatures | Where-Object {$_.Name -eq 'RDS-Gateway'}).Installed
                  $domainServicesInstalled = ($allFeatures | Where-Object {$_.Name -eq 'AD-Domain-Services'}).Installed
               
                  # If the instance is a domain controller, the breakglass script should not run.
                  if (-Not $domainServicesInstalled)
                  {
                      # If the instance is an RDS Gateway, remove the breakglass configurations
                      if ($rdsGatewayInstalled)
                      {
                        Write-Output 'RDS Gateway role detected. Removing RDS Gateway configurations that allowed breakglass access.'
                        Import-Module RemoteDesktopServices
                        Remove-Item -Path RDS:\GatewayServer\CAP\$breakglassUser -Recurse
                        Remove-Item -Path RDS:\GatewayServer\RAP\$breakglassUser -Recurse
                      }
               
                      # Remove the breakglass user (PowerShell user management cmdlets not used for backward compatability).
                      Write-Output 'Removing breakglass user.'
                      net localgroup 'Administrators' $breakglassUser /delete
                      net user $breakglassUser /delete
                  }
                  else
                  {
                      Write-Output 'Domain controller role detected. Breakglass script will not execute'
                  }
                }
               
                # If anything fails in the commands, SSM run command should fail too
                catch
                {
                  Write-Output 'Exception block reached'
                  Write-Output $_.Exception.Message
                  Exit -1
                }
            """
        ]
        comment = 'Break Glass Command - Disable Windows Local Administrator'
    else:
        raise Exception("Called with invalid command_type")
 
    if str(tag_value) == 'None':
        logger.info('============RunCommand Using Instances')
        return send_instance_run_command(session, document_name, commands, instance_id_list, comment)
    else:
        logger.info('============RunCommand Using Target Value Pair or All instance with the tag passed')
        return send_tag_run_command(session, document_name, commands, 'tag:Name', tag_value, comment)
    
         
def lambda_handler(event, context):
    invoking_event = event
    account_id = invoking_event.get('account_id')
    role_name = invoking_event.get('role_name')
    account_region = invoking_event.get('account_region')
    platform_type = invoking_event.get('platform_type')
    command_type = invoking_event.get('command_type')
    tag_value = invoking_event.get('tag_value')
    instance_id_list = invoking_event.get('instance_id_list')
    elb_name = invoking_event.get('elb_name')
    elb_type = invoking_event.get('elb_type')
    username = invoking_event.get('username')
    password_store_key = invoking_event.get('password_store_key')
     
    comment = 'Break Glass Command'
    commands = []
    target_key = 'tag:Platform' 
     
    execution_role = f'arn:aws:iam::{account_id}:role/{role_name}'
    logger.info(execution_role)
 
    role = sts_client.assume_role(
        RoleArn=execution_role,
        RoleSessionName='BreakGlass_{}_{}'.format(platform_type, command_type),
        DurationSeconds=1000
    )['Credentials']
 
    session = boto3.session.Session(
        aws_access_key_id=role['AccessKeyId'],
        aws_secret_access_key=role['SecretAccessKey'],
        aws_session_token=role['SessionToken'],
        region_name=account_region
 
    )
    password = getPassword() 
    
    command_id = ''
    parameter_name = ''
    if platform_type == 'Windows': 
        
        if (command_type=='DISABLE'):
            ssm_delete_parameter(session,password_store_key)
        elif (command_type=='ENABLE'):
            parameter_name = ssm_put_parameter(session, username, password, getRandomParameterName())
        
        command_id = windows_execution(session, elb_name, elb_type, command_type, instance_id_list, tag_value, platform_type, username, parameter_name)
        
            
    elif platform_type == 'Linux':
        
        if (command_type=='DISABLE'):
            ssm_delete_parameter(session,password_store_key)
        elif (command_type=='ENABLE'):
            parameter_name = ssm_put_parameter(session, username, password, getRandomParameterName())
            logger.info('parameter_name : ' + parameter_name)
            
        command_id = linux_execution(session, elb_name, elb_type, command_type, instance_id_list, tag_value, platform_type, username, parameter_name)
       
    else:
        logger.info('===========Invalid Input') 
  
    return command_id
