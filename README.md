[comment]: # "Auto-generated SOAR connector documentation"
# Slack Bot

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Slack Technologies  
Product Name: Slack Bot  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.5  

Integrate with Slack using a custom Slack App

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Slack Bot asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**bot\_token** |  required  | password | Bot User OAuth Access Token
**socket\_token** |  required  | password | Socket Token
**soar\_auth\_token** |  required  | password | Automation User Auth Token
**permitted\_bot\_users** |  optional  | string | Users permitted to use bot commands\. Comma seperated list of Member IDs\. Leave blank to allow all users \(default\)
**log\_level** |  optional  | string | The log level for the bot
**permit\_bot\_get\_action** |  optional  | boolean | Permit 'get\_action' command
**permit\_bot\_run\_action** |  optional  | boolean | Permit 'run\_action' command
**permit\_bot\_get\_playbook** |  optional  | boolean | Permit 'get\_playbook' command
**permit\_bot\_run\_playbook** |  optional  | boolean | Permit 'run\_playbook' command
**permit\_bot\_get\_container** |  optional  | boolean | Permit 'get\_container' command

### Supported Actions  
[test connectivity](#action-test-connectivity) - Tests authorization with Slack  
[on poll](#action-on-poll) - Start Slack Bot and make health checks to it  
[start bot](#action-start-bot) - Start Slack Bot  
[stop bot](#action-stop-bot) - Stop Slack Bot  

## action: 'test connectivity'
Tests authorization with Slack

Type: **test**  
Read only: **True**

Checks that the provided bot token is valid and grabs information about the configured bot user\.

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Start Slack Bot and make health checks to it

Type: **ingest**  
Read only: **True**

Enabling ingestion causes the on poll action to be called every polling interval \(configured in ingestion settings\)\. The on poll action will check if Slack Bot is running; if it is not, the action will start it\. No new containers or artifacts will be created by this action\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_id** |  optional  | Parameter ignored in this app | string | 
**container\_count** |  optional  | Parameter ignored in this app | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'start bot'
Start Slack Bot

Type: **correct**  
Read only: **False**

This action will start Slack Bot if it is not already running\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'stop bot'
Stop Slack Bot

Type: **correct**  
Read only: **False**

This action will stop Slack Bot if it is running\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 