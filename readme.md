[comment]: # "Auto-generated SOAR connector documentation"
# Vectra Active Enforcement

Publisher: Vectra  
Connector Version: 3\.0\.5  
Product Vendor: Vectra  
Product Name: Vectra Active Enforcement  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

This app supports investigate and ingest actions on Vectra Active Enforcement platform


Vectra Active Enforcement is designed to extract host information based on the following criteria:  

-   IP - Search for hosts based on addresses
-   Tagging - Search for hosts based tags applied to the object in the UI
-   Scoring - Search for hosts that meet or exceed user-defined minimum threat and certainty scores
-   Detections - Search for hosts that trigger detections based on user-defined detection categories
    and types

  
It is important to note that Vectra Active Enforcement is built around a source-host centric view of
the environment


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Vectra Active Enforcement asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** |  required  | string | Vectra Brain IP/Hostname
**severity** |  required  | string | Default severity
**username** |  required  | string | Username
**password** |  required  | password | Password
**tags** |  optional  | boolean | Enable tag search \(on poll\)
**ph\_0** |  optional  | ph | Placeholder
**dtags** |  optional  | string | Tags to search \(comma\-separated; no spaces\)
**ph\_1** |  optional  | ph | Placeholder
**scores** |  required  | boolean | Enable threat/certainty score search \(on poll\)
**ph\_2** |  optional  | ph | Placeholder
**cscore** |  optional  | numeric | Minimum certainty score
**tscore** |  optional  | numeric | Minimum threat score
**detections** |  required  | boolean | Enable search for detection types \(on poll\)
**ph\_3** |  optional  | ph | Placeholder
**dettypes** |  optional  | string | Detection types \(comma\-separated\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[lookup ip](#action-lookup-ip) - Retrieve host based on IP address  
[get detections](#action-get-detections) - Retrieve detections  
[get scored hosts](#action-get-scored-hosts) - Retrieve hosts based on a minimum certainty and threat score  
[get tagged hosts](#action-get-tagged-hosts) - Retrieve hosts based on descriptive tags  
[on poll](#action-on-poll) - Query device on a known interval  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Retrieve host based on IP address

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to lookup | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.data\.\*\.\*\.artifacts | string | 
action\_result\.data\.\*\.\*\.certainty | string | 
action\_result\.data\.\*\.\*\.id | numeric | 
action\_result\.data\.\*\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.\*\.key\_asset | string | 
action\_result\.data\.\*\.\*\.name | string | 
action\_result\.data\.\*\.\*\.owner | string | 
action\_result\.data\.\*\.\*\.state | string | 
action\_result\.data\.\*\.\*\.tags | string | 
action\_result\.data\.\*\.\*\.threat | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get detections'
Retrieve detections

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**src\_ip** |  optional  | Source IP address of detection | string |  `ip` 
**dest\_port** |  optional  | Destination port of detection | numeric | 
**dettypes** |  required  | Detection types | string | 
**state** |  required  | State of detection | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.dest\_port | numeric | 
action\_result\.parameter\.dettypes | string | 
action\_result\.parameter\.src\_ip | string |  `ip` 
action\_result\.parameter\.state | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.\*\.category | string | 
action\_result\.data\.\*\.\*\.certainty | string | 
action\_result\.data\.\*\.\*\.dst | string |  `ip` 
action\_result\.data\.\*\.\*\.id | numeric | 
action\_result\.data\.\*\.\*\.src | string |  `ip` 
action\_result\.data\.\*\.\*\.targets\_key\_asset | boolean | 
action\_result\.data\.\*\.\*\.threat | string | 
action\_result\.data\.\*\.\*\.triage\_rule | numeric | 
action\_result\.data\.\*\.\*\.type | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get scored hosts'
Retrieve hosts based on a minimum certainty and threat score

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cscore** |  required  | Minimum certainty score | numeric | 
**tscore** |  required  | Minimum threat score | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cscore | numeric | 
action\_result\.parameter\.tscore | numeric | 
action\_result\.data | string | 
action\_result\.data\.\*\.\*\.artifacts | string | 
action\_result\.data\.\*\.\*\.certainty | string | 
action\_result\.data\.\*\.\*\.id | numeric | 
action\_result\.data\.\*\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.\*\.key\_asset | string | 
action\_result\.data\.\*\.\*\.name | string | 
action\_result\.data\.\*\.\*\.owner | string | 
action\_result\.data\.\*\.\*\.state | string | 
action\_result\.data\.\*\.\*\.tags | string | 
action\_result\.data\.\*\.\*\.threat | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get tagged hosts'
Retrieve hosts based on descriptive tags

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**dtags** |  required  | Tags | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.dtags | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.\*\.artifacts | string | 
action\_result\.data\.\*\.\*\.certainty | string | 
action\_result\.data\.\*\.\*\.id | numeric | 
action\_result\.data\.\*\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.\*\.key\_asset | string | 
action\_result\.data\.\*\.\*\.name | string | 
action\_result\.data\.\*\.\*\.owner | string | 
action\_result\.data\.\*\.\*\.state | string | 
action\_result\.data\.\*\.\*\.tags | string | 
action\_result\.data\.\*\.\*\.threat | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Query device on a known interval

Type: **ingest**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output