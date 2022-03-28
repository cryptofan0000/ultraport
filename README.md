# ultraport

Custom packet forwarding and management panel.

### System Requirements:

##### Minimum Hardware Requirements
```
No of Cores: 1
 
Ram: 1GB
 
Storage: 1GB for log purpose
```
##### Software Requirements
```
OS: Debian or Ubuntu

Packages: 
   * ssh
   * gcc
   * git
   * curl
   * libb64

```
## Instructions

### Proxy Deployment

#### Pre-Requisite
```
* Launch a fresh system with either Debian or Ubuntu. (For example 45.76.9.93)
* ssh root@45.76.9.93
* apt-get update
* apt-get install -y build-essential git libcurl4-openssl-dev libb64-dev
* ufw disable
* git clone https://github.com/ultratelecom/ultraport
* username/password - ultratelecom/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
* cd ultraport/
* gcc deploy.c -o deploy -lm
* gcc list.c -o list
```
#### Launch
```
For Examples:
SingleProxy with SingleIP and SinglePort:
   * ./deploy -i 127.0.0.1 -p 3000
MultipleProxy with SingleIP and MultiplePort:
   * ./deploy -i 127.0.0.1 -p 4000 -q 4002
   -p=portStart
   -q=portEnd
MultipleProxy with MultipleIP and MultiplePort:
   * ./deploy -i 2.2.2.2/24 -p 5000
```

### Proxy Management
```
* View Lists of Proxies: ./list -l
* View a single list: ./list -p 3000.list
* Terminate a single list: ./list -t 3000.list
```
