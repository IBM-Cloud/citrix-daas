# Citrix Virtual Apps and Desktops service (CVADs) on IBM Virtual Private Cloud - Closed Beta

## Overview

This Terraform module deploys the following VPC infrastructure for enabling CVADs on IBM Cloud:

- VPC (optional)
- Subnet
- Public Gateway
- Security Groups
- Active Directory VSI
- Cloud Connector VSIs
- Additional VSI for creating custom image (optional)

![VPC Deployment Model](materials/vpc-deployment.png)

We recommend using the IBM Cloud portal WES-UI to deploy CVADs on IBM Cloud VPC. The
WES-UI creates an IBM Cloud Schematics workspace that points to this Terraform module and deploys
your CVADs infrastructure. Using Schematics is *no additional cost* and provides a way for you to
easily manage your Terraform lifecycle. See
[IBM Cloud portal WES-UI](https://cloud.ibm.com/wes-ui/citrix-virtual-app-desktop?featureFlags=vpcBeta)
.

For more information on IBM Cloud Schematics, see
[IBM Cloud Schematics](https://cloud.ibm.com/schematics/overview).

You may run this Terraform module locally, supplying the necessary variables. See
[Assigning values to root module variables](https://www.terraform.io/docs/language/values/variables.html#assigning-values-to-root-module-variables)
.

## Setup Requirements

### Prerequisites

#### Verify IBM Cloud Account

To order and use IBM Cloud services, billing information is required for your account. See
[Verify Your Account](https://cloud.ibm.com/docs/account?topic=account-upgrading-account).

#### Verify Citrix and Operating System Entitlements

Verify that you have Citrix Virtual Apps and Desktops Service license entitlements. Review the
requirements on [Citrix Cloud](https://citrix.cloud.com/).

#### Install Terraform

If you wish to run Terraform locally, see
[Install Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli#install-terraform).

#### IBM Cloud API Key

You must supply an IBM Cloud API key so that Terraform can connect to the IBM Cloud Terraform
provider. See
[Create API Key](https://cloud.ibm.com/docs/account?topic=account-userapikey&interface=ui#create_user_key).

#### Github Personal Access Token

You must create a new GitHub token in [GHE Personal Access Tokens](https://github.com/settings/tokens).

#### Enable VRF (optional)

If you would like to have network connection between IBM Cloud VPC and Classic Infrastructure, see
[Enabling VRF](https://cloud.ibm.com/docs/account?topic=account-vrf-service-endpoint&interface=ui#vrf)
. This option is *not* required to deploy CVADs on IBM Cloud VPC.

#### IBM Cloud Schematics Access Policies

You must create the proper Schematics access policies for a user to deploy CVADs on IBM Cloud VPC
using the
[WES-UI](https://cloud.ibm.com/wes-ui/citrix-virtual-app-desktop?featureFlags=vpcBeta)
or IBM Cloud Schematics. See
[IBM Cloud Schematics Access](https://cloud.ibm.com/docs/schematics?topic=schematics-access).

## Variable Behavior

There are a number of variables defined in variables.tf used by this Terraform module to
deploy and configure your CVADs infrastructure. This section will describe variable behavior. See
[variables.tf](variables.tf)
for full list of variables with their descriptions, defaults, and conditions.

### Active Directory Topology

#### IBM Cloud

When deploying CVADs on VPC using IBM Cloud topology, the following
infrastructure will be created by default:

- 1 x VPC (if VPC name not specified)
- 1 x /24 Subnet (256 IPs)
- 1 x Public Gateway
- 1 x Active Directory VSI
- 2 x Cloud Connector VSIs
- Custom Image VSI (optional)
- 3 Security Groups (4 if Custom Image VSI deployed)
  - Control Plane (Active Directory and Cloud Connector VSIs)
  - VDA VSIs
  - Master Image Prep VSI (VSI deployed during Citrix Machine Catalog creation)
  - Custom Image VSI (optional)

Your Active Directory VSI will come with AD installed and minimally configured. See
[AD Cloudbase-Init section](#active-directory).

Your Cloud Connector VSIs will be joined to your AD Domain Controller. See
[Cloud Connector Cloudbase-Init section](#cloud-connector).

#### Extended (Multisite)

When deploying using Extended topology, the same infrastructure will be created as IBM
Cloud topology
[above](#ibm-cloud)
, but AD will not be installed or configured on your Active Directory VSI. Once you setup your
Active Directory VSI the Cloud Connector VSIs will automatically join the domain. See
[Cloud Connector Cloudbase-Init script](#cloud-connector).

### Deploy A Custom Image VSI

You have the option to deploy a VSI to use when creating a custom VDA image for your Citrix Machine
Catalog. Set the `deploy_custom_image_vsi` variable to true if you would like to use this option.
You need to attach a Floating IP to the primary NIC of your Custom Image VSI during post deployment
to enable remote access. A Custom Image VSI security group is created, enabling access to the VSI
using RDP on port 3389.

### Profiles

#### Control Plane VSIs

The `control_plane_profile` variable allows you to specify the VSI profile for your Active Directory
and Cloud Connector VSIs. The default is set to cx2-4x8, but can be overridden with any valid VSI
profile.

#### Custom Image VSI

The `custom_image_vsi_profile` variable allows you to specify the VSI profile for your Custom Image
VSI. The default is set to cx2-4x8, but can be overridden with any valid VSI profile.

See
[VSI profiles](https://cloud.ibm.com/docs/vpc?topic=vpc-profiles&interface=ui).

## Security Groups

As part of your CVADs on VPC deployment, this Terraform module creates the following 4 security
groups:

| Group | Description | Rule(s) |
| --- | --- | --- |
| Control Plane | Active Directory and Cloud Connector VSIs | any |
| VDA | VDA VSIs that you deploy as part of your Citrix Machine Catalog | any |
| Master Image Prep | Master Image Prep VSI deployed during Citrix Machine Catalog creation | none |
| Custom Image (optional) | Custom Image VSI | ingress TCP 3389, egress any |

Security groups will soon be restricted according to Citrix guidelines. See
[Communication ports used by Citrix](https://docs.citrix.com/en-us/tech-zone/build/tech-papers/citrix-communication-ports.html#citrix-cloud).

## Cloudbase-Init Scripts

This Terraform module defines the `userdata` argument on several `resource` blocks in `main.tf`,
providing VSI configuration on initial boot using
[Cloudbase-Init](https://cloudbase.it/cloudbase-init/). See [main.tf](main.tf).

### Active Directory

When using the IBM Cloud topology, this Terraform module will pass the `ad-userdata.ps1` script into
`resource "ibm_is_instance" "active_directory"` along with variables. The `ad-userdata.ps1` script
installs Active Directory, AD Forest, pre-registers Cloud Connectors, and verifies that your AD Domain
Controller is running. Please note, the script registers more Cloud Connectors than deployed to allow for
creating additional Cloud Connectors using this Terraform module. See
[ad-userdata.ps1](scripts/ad-userdata.ps1).

### Cloud Connector

This Terraform module will pass the `connector-userdata.ps1` script into `resource"ibm_is_instance"
"connector"` along with variables. The `connector-userdata.ps1`script installs the Cloud Connector
software and registers the Cloud Connector. The script also joins the Cloud Connector to the AD
domain and installs the IBM Cloud VPC Plugin on the Cloud Connector. See
[connector-userdata.ps1](scripts/connector-userdata.ps1).

### Custom Image

This Terraform module will pass the `custom-image-userdata.ps1` script into `resource
"ibm_is_instance" "custom_image_instance"` along with the ad_ip variable. The
`custom-image-userdata.ps1` script sets the DNS on your Custom Image VSI to the IP of your Active
Directory VSI. See
[custom-image-userdata.ps1](scripts/custom-image-userdata.ps1).

## IBM Cloud VPC Plugin

The Citrix CVADs product uses a plugin architecture to add support for new hypervisors and cloud
providers. Partners and vendors can develop their own plugins which will be recognized by CVADs.
Through a partnership with Citrix, IBM has developed an IBM Cloud VPC plugin that allows CVADs
customers to manage resources on IBM Cloud VPC.

In order to access restricted resources, whether on-prem or in the cloud, CVADs requires the use of
an authorized proxy. This is accomplished with the installation of a Cloud Connector, which
is also used by CVADs plugins that need access to the restricted resources. The IBM Cloud VPC plugin
needs to be installed on all Cloud Connectors on your Citrix Cloud account. See
[Cloud Connector](https://docs.citrix.com/en-us/citrix-cloud/citrix-cloud-resource-locations/citrix-cloud-connector.html).

This Terraform module downloads the `cvad-plugin.msi` from this repository, then installs and
registers the IBM Cloud VPC Plugin from the msi. See
[Cloud Connector Cloudbase-Init script](#cloud-connector).

## Post Deploy

If you provision a Custom Image VSI, you need to attach a Floating IP to the primary NIC of your
Custom Image VSI during post deployment to enable remote access.

When using the Extended topology, this Terraform module will *not* install Active Directory. You are
responsible for installation and configuration of your multisite Active Directory. The Cloud
Connector will attempt to join the AD domain every so often until you setup your Active Directory.

We strongly recommend securing your Active Directory by enabling LDAPS. Follow the Microsoft
guidelines here
[Enabling LDAPS](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority).

We recommend creating Citrix Machine Catalogs totaling no more than 100 VSIs. When creating
catalogs, you can add multiple NICs to the resulting VSIs. Network Security Groups (NSGs) can be
only be assigned to all NICs. That is, you can’t assign different NSGs to different NICs.

To start creating a Citrix Machine Catalog, login to
[Citrix Web Studio](https://xenapp.cloud.com/manage/webstudio)

## Remote Access and Logging

In order to manage your Active Directory or debug VSIs, you will need to reserve and attach a
Floating IP for each VSI NIC you wish to access. See
[Floating IPs for external connectivity](https://cloud.ibm.com/docs/vpc?topic=vpc-about-networking-for-vpc#floating-ip-for-external-connectivity).

The Cloudbase-Init scripts described
[above](#cloudbase-init-scripts)
send log messages to `C:\IBMCVADInstallation.log` on each VSI.
The Cloud Connector VSI also contains a log file from the `cvad-plugin.msi` install at `C:\msi.log`.

## Support

If you have problems or questions when using Citrix Virtual Apps and Desktops, you can contact
Citrix support. Contact
[Citrix support](https://www.citrix.com/support/).

If you have problems or questions when using the underlying IBM Cloud VPC infrastructure, you can
get help by searching for information or by asking questions through one of the forums. You can also
create a case in the
[IBM Cloud console](https://cloud.ibm.com/unifiedsupport/supportcenter).

For information about opening an IBM support ticket, see
[Contacting support](https://cloud.ibm.com/docs/get-support?topic=get-support-using-avatar).

To report bugs or make feature requests regarding this Terraform module, please create an issue in
this repository.

## Releases

Minor and major releases to this repository will occur on Tuesday / Thursday at 6:00pm Central Time.
Hot patches will be released on demand.

## References

- [IBM Cloud provider Terraform getting started](https://cloud.ibm.com/docs/ibm-cloud-provider-for-terraform?topic=ibm-cloud-provider-for-terraform-getting-started)
- [Citrix (CVADs)](https://docs.citrix.com/en-us/tech-zone/learn/tech-briefs/cvads.html)
- [IBM Cloud Schematics](https://cloud.ibm.com/schematics/overview)
- [CVADs Ordering UI](https://cloud.ibm.com/wes-ui/citrix-virtual-app-desktop?featureFlags=vpcBeta)
