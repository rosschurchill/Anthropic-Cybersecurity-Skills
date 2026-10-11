---
name: implementing-data-loss-prevention-with-microsoft-purview
description: 'Implements DLP policies using Microsoft Purview PowerShell cmdlets and the Graph API
  to protect data across Exchange Online, SharePoint, OneDrive, Teams, endpoints, and Power BI, including
  sensitivity labels, custom sensitive information types with regex, endpoint DLP rules, and Activity
  Explorer monitoring. Use when stopping PII/PHI/PCI exfiltration, configuring sensitivity labels, or
  investigating DLP incidents for policy tuning. Do not use for DLP enforced by agents at the endpoint
  - use implementing-endpoint-dlp-controls.'
domain: cybersecurity
subdomain: data-protection
tags:
- DLP
- Microsoft-Purview
- sensitivity-labels
- endpoint-DLP
- data-classification
- compliance
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
- GV.PO-01
mitre_attack:
- T1486
- T1530
- T1537
- T1048
- T1573
---
# Implementing Data Loss Prevention with Microsoft Purview

## When to Use

- Deploying DLP policies to prevent sensitive data (PII, PHI, PCI, intellectual property) from leaving the organization through email, cloud storage, chat, or endpoint file operations
- Configuring sensitivity labels with encryption, content marking, and auto-labeling to classify documents and emails by confidentiality level
- Creating custom sensitive information types with regex patterns to detect organization-specific data formats (employee IDs, project codes, internal account numbers)
- Deploying endpoint DLP to control copy-to-USB, print, upload-to-cloud, and copy-to-clipboard actions for labeled or sensitive content on managed devices
- Investigating DLP incidents through Activity Explorer to analyze policy match events, user activity patterns, and false positive rates for policy tuning

**Do not use** without appropriate Microsoft 365 E5, E5 Compliance, or E5 Information Protection licensing. Do not deploy DLP policies directly to production enforcement mode without a simulation period. Do not configure endpoint DLP without coordinating with the endpoint management team responsible for device onboarding.

## Prerequisites

- Microsoft 365 E5 or E5 Compliance / E5 Information Protection add-on license assigned to target users
- Global Administrator, Compliance Administrator, or Compliance Data Administrator role in the Microsoft Purview portal
- Exchange Online PowerShell module (ExchangeOnlineManagement v3.x) and Security & Compliance PowerShell for policy automation
- Devices onboarded to Microsoft Purview endpoint DLP through Microsoft Intune or Configuration Manager (Windows 10/11 21H2+, macOS 12+)
- Data classification scan completed or content explorer populated to understand existing sensitive data distribution
- Stakeholder agreement on sensitivity label taxonomy (classification levels, encryption requirements, scope)

## Workflow

### Step 1: Design the Sensitivity Label Taxonomy

Define the classification hierarchy that maps to organizational data handling requirements:

- **Establish label tiers**: Create a label hierarchy reflecting data sensitivity levels. A standard enterprise taxonomy includes:
  ```
  Public           -> No protection, external sharing allowed
  General          -> No encryption, internal watermark "GENERAL"
  Confidential     -> Encryption (all employees), header/footer marking
    ├─ Confidential - All Employees
    ├─ Confidential - Finance
    └─ Confidential - HR
  Highly Confidential -> Encryption (specific users/groups), watermark, no forwarding
    ├─ Highly Confidential - Project X
    └─ Highly Confidential - Board Only
  ```
- **Define protection settings per label**: For each label, configure encryption scope (all employees, specific groups, or custom permissions), content marking (headers, footers, watermarks), and auto-labeling conditions:
  ```powershell
  # Connect to Security & Compliance PowerShell
  Connect-IPPSSession -UserPrincipalName admin@contoso.com

  # Create parent label
  New-Label -DisplayName "Confidential" `
    -Name "Confidential" `
    -Tooltip "Business data that could cause damage if disclosed to unauthorized parties" `
    -Comment "Apply to internal business documents, financial reports, and customer data"

  # Create sub-label with encryption
  New-Label -DisplayName "Confidential - Finance" `
    -Name "Confidential-Finance" `
    -ParentId (Get-Label -Identity "Confidential").Guid `
    -Tooltip "Financial data restricted to Finance department" `
    -EncryptionEnabled $true `
    -EncryptionProtectionType "Template" `
    -EncryptionRightsDefinitions "finance-group@contoso.com:VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,OBJMODEL" `
    -ContentType "File, Email"
  ```
- **Configure content marking**: Apply visual indicators that persist with the document:
  ```powershell
  Set-Label -Identity "Confidential-Finance" `
    -HeaderEnabled $true `
    -HeaderText "CONFIDENTIAL - FINANCE" `
    -HeaderFontSize 10 `
    -HeaderFontColor "#FF0000" `
    -HeaderAlignment "Center" `
    -FooterEnabled $true `
    -FooterText "This document contains confidential financial information" `
    -WatermarkEnabled $true `
    -WatermarkText "CONFIDENTIAL" `
    -WatermarkFontSize 36
  ```
- **Publish labels via label policy**: Labels must be published to users through a label policy that defines which users see the labels and whether a default label or mandatory labeling is enforced:
  ```powershell
  New-LabelPolicy -Name "Corporate Label Policy" `
    -Labels "Public","General","Confidential","Confidential-Finance",
            "Confidential-HR","HighlyConfidential","HighlyConfidential-ProjectX" `
    -ExchangeLocation "All" `
    -ModernGroupLocation "All" `
    -Comment "Standard corporate sensitivity labels"

  # Require justification for label downgrade
  Set-LabelPolicy -Identity "Corporate Label Policy" `
    -AdvancedSettings @{RequireDowngradeJustification="True";
                        DefaultLabelId="General"}
  ```

### Step 2: Create DLP Policies with Sensitive Information Types

Configure DLP policies that detect and protect sensitive content across Microsoft 365 workloads:

- **Create a DLP policy using built-in sensitive information types**: Microsoft Purview includes 300+ built-in SITs for credit card numbers, Social Security numbers, passport numbers, and health records. Create a policy targeting financial data:
  ```powershell
  # Create DLP policy scoped to Exchange, SharePoint, OneDrive
  New-DlpCompliancePolicy -Name "Financial Data Protection" `
    -ExchangeLocation "All" `
    -SharePointLocation "All" `
    -OneDriveLocation "All" `
    -TeamsLocation "All" `
    -Mode "TestWithNotifications" `
    -Comment "Protects credit card numbers, bank account numbers, and financial identifiers"

  # Create rule for high-volume credit card detection
  New-DlpComplianceRule -Name "Block Bulk Credit Card Sharing" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 5;
      MinConfidence = 85
    } `
    -BlockAccess $true `
    -BlockAccessScope "All" `
    -NotifyUser "SiteAdmin","LastModifier" `
    -NotifyUserType "NotSet" `
    -GenerateIncidentReport "SiteAdmin" `
    -IncidentReportContent "All" `
    -ReportSeverityLevel "High"

  # Create rule for low-volume with user override
  New-DlpComplianceRule -Name "Warn on Credit Card Sharing" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 1;
      MaxCount = 4;
      MinConfidence = 75
    } `
    -NotifyUser "LastModifier" `
    -NotifyUserType "NotSet" `
    -GenerateAlert "Low" `
    -NotifyOverride "WithJustification"
  ```
- **Create custom sensitive information types with regex**: Define organization-specific patterns for data that built-in SITs do not cover:
  ```powershell
  # Create custom SIT for employee ID format (EMP-XXXXXX)
  $rulePackXml = @"
  <RulePackage xmlns="http://schemas.microsoft.com/office/2011/mce">
    <RulePack id="$(New-Guid)">
      <Version major="1" minor="0" build="0" revision="0"/>
      <Publisher id="$(New-Guid)"/>
    </RulePack>
    <Rules>
      <Entity id="$(New-Guid)" patternsProximity="300"
              recommendedConfidence="85">
        <Pattern confidenceLevel="85">
          <IdMatch idRef="EmployeeId_Regex"/>
        </Pattern>
        <Pattern confidenceLevel="95">
          <IdMatch idRef="EmployeeId_Regex"/>
          <Match idRef="EmployeeId_Keyword"/>
        </Pattern>
      </Entity>
      <Regex id="EmployeeId_Regex">EMP-[0-9]{6}</Regex>
      <Keyword id="EmployeeId_Keyword">
        <Group matchStyle="word">
          <Term>employee</Term>
          <Term>employee id</Term>
          <Term>emp id</Term>
          <Term>staff number</Term>
        </Group>
      </Keyword>
      <LocalizedStrings>
        <Resource idRef="EmployeeId_Regex">
          <Name default="true" langcode="en-us">Contoso Employee ID</Name>
          <Description default="true" langcode="en-us">
            Detects Contoso employee IDs in format EMP-XXXXXX
          </Description>
        </Resource>
      </LocalizedStrings>
    </Rules>
  </RulePackage>
  "@

  # Save and import the rule package
  $rulePackXml | Out-File -FilePath "EmployeeID_SIT.xml" -Encoding utf8
  New-DlpSensitiveInformationTypeRulePackage -FileData (
    [System.IO.File]::ReadAllBytes("EmployeeID_SIT.xml")
  )
  ```
- **Use sensitivity labels as DLP conditions**: Create policies that apply different restrictions based on the label applied to the content:
  ```powershell
  New-DlpCompliancePolicy -Name "Highly Confidential Sharing Control" `
    -ExchangeLocation "All" `
    -SharePointLocation "All" `
    -OneDriveLocation "All" `
    -Mode "Enable"

  New-DlpComplianceRule -Name "Block External Sharing of HC Content" `
    -Policy "Highly Confidential Sharing Control" `
    -ContentContainsSensitiveInformation $null `
    -ContentPropertyContainsWords "MSIP_Label_$(
      (Get-Label -Identity 'HighlyConfidential').Guid
    )_Enabled=True" `
    -BlockAccess $true `
    -BlockAccessScope "NotInOrganization" `
    -NotifyUser "LastModifier" `
    -GenerateIncidentReport "SiteAdmin" `
    -ReportSeverityLevel "High"
  ```

### Step 3: Deploy Endpoint DLP Rules

Extend DLP protection to managed Windows and macOS endpoints to control file operations:

- **Verify device onboarding**: Confirm devices are onboarded to Microsoft Purview endpoint DLP through Microsoft Intune or the local onboarding script:
  ```powershell
  # Check onboarding status via Intune Graph API
  # GET https://graph.microsoft.com/beta/deviceManagement/managedDevices
  # Filter for complianceState and dlpOnboardingStatus

  # Local verification on Windows endpoint
  # Check registry key:
  # HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status
  # OnboardingState should be 1
  ```
- **Configure endpoint DLP settings**: Define global settings that control which applications and file types endpoint DLP monitors:
  ```powershell
  # Configure unallowed apps (browsers, cloud sync clients)
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -UnallowedApps @(
      @{Name="Chrome"; Executable="chrome.exe"},
      @{Name="Firefox"; Executable="firefox.exe"},
      @{Name="PersonalDropbox"; Executable="Dropbox.exe"}
    )

  # Configure unallowed Bluetooth apps
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -UnallowedBluetoothApps @(
      @{Name="BluetoothFileTransfer"; Executable="fsquirt.exe"}
    )

  # Configure network share groups
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -NetworkShareGroups @(
      @{
        Name = "Authorized Shares";
        NetworkPaths = @("\\server01\approved$", "\\server02\secure$")
      }
    )

  # Configure sensitive service domains (allowed cloud destinations)
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -SensitiveServiceDomains @(
      @{
        Name = "Approved Cloud Storage";
        Domains = @("sharepoint.com", "onedrive.com")
        MatchType = "Allow"
      },
      @{
        Name = "Blocked Cloud Storage";
        Domains = @("dropbox.com", "box.com", "drive.google.com")
        MatchType = "Block"
      }
    )
  ```
- **Create endpoint-specific DLP rules**: Define rules that control copy-to-USB, print, upload, and clipboard operations for sensitive content:
  ```powershell
  # Add endpoint location to existing policy
  Set-DlpCompliancePolicy -Identity "Financial Data Protection" `
    -EndpointDlpLocation "All"

  # Create endpoint-specific rule
  New-DlpComplianceRule -Name "Block USB Copy of Financial Data" `
    -Policy "Financial Data Protection" `
    -ContentContainsSensitiveInformation @{
      Name = "Credit Card Number";
      MinCount = 1;
      MinConfidence = 85
    } `
    -EndpointDlpRestrictions @(
      @{Setting="CopyToRemovableMedia"; Value="Block"},
      @{Setting="CopyToNetworkShare"; Value="Audit"},
      @{Setting="CopyToClipboard"; Value="Block"},
      @{Setting="Print"; Value="Warn"},
      @{Setting="UploadToCloudService"; Value="Block"},
      @{Setting="UnallowedBluetoothApp"; Value="Block"}
    ) `
    -NotifyUser "LastModifier" `
    -GenerateIncidentReport "SiteAdmin"
  ```
- **Configure printer groups and USB device exceptions**: Allow specific printers and approved USB devices while blocking unauthorized removable media:
  ```powershell
  # Define authorized USB devices by vendor/product ID
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -RemovableMediaGroups @(
      @{
        Name = "Approved Encrypted USBs";
        Devices = @(
          @{VendorId="0781"; ProductId="5583"; SerialNumber="*"}  # SanDisk Extreme
        )
      }
    )

  # Define authorized printers
  Set-PolicyConfig -EndpointDlpGlobalSettings `
    -PrinterGroups @(
      @{
        Name = "Corporate Printers";
        Printers = @(
          @{PrinterName="*Corporate*"; PrinterType="Corporate"},
          @{PrinterName="PDF Printer"; PrinterType="Print to PDF"}
        )
      }
    )
  ```

### Step 4: Configure Auto-Labeling Policies

Deploy service-side auto-labeling to automatically classify content at rest and in transit:

- **Create auto-labeling policy for email**: Automatically label inbound and outbound emails containing sensitive information:
  ```powershell
  New-AutoSensitivityLabelPolicy -Name "Auto-Label Financial Emails" `
    -ExchangeLocation "All" `
    -Mode "TestWithNotifications" `
    -Comment "Automatically labels emails containing financial data as Confidential-Finance"

  New-AutoSensitivityLabelRule -Name "Financial SIT Match" `
    -Policy "Auto-Label Financial Emails" `
    -SensitiveInformationType @{
      Name = "Credit Card Number";
      MinCount = 1;
      MinConfidence = 85
    },@{
      Name = "U.S. Bank Account Number";
      MinCount = 1;
      MinConfidence = 85
    } `
    -WorkloadDomain "Exchange" `
    -ApplySensitivityLabel "Confidential-Finance"
  ```
- **Create auto-labeling policy for SharePoint and OneDrive**: Label existing files at rest that match sensitive information patterns:
  ```powershell
  New-AutoSensitivityLabelPolicy -Name "Auto-Label SP Financial Docs" `
    -SharePointLocation "https://contoso.sharepoint.com/sites/finance" `
    -OneDriveLocation "All" `
    -Mode "TestWithNotifications"

  New-AutoSensitivityLabelRule -Name "Financial Docs SIT Match" `
    -Policy "Auto-Label SP Financial Docs" `
    -SensitiveInformationType @{
      Name = "Credit Card Number"; MinCount = 1; MinConfidence = 85
    } `
    -WorkloadDomain "SharePoint" `
    -ApplySensitivityLabel "Confidential-Finance"
  ```
- **Simulate before enforcing**: Always run auto-labeling in simulation mode first. Review the simulation results in the Microsoft Purview portal under Information Protection > Auto-labeling. The simulation shows estimated matches per location and sample content matches for validation. Only switch to enforcement mode after confirming accuracy:
  ```powershell
  # Check simulation results
  Get-AutoSensitivityLabelPolicy -Identity "Auto-Label Financial Emails" |
    Select-Object Name, Mode, WhenCreated, DistributionStatus

  # Switch to enforcement after validation
  Set-AutoSensitivityLabelPolicy -Identity "Auto-Label Financial Emails" `
    -Mode "Enable"
  ```

### Step 5: Monitor with Activity Explorer and Manage DLP Alerts

Use Activity Explorer and the DLP alerts dashboard to monitor policy effectiveness and investigate incidents:

- **Access Activity Explorer**: Navigate to Microsoft Purview portal > Data Classification > Activity Explorer. Filter by activity type "DLPRuleMatch" to see all DLP policy matches. Key columns include:
  - Activity timestamp and user principal name
  - Sensitive information type matched and confidence level
  - Policy and rule name that triggered
  - Action taken (Audit, Block, Warn with Override)
  - Location (Exchange, SharePoint, OneDrive, Endpoint)
  - File name and site URL
- **Analyze false positive rates**: Export Activity Explorer data filtered by "Override" actions with justification text to identify rules that users frequently override. A high override rate (>20%) indicates the rule may be too aggressive or matching non-sensitive content:
  ```
  Activity Explorer filter:
    Activity type = DLPRuleMatch
    Action = Override
    Date range = Last 30 days
    Policy name = Financial Data Protection

  Export to CSV for analysis of override justifications and
  affected file types to refine SIT confidence thresholds.
  ```
- **Configure DLP alerts**: Set up alert policies in Microsoft Purview > Data Loss Prevention > Alerts to receive notifications for high-severity matches:
  ```powershell
  # DLP alerts are configured within the DLP rule itself
  # Adjust alert volume thresholds on high-traffic rules
  Set-DlpComplianceRule -Identity "Block Bulk Credit Card Sharing" `
    -GenerateAlert "High" `
    -AlertProperties @{
      AggregationType = "SimpleAggregation";
      Threshold = 1;
      TimeWindow = "00:05:00"
    }
  ```
- **Query DLP events via Microsoft Graph API**: Programmatically retrieve DLP alerts and policy match details for integration with SIEM or custom dashboards:
  ```python
  import requests

  # Authenticate with Microsoft Graph (client credentials flow)
  token_url = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
  token_response = requests.post(token_url, data={
      "client_id": client_id,
      "client_secret": client_secret,
      "scope": "https://graph.microsoft.com/.default",
      "grant_type": "client_credentials"
  })
  access_token = token_response.json()["access_token"]

  headers = {"Authorization": f"Bearer {access_token}"}

  # Retrieve DLP alerts
  alerts_url = "https://graph.microsoft.com/v1.0/security/alerts_v2"
  params = {
      "$filter": "serviceSource eq 'microsoftDataLossPrevention'",
      "$top": 50,
      "$orderby": "createdDateTime desc"
  }
  response = requests.get(alerts_url, headers=headers, params=params)
  alerts = response.json().get("value", [])

  for alert in alerts:
      print(f"Alert: {alert['title']}")
      print(f"  Severity: {alert['severity']}")
      print(f"  Status: {alert['status']}")
      print(f"  Created: {alert['createdDateTime']}")
      print(f"  User: {alert.get('userStates', [{}])[0].get('userPrincipalName', 'N/A')}")
  ```
- **Retrieve DLP policy match details for compliance reporting**: Use the unified audit log to extract granular DLP match data including the matched content, SIT type, and confidence level:
  ```powershell
  # Search unified audit log for DLP policy matches
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) `
    -EndDate (Get-Date) `
    -RecordType "DLP" `
    -ResultSize 1000 |
    Select-Object CreationDate, UserIds, Operations,
      @{N='PolicyName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.PolicyName}},
      @{N='RuleName';E={($_.AuditData | ConvertFrom-Json).PolicyDetails.Rules.RuleName}},
      @{N='SITMatched';E={($_.AuditData | ConvertFrom-Json).SensitiveInfoDetections.SensitiveType}} |
    Export-Csv -Path "DLP_Audit_Report.csv" -NoTypeInformation
  ```

## Reference Material

See [references/reference-material.md](references/reference-material.md) for the Key Concepts glossary, the Tools & Systems list, worked deployment scenarios, and the full DLP deployment report template.
