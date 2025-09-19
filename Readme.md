# Analyzing DHCP Log Files Using Splunk SIEM

## Introduction
DHCP (Dynamic Host Configuration Protocol) log files contain valuable information about IP address assignments, lease durations, client requests, and server responses. Analyzing DHCP logs using Splunk SIEM enables network administrators to monitor IP address usage, detect anomalies, and troubleshoot network issues effectively.

## Project Overview
In this project, we will upload sample DHCP log files to Splunk SIEM and perform various analyses to gain insights into IP address assignment within the network.

## Prerequisites
Before starting the project, ensure the following:
- Splunk instance is installed and configured.
- DHCP log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample DHCP Log Files to Splunk SIEM

### 1. Prepare Sample DHCP Log Files
- Obtain sample [DHCP log files](https://www.secrepo.com/maccdc2012/dhcp.log.gz) in a suitable format.
- Ensure the log files contain relevant DHCP events, including timestamps, IP address assignments, lease durations, client identifiers, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample DHCP log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for DHCP logs (e.g., `dhcpd` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample DHCP log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample DHCP log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded DHCP events are visible.

## Steps to Analyze DHCP Log Files in Splunk SIEM


### 1. 1. Search for DHCP Events
- Open Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve DHCP events:
```
source="dhcp.log" host="SoujanyaPC" sourcetype="dhcp"
```

### 2. Extract Relevant Fields
- Identify key fields in DHCP logs such as timestamps, IP addresses, lease durations, client identifiers, etc.

```
source="dhcp.log" host="SoujanyaPC" sourcetype="dhcp" 
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| eval readable_time = strftime(timestamp, "%Y-%m-%d %H:%M:%S")
| table readable_time, session_id, src_ip, src_port, dst_ip, dst_port, mac_address, assigned_ip, lease_duration, transaction_id

```
[Dhcp_Field_Extraction](Dhcp_Field_Extraction.png)
### 3. Analyze Email Traffic Patterns
- Determine the distribution of IP address assignments:
```
source="dhcp.log" host="SoujanyaPC" sourcetype="dhcp" 
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| stats count as assignment_count by assigned_ip
| sort - assignment_count
```
[Dhcp_Ip_Assignment](Dhcp_Ip_Assignment.png)
### 4. Detect Anomalies
- Look for unusual patterns in IP address assignments:
```
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| timechart span=1h count by _time
```

- Analyze DHCP requests from unauthorized or unknown clients:
```
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| search NOT client_identifier="authorized_identifier"
```

### 5. Monitor IP Address Usage
- Monitor IP address usage over time:
```
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| timechart span=1h count by leased_ip
```
- Identify IP addresses with multiple lease renewals or changes:
```
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| stats count by leased_ip, lease_renewal
| where count > 1 AND lease_renewal="true"
```
- Analyze DHCP traffic patterns and deviations from normal behavior:
```
| rex "^(?<timestamp>\d+\.\d+)\s+(?<session_id>\S+)\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<src_port>\d+)\s+(?<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<dst_port>\d+)\s+(?<mac_address>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<assigned_ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<lease_duration>\d+\.\d+)\s+(?<transaction_id>\d+)"
| timechart span=1d count by leased_ip
```



## Conclusion
Analyzing DHCP log files using Splunk SIEM provides valuable insights into IP address assignment within a network. By monitoring DHCP events, detecting anomalies, and correlating with other logs, organizations can enhance their network management capabilities, troubleshoot issues, and improve overall network security.

