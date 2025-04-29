# Azure Honeypot RDP Lab
This project simulates a real-world cybersecurity environment by deploying a cloud-based honeypot in Microsoft Azure. The purpose of this lab was to gain hands-on experience in detecting, analyzing, and visualizing attack patterns against exposed cloud resources using enterprise-grade SIEM tools.

I configured an intentionally vulnerable virtual machine (VM) exposed to the public internet, centralized security event logging with Azure Log Analytics, and integrated Microsoft Sentinel for threat detection and monitoring. Using Kusto Query Language (KQL) and geolocation enrichment, I analyzed failed Remote Desktop Protocol (RDP) login attempts and visualized attacker origins across the globe.

<p align="center">
    <img src="Azure-Honeypot-Lab-Diagram.png" alt="Azure Honeypot Lab Architecture" length="500" width="800" height="600">
</p>




</div>

# Objectives
<ul>
  <li>Deploy a public-facing VM in Azure to simulate a honeypot</li>
  <li>Configure Log Analytics Workspace (LAW) to centralize security event collection</li>
  <li>Forward security logs from the VM and integrate them with Sentinel for real-time monitoring</li>
  <li>Query failed login attempts using KQL and enrich the data with geolocation information</li>
  <li>Create an attack map to track real-time hacker activity across the globe</li>
</ul>

# Key Steps

<h3>1. Set up VM</h3>
<ul>
<li>Created an image of Windows 10 Pro</li>
<li>Network Security Group in Azure modified to allow all inbound traffic</li>
<li>Connected remotely to VM to disable the firewall state for Domain, Private, and Public Profiles</li>
<br>
  <blockquote><em><sub>This configuration is intended for lab use only. Exposing a VM with all inbound traffic and no firewall is highly insecure and should never be done in a production environment.</sub></em></blockquote>
</ul>

<br>

---

<h3>2. Log Collection Configuration</h3>

<p align="left">
  <img src="Failed-Event-Logs-VM.png" alt="Failed Event Logs in VM" length="200" width="700" height="400">
    <br><blockquote><sub>RDP failed login attempts are captured in the Windows Event Viewer. These events are forwarded to Azure Log Analytics Workspace, where they can be queried and analyzed in Microsoft Sentinel to identify the origin of attempted attacks against the honeypot VM.</sub></em></blockquote>
</p>
<br>

<ul>
  <li><strong>Created a Log Analytics Workspace (LAW)</strong> to serve as a central log repository for forwarding VM security events.</li>
  <li><strong>Deployed Microsoft Sentinel</strong> and connected it to the LAW to enable centralized security event monitoring.</li>
  <li>
    <strong>Installed and configured Windows Security Events</strong> in Sentinel:
    <ul>
      <li>
          Linked the VM to the LAW using <em>Windows Security Events via Azure Monitoring Agent (AMA)</em>                   connector.
      </li>
      <li>
        This connector creates a <em>Data Collection Rule (DCR)</em>, to automatically forward security event logs         from the VM into LAW, enabling Sentinel to ingest and query the data in real time.
      </li>
    </ul>
  </li>
</ul>

<p align="center">
  <img src="LogCollectionConfig.png" alt="Log Collection Process in Azure" length="200" width="600" height="400">
</p>

<br>

---

<h3>3. Querying logs in LAW</h3>

<ul>
  <li>Queried failed login attempts <code>Event ID == 4625</code> using Kusto Query Language (KQL)</li>
    <pre><code>
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
WindowsEvents
    | project TimeGenerated, Computer, AttackerIp = IpAddress, cityname, countryname, longitude, latitude
</code></pre>
  <li>Enriched logs using a custom IP geolocation watchlist
     <br>
      <blockquote><sub><em>The geolocation dataset (<code>geoip-summarized.csv</code>) was provided as part of the lab exercise. In production environments, IP enrichment data is typically pulled dynamically from live threat intelligence sources or maintained automatically by a security team.</em></sub></blockquote>
</li>
  <li>Mapped attacker IPs to geographic locations for visualization</li>
</ul>

<p align="center">
  <img src="Failed-Event-Logs-KQL.png" alt="Log Collection Process in Azure" length="300" width="800" height="400">
</p>






