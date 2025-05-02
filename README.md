# Azure Honeypot RDP Lab
This project simulates a real-world cybersecurity environment by deploying a cloud-based honeypot in Microsoft Azure. The purpose of this lab was to gain hands-on experience in detecting, analyzing, and visualizing attack patterns against exposed cloud resources using enterprise-grade SIEM tools.

I configured an intentionally vulnerable virtual machine (VM) exposed to the public internet, centralized security event logging with Azure Log Analytics, and integrated Microsoft Sentinel for threat detection and monitoring. Using Kusto Query Language (KQL) and geolocation enrichment, I analyzed failed Remote Desktop Protocol (RDP) login attempts and visualized attacker origins across the globe.

<p align="center">
    <img src="https://github.com/user-attachments/assets/9907cae3-b29e-4503-b867-dd2a2c1a0606" alt="Azure Honeypot Lab Architecture" width="850">
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

<br>

# Process

<h3>1. Set up VM</h3>
<ul>
<li>Created an image of Windows 10 Pro</li>
<li>Network Security Group in Azure modified to allow all inbound traffic</li>
<li>Connected remotely to VM to disable the firewall state for Domain, Private, and Public Profiles</li>
  <blockquote><em><sub>This configuration is intended for lab use only. Exposing a VM with all inbound traffic and no firewall is highly insecure and should never be done in a production environment.</sub></em></blockquote>
<li>Pinged VM from local computer to make sure it's reachable over the internet</li>
</ul>

---

<h3>2. Log Collection Configuration</h3>

<p align="left">
  <img src="https://github.com/user-attachments/assets/a6200d04-4f73-400d-99a0-710434ddd01a" alt="Failed Event Logs in VM" width="700">
    <br><blockquote><sub>RDP failed login attempts are captured in the Windows Event Viewer. These events are forwarded to Azure Log Analytics Workspace, where they can be queried and analyzed in Microsoft Sentinel, to identify the origin of attempted attacks against the honeypot VM.</sub></em></blockquote>
</p>
<br>

<ul>
  <li>Created a <b>Log Analytics Workspace (LAW)</b> to serve as a central log repository for forwarding VM security events.</li>
  <li>Deployed a <b>Sentinel instance</b> and connected it to LAW, to enable centralized access to security logs through the SIEM platform.</li>
  <li>Installed and configured <b>Windows Security Events</b>:
    <ul>
      <li>
          Installed <b>Azure Monitoring Agent (AMA)</b> connector on the VM to collect event logs.
      </li>
<ul>
      <li>
        Created a <b>Data Collection Rule (DCR)</b>, to automatically forward security event logs from the VM into workspace, enabling Sentinel to ingest and query the data in real time. 
      </li>
</ul>
    </ul>
  </li>
<br>
<details>
<summary><sub><em>What is Azure Monitor Agent (AMA)?</em></sub></summary><br>

<sub>It collects logs and performance data from VMs running in Azure, on-premises, or in other cloud environments. It sends data to **Azure Monitor**, where services like **Microsoft Sentinel** and **Microsoft Defender for Cloud** can use it for analysis.</sub>

<sub>AMA collects all data by using **Data Collection Rules (DCRs)**, which define:</sub>
<br>
    <sub>- What data is collected</sub><br>
    <sub>- How the data is filtered, transformed, or aggregated</sub><br>
    <sub>- Where the data is sent (e.g., Log Analytics Workspace)</sub>
</details>
</ul>


<p align="center">
  <img src="LogCollectionConfig.png" alt="Log Collection Process in Azure" length="200" width="600" height="400">
</p>

---

<h3>3. Querying logs in LAW</h3>
<h4>Before Data Enrichment:</h4>
<p>
  <img src="https://github.com/user-attachments/assets/dd53b5a1-e919-4440-bc0d-8acd4bb05d34" alt="Before Data Enrichment" width="600">
</p>

<h4>To understand where attacks are coming from:</h4>
<ul>
    <li>Uploaded <code>geoip-summarized.csv</code> file as a Sentinel watchlist to provide geolocation data for public IP address blocks.
     <br>
      <blockquote><sub><em><code>geoip-summarized.csv</code> is a geolocation dataset containing IP ranges and location data to enrich attacker IPs with geographic context. In production environments, this investigative technique is typically automated through live threat intelligence feeds or maintained internally by a security team.</em></sub></blockquote>
<details>
<summary><sub><em>What is a watchlist?</em></sub></summary><br>

<sub>A Microsoft Sentinel watchlist lets you bring in data from external sources (like IP lists or threat intel) to correlate against the events in your Sentinel environment. Once added, watchlists can be used in queries, threat hunting, workbooks, and response playbooks.</sub>
</details>
<br>
<li>Queried failed login attempts <code>Event ID == 4625</code> using <b>Kusto Query Language (KQL)</b>, joining raw event logs with the geolocation watchlist to attach physical location details to     attacker IPs.
  </li>
</ul>

<pre><code>
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
    | project Computer, AttackerIP = IpAddress, cityname, countryname, latitude, longitude
</code></pre>
</ul>

<h4>After Data Enrichment:</h4>
<p align="left">
  <img src="https://github.com/user-attachments/assets/62a0f7cc-c152-49db-a863-c7e729f7a074" alt="After Data Enrichment" width="700">
</p>
<p align="center"><blockquote>
    <sub>Query output showing failed RDP login attempts with enriched location data from the IP geolocation watchlist.</sub>
</blockquote></p>
<blockquote>
<sub>The geolocation watchlist allowed the KQL query to perform an IP range lookup via the <code>ipv4_lookup()</code> function, correlating attacker IPs with real-world locations.</sub>
</blockquote>

---
<h2>4. Attack Map Creation </h2>

<ul>
    <li>Used JSON to add a query in Sentinel Workbook to generate a global heatmap.</li>
    <blockquote>
    <sub><em>The <code>map.json</code> file includes a KQL query that runs when you add it to a Sentinel Workbook. The query pulls failed login events, enriches them with geolocation data from the watchlist, and sends the results to the map. It also defines how the map looks with attributes like bubble size, colors, and labels showing city and country names.</sub></em>
    </blockquote>
</ul>
<br>

<ul>
    <li>The map visualizes attacker IPs by correlating enriched geolocation data (latitude/longitude) with failed login counts, highlighting regions with high attack activity.</li>
</ul>
    
---

<h3>Attack Map Activity Over Time</h3>

To monitor how external attacks build up over time, I kept the honeypot VM exposed to the internet for several hours.

The Sentinel Workbook attack map continuously updated as failed RDP login attempts were recorded and matched with geographic data from the watchlist.

<h4 align="center"> Initial Results (0–1 hour)</h4>
<p align="center">
  <img src="Initial-Attack-Map.png" alt="Initial Attack Map in Sentinel Workbook" width="700">
</p>
    <blockquote>
        <sub>Shortly after deploying the honeypot, a few failed RDP login attempts were detected, mostly from a limited number of regions. This confirms that exposed systems are quickly found by automated scanners.</sub>
    </blockquote>

<h4 align="center"> Updated Results (10 hours)</h4>
<p align="center">
  <img src="Attack-Map-Updated.png" alt="Updated Attack Map in Sentinel Workbook" width="700">
</p>
    <blockquote>
        <sub>After leaving the honeypot exposed for about 10 hours, the number and spread of failed RDP login attempts increased significantly — showing attacks from multiple countries and networks.</sub>
    </blockquote>

<br>

# Takeaways

<ul>
  <li><strong>Exposed services are high-risk assets</strong><br>
    Public-facing RDP is a well-known attack vector. Even during a short exposure window, the VM was targeted by automated scanning tools. This highlights the importance of hardening access using NSG rules, account lockout policies, host-based firewalls, and secure access solutions like Azure Bastion.
  </li>
  <br>
  <li><strong>Log telemetry is foundational to detection</strong><br>
    Without forwarding security logs to a centralized workspace, detection and investigation would not be possible. Without this step, a security analyst/team has no line of sight into endpoint activity or brute-force behavior.
  </li>
  <br>
  <li><strong>Data context accelerates triage</strong><br>
    Matching attacker IPs with geographic location made it easier to understand threat patterns and prioritize analysis. In a live SOC, this kind of enrichment helps filter noise, spot patterns, and respond with appropriate urgency.
  </li>
  <br>
  <li><strong>Visual dashboards support situational awareness</strong><br>
    The attack map served as a real-time view into where attacks were originating. In enterprise settings, similar dashboards help analysts spot anomalies and detect coordinated attacks faster.
  </li>
  <br>
  <li><strong>KQL enables efficient investigation</strong><br>
    Writing KQL queries to identify failed RDP logins and correlate them with geolocation data mirrors how detection and response teams perform root-cause analysis and monitor threat activity in Microsoft-based environments.
  </li>
</ul>

<br>

<p>This project provided a realistic view of how exposed cloud resources are targeted and monitored in a SOC environment. It emphasized the importance of log visibility, contextual analysis, and actionable insights using SIEM tools like Microsoft Sentinel.</p>





