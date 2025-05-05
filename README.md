# Azure Honeypot RDP Lab
This project simulates a real-world threat scenario by deploying a cloud-based honeypot in Microsoft Azure. The purpose of this lab was to gain hands-on experience in threat detection and telemetry analysis against exposed cloud resources using enterprise SIEM tools.

I configured a deliberately vulnerable virtual machine (VM) exposed to the public internet to simulate an unprotected endpoint. Security event logs were collected using a monitoring agent, centralized in a log analytics workspace, and integrated Microsoft Sentinel for threat detection and monitoring. Using Kusto Query Language (KQL) and geolocation enrichment, I analyzed failed Remote Desktop Protocol (RDP) login attempts and visualized attacker origins across the globe.

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
  <li>Analyze attacker behavior by identifying patterns</li>
</ul>

<br>

# Process

<h2>1. Set up VM</h2>
<ul>
<li>Created an image of Windows 10 Pro.</li>
<li>Network Security Group in Azure modified to allow all inbound traffic.</li>
<li>Connected remotely to VM to disable the firewall state for Domain, Private, and Public Profiles.</li>
  <blockquote><em><sub>This configuration is intended for lab use only. Exposing a VM with all inbound traffic and no firewall is highly insecure and should never be done in a production environment.</sub></em></blockquote>
<li>Validated external connectivity by initiating an ICMP echo request from local machine to confirm the VM was reachable over the public IP.</li>
</ul>

<br>

<h2>2. Log Collection Configuration</h2>
<br>
<p align="left">
  <img src="https://github.com/user-attachments/assets/a6200d04-4f73-400d-99a0-710434ddd01a" alt="Failed Event Logs in VM" width="600">
    <br><blockquote><sub>RDP failed login attempts are captured in the Windows Event Viewer. These events are forwarded to Azure Log Analytics Workspace, where they can be queried and analyzed in Microsoft Sentinel, to identify the origin of attempted attacks against the honeypot VM.</sub></em></blockquote>
</p>
<br>

<ul>
  <li>Created a <b>Log Analytics Workspace (LAW)</b> to serve as a central log repository for forwarding VM security events.</li>
  <li>Deployed a <b>Sentinel instance</b> and connected it to LAW, to enable access to security logs through Sentinel.</li>
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
  <img src="https://github.com/user-attachments/assets/307b32d1-8abc-4426-a67a-8f04c93b048e" alt="Log Collection Process in Azure" width="600">
</p>

<br>

<h2>3. Querying logs in LAW</h2>
<h4><mark>Before Data Enrichment:</mark></h4>
<p>
  <img src="https://github.com/user-attachments/assets/dd53b5a1-e919-4440-bc0d-8acd4bb05d34" alt="Before Data Enrichment" width="600">
</p>

---

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

---

<h4><mark>After Data Enrichment:</mark></h4>
<p align="left">
  <img src="https://github.com/user-attachments/assets/62a0f7cc-c152-49db-a863-c7e729f7a074" alt="After Data Enrichment" width="600">
</p>
<p align="center"><blockquote>
    <sub>Query output showing failed RDP login attempts with enriched location data from the IP geolocation watchlist.</sub>
</blockquote></p>
<blockquote>
<sub>The geolocation watchlist allowed the KQL query to perform an IP range lookup via the <code>ipv4_lookup()</code> function, correlating attacker IPs with real-world locations.</sub>
</blockquote>

<br>

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

To examine the progression of external threat activity, the honeypot VM was left publicly exposed, allowing for continuous monitoring and collection of failed login attempts and malicious IP activity.

The Sentinel Workbook attack map dynamically updated in real time, correlating incoming threats with geolocation data from the IP watchlist.

<h4 align="center"> Initial Results (0–1 hour)</h4>
<p align="center">
  <img src="https://github.com/user-attachments/assets/fe82220c-de5a-4f33-8e41-73ee8049511a" alt="Initial Attack Map in Sentinel Workbook" width="800">
</p>
    <blockquote>
        <sub>Shortly after deploying the honeypot, the attack map began registering failed login attempts from a limited number of global IPs. Notably, the highest activity originated from Argentina and Poland. This demonstrates how quickly exposed cloud assets are discovered and targeted by automated scripts and scanning bots.</sub>
    </blockquote>

<h4 align="center"> Updated Results (24 hours)</h4>
<p align="center">
  <img src="https://github.com/user-attachments/assets/57d340af-8821-4230-9f59-2b321f0ec245" alt="Updated Attack Map in Sentinel Workbook" width="800">
</p>
    <blockquote>
        <sub>After leaving the VM exposed for a full 24 hours, the attack surface expanded significantly. The map captured failed login attempts from over a dozen additional global regions, with persistent attempts from Europe, South America, and parts of Asia. The increased geographic distribution and volume of events suggest widespread use of automated tools, such as botnets or distributed brute-force frameworks, actively scanning for unsecured RDP endpoints.</sub>
    </blockquote>

---

<h3>Observed Attacker Behaviors</h3>

<ul>
  <li>
    <strong>Repeated login failures from the same IP address</strong><br>
    Many failed attempts originated from a single IP, suggesting the use of automated scripts cycling through passwords.
  </li>
    <br>
  <li>
    <strong>Attempts using common usernames</strong><br>
    Usernames like <code>admin</code>, <code>administrator</code>, <code>user</code>, and <code>employee</code> appeared frequently, indicating attackers were targeting predictable credentials.
  </li>
    <br>
  <li>
    <strong>Clusters of IPs from specific regions</strong><br>
    A large number of attempts came from the same geographic areas—primarily Eastern Europe and Asia—consistent with botnet or proxy-based attacks.
  </li>
    <br>
  <li>
    <strong>High frequency of login attempts in short timeframes</strong><br>
    The rapid succession of failed logins suggested the use of scripts or tools rather than manual brute-force efforts.
  </li>
</ul>

<br>

# Framework Alignment
<h3>NIST Cybersecurity Framework 2.0</h3>
<table>
  <tr>
    <th>Function</th>
    <th>Category & Category Identifier</th>
    <th>Lab Implementation</th>
  </tr>
  <tr>
    <td>Identify</td>
    <td><a href="https://csf.tools/reference/nist-cybersecurity-framework/v2-0/id/id-ra/id-ra-03/">Risk Assessment<br> (ID.RA-03)</a></td>
    <td>Deployed a VM to observe brute-force attacks and record external threats using actual failed RDP login attempts
</td>
  </tr>
  <tr>
    <td>Protect</td>
    <td><a href="https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-ps/pr-ps-04/">Platform Security<br> (PR.PS-04)</a></td>
    <td>Configured VM and monitoring agent to generate and forward security event logs to Log Analytics Workspace for continuous monitoring
</td>
  </tr>
  <tr>
    <td>Detect</td>
    <td><a href="https://csf.tools/reference/nist-cybersecurity-framework/v2-0/de/de-cm/de-cm-01/">Continuous Monitoring<br> (DE.CM-01)</a></td>
    <td>Used Sentinel to monitor failed login events (Event ID 4625), detecting signs of unauthorized access attempts
</td>
  </tr>
  <tr>
    <td>Detect</td>
    <td><a href="https://csf.tools/reference/nist-cybersecurity-framework/v2-0/de/de-ae/de-ae-02/">Adverse Event Analysis (DE.AE-02)</a></td>
    <td>Used Sentinel and KQL to continuously monitor and analyze failed RDP login attempts, identifying suspicious patterns and attacker behavior
</td>
  </tr>
  <tr>
    <td>Detect</td>
    <td><a href="https://csf.tools/reference/nist-cybersecurity-framework/v2-0/de/de-ae/de-ae-03/">Adverse Event Analysis (DE.AE-03)</a></td>
    <td>Correlated security events with external IP data using a custom watchlist, enriching logs with geographic context to pinpoint the origin of malicious login attempts</td>
  </tr>
</table>
<br>

# Takeaways
<ul>
  <li>
    <strong>Exposing services comes with real risk</strong><br>
    Even within hours, the public-facing VM attracted automated brute-force attempts, reinforcing why remote access should always be restricted using NSG rules, account lockout policies, host firewalls, etc.
  </li>
    <br>
  <li>
    <strong>Centralized log collection is critical</strong><br>
    Forwarding logs to Log Analytics Workspace was essential for visibility. Without it, there's no way to detect or investigate suspicious activity across cloud assets.
  </li>
    <br>
  <li>
    <strong>Context improves detection</strong><br>
    Adding geolocation data to attacker IPs made it easier to identify patterns and prioritize potential threats—an approach used in real-world SOC environments to speed up triage.
  </li>
    <br>
  <li>
    <strong>Visualizations enhance situational awareness</strong><br>
    The attack map helped translate raw logs into a clear visual of global attack sources, similar to how dashboards help SOC teams quickly spot anomalies.
  </li>
</ul>
<br>
<p>This lab provided hands-on exposure to how threat actors exploit publicly exposed services, highlighting the importance of minimizing attack surfaces and monitoring for brute-force activity. It also gave me insight on how analysts detect, monitor, and respond using SIEM tools like Microsoft Sentinel.</p>


