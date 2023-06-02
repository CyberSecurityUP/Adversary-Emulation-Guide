# Adversary-Emulation-Guide

## What is

### C2

- Command and Control (C2) is the influence an attacker has over a compromised computer system that they control.

### C2 Tiers

- Interactive

	- Used for general commands, enumeration, scanning, data exfiltration, etc.
	- This tier has the most interaction and is at the greatest risk of exposure.
	- Plan to lose access from communication failure, agent failure, or Blue Team actions.
	- Run enough interactive sessions to maintain access. Although interactive, this doesn’t mean blasting the client with packets. Use good judgment to minimize interaction just enough to perform an action.

- Short haul

	- Used as a backup to reestablish interactive sessions.
	- Use covert communications that blend in with the target.
	- Slow callback times. Callback times in the 1–24 hr. range are common.

- Long haul

	- The same as Short Haul but even lower and slower.
	- Slow callback times. Callback times of 24+ hours are common.

### CONTROL CELL

- Serves as referee between Red Team activities and defender responses during an engagement. Controls the engagement environment/network. Monitors adherence to the ROE. Coordinates activities required to achieve engagement goals. Correlates Red Team activities with defensive actions. Ensures the engagement is conducted without bias to either side.

### Get In

- Gain access to a network. The Red Team must have access to their target. Access can be through a legitimate compromise or access is directly granted as part of an assumed breach scenario, such as an insider threat scenario

### Stay In

- Establish persistence or a permanent presence. Red Team engagements are typically longer than other types of tests. A Red Team usually establishes persistence or a permanent presence to survive the duration of the engagement.

### Act

- Phase where a Red Team performs operational impacts against a target.

### IOC

- Indicators of Compromise (IOCs) are artifacts that identify or describe threat actions.

### OPSEC

- OPSEC or Operational Security is a process that identifies critical information to determine if friendly actions can be observed by enemy intelligence, determines if information obtained by adversaries could be interpreted to be useful to them, and then executes selected measures that eliminate or reduce adversary exploitation of friendly critical information. In terms of Red Teaming, it is understanding what actions Blue can observe and minimizes exposure.

### RED CELL

- The term red cell is borrowed from the military. It is commonly associated with a group that plays OPFOR (opposing force) during red vs. blue exercises. A red cell is the components that make up the offensive portion of a red team engagement that simulates the strategic and tactical responses of a given target. The red cell is typically comprised of red team leads and operators and is commonly referred to as Red Team instead of Red Cell.

### RULES OF ENGAGEMENT (ROE)

- The Rules of Engagement establish the responsibilities, relationships, and guidelines among the Red Team, the customer, the system owner, and any stakeholders required for engagement execution.

### TRADECRAFT

- Tradecraft is the techniques and procedures of espionage. Tradecraft is typically associated with the intelligence community. TTPs and Tradecraft are used interchangeably in this course.

## What is necessary?

### Adversary Emulation Plan

- Adversary Emulation, also known as Red Team Operations, is a proactive cybersecurity approach where an organization simulates real-world attack scenarios to identify vulnerabilities in their systems, processes, and defenses. The goal of adversary emulation is to assess an organization's security posture by adopting the mindset and tactics of a potential attacker.

	- Scope Definition: Define the objectives, constraints, and boundaries of the emulation exercise. Determine the systems, networks, or specific assets to be targeted and identify the rules of engagement.
	- Reconnaissance: Conduct preliminary information gathering to understand the target environment. This may involve gathering publicly available data, analyzing open-source intelligence, or performing network scanning to identify potential entry points.
	- Threat Modeling: Analyze the target infrastructure and applications to identify potential vulnerabilities and attack vectors. This involves mapping out the architecture, identifying weaknesses, and prioritizing potential attack paths.
	- Tactic Selection: Based on the threat modeling exercise, determine the specific attack techniques, tactics, and procedures (TTPs) that will be employed during the emulation. This may include social engineering, network exploitation, privilege escalation, or other tactics commonly used by adversaries.
	- Planning: Develop a detailed plan that outlines the sequence of attack steps, timelines, and required resources. This plan should consider potential contingencies and include any necessary approvals from stakeholders.
	- Execution: Implement the planned attack scenarios, following the predefined TTPs. This may involve deploying specialized tools, exploiting vulnerabilities, attempting to gain unauthorized access, or exfiltrating sensitive information.
	- Detection Evasion: Emulate advanced persistent threats (APTs) by employing techniques to evade detection by security controls and monitoring systems. This may involve bypassing intrusion detection systems, avoiding antivirus detection, or leveraging zero-day vulnerabilities.
	- Post-Exploitation and Persistence: Once access is gained, attempt to establish persistence within the target environment, such as creating backdoors, installing persistent malware, or creating privileged accounts. This step aims to simulate the actions an attacker might take to maintain long-term access.
	- Reporting: Document the findings, observations, and recommendations from the emulation exercise. A comprehensive report should detail the identified vulnerabilities, successful attack paths, and recommendations for improving security controls and mitigating risks.
	- Remediation: Work with the organization's security team to address the identified vulnerabilities and implement appropriate countermeasures. This may involve patching systems, updating configurations, improving network segmentation, or enhancing employee training and awareness.
	- Follow-Up Testing: Conduct additional testing to validate the effectiveness of the implemented remediation measures and ensure that the identified vulnerabilities have been adequately addressed.

### Goal Planning

- Physical

	- Unauthorized Access: The red team aims to gain unauthorized physical access to restricted areas within the organization's premises, such as server rooms, executive offices, or sensitive data storage areas. This helps evaluate the effectiveness of access controls, surveillance systems, and other physical security measures.  Such as confidential documents, prototypes, intellectual property, or physical equipment. This helps assess the organization's ability to protect sensitive information and valuable resources from theft?
	- Social Engineering: Physical red team engagements often involve social engineering tactics to manipulate employees and gain access to restricted areas or sensitive information. This can include impersonating authorized personnel, tailgating (following someone without proper authorization), or exploiting trust relationships to bypass security controls?
	- The red team may perform surveillance and reconnaissance activities to gather information about the organization's physical security infrastructure, including security camera locations, guard rotations, and security personnel behavior?

- Critical System

	- Can a threat access key/critical systems?
	- What impacts can a threat have on key/critical systems?

- Domain 

	- What ability does a threat have to gain local administrative access?
	- What ability does a threat have to gain domain administrative access?
	- What ability does a threat have to gain elevated access?

- Network Edge

	- Do I have assets exposed to the internet? Open cloud storages? Subdomains without waf?Configuration files exposed?
	- Have any of my applications already been hacked?

- PII

	- What ability does a threat have to access sensitive information?
	- What ability does a threat have to identify sensitive information?

- Exfiltrate

	- What ability does a threat have to exfiltrate data outside an organization?
	- How much data must be exfiltrated to impact an organization?

### TTPs and Tradecraft

- Every Red Team should have a guidance document. Keep this document updated and distributed to all Red Team members. This document should be used to guide Red Team actions of all Red Team operators on all engagements. Exceptions to these rules can (and will) be made based on specific Rules of Engagement (ROE) or decision made by Red Team leads during an engagement. Exceptions should be documented as part of the engagement logging. It is important to use and follow this document to maintain a high-quality professional Red Team.
- Add custom or specific Tradecraft and TTP Guidance to this document as needed. This include specific or customs tools that should be used for various tasks, C2, enumeration, etc

### Test Environment (script, application, binary, process, etc.)

- Before using a new tool (script, application, binary, process, etc.) on a target system, it must be tested, undergo an internal vetting process and be added to an official toolset.
- Create Virtual environment to Testing

	- Works fine on Windows 7 but causes system error in Windows 8?
	- Do you know if/what additional actions the tool performs?
	- Tool creates a covert channel for use inside the network.
	- This tool creates a private tunnel between host on a virtual interface; however, this creates a network conflict
	- Ex: target net: 10.10.2.0/24, covert channel net: 10.10.2.0/24 - Hint: Don’t use these! Does the tool try to call home for updates?
	- At start or during a specific operation, the tool tries to poll home for updates
	- This can trigger defensive alerts identifying unauthorized persons or software on the network

### Tools and Infraestructure

- Redirectors

	- A redirector or a relay is a network widget that listens for incoming connections and forwards them to another host or port. This is an operational security best practice so that you never expose your Command and Control (C2) server to everyone on the Internet. Instead, your payload should be configured to connect to the redirector/relay so that anyone looking at the network connections sees the redirector/relay and not your C2 server. If a defender/Blue Team blocks your redirector, your C2 server is still accessible.

- Adversary Emulation Tools

	- Metasploit: A popular framework for penetration testing and exploiting vulnerabilities.
	- Empire: An open-source post-exploitation framework for Windows environments.
	- Cobalt Strike: Although it has a commercial version, the older version of Cobalt Strike (3.13) is open source and widely used for red teaming activities.
	- CALDERA: An open-source framework designed to automate the adversary emulation process.
	- MITRE ATT&CK Framework: Not a tool itself, but a knowledge base that provides a comprehensive framework of known adversary tactics, techniques, and procedures (TTPs) that can guide red teaming activities.
	- Red Canary Atomic Red Team: A subscription-based service that provides a library of adversary emulation tests based on the MITRE ATT&CK framework.
	- SafeBreach: A platform that allows organizations to simulate attacks and test their security controls and detection capabilities.
	- AttackIQ: A platform that enables continuous adversary emulations to validate and improve an organization's security posture.
	- Verodin (now part of FireEye): A platform that allows organizations to measure, manage, and improve their security effectiveness through adversary simulations.

### The Adversary Emulation Plan Library

- In collaboration with Center Participants, the MITRE Engenuity Center for Threat-Informed Defense (Center) is building a library of adversary emulation plans to allow organizations to evaluate their defensive capabilities against the real-world threats they face. Emulation plans are an essential component in testing current defenses for organizations that are looking to prioritize their defenses around actual adversary behavior. Focusing our energies on developing a set of common emulation plans that are available to all means that organizations can use their limited time and resources to focus on understanding how their defenses actually fare against real-world threats.

	- https://github.com/R0B1NL1N/adversary_emulation_library-1

### Adversary Emulation Structure

- Phase 1 - Planning and Preparation:

	- Collection of resources that enables operators to enable adversary
	- Objective Definition: Clearly define the goals, scope, and objectives of the adversary emulation exercise.
	- Rules of Engagement: Establish the rules, constraints, and limitations of the exercise, including any systems or assets that are out of bounds.
	- Resource Allocation: Determine the necessary resources, tools, and personnel required for the exercise.
	- Reconnaissance: Gather information about the target organization, its systems, networks, employees, and potential vulnerabilities.

- Phase 2 - Threat Emulation and Modeling

	- Identify Potential Adversaries: Research and identify the threat actors or adversary groups that are most relevant to the target organization.
	- Tactics, Techniques, and Procedures (TTPs) Selection: Select the specific attack techniques and tactics that the red team will emulate based on the identified adversaries and their modus operandi.
	- Scenario Development: Design realistic attack scenarios that align with the selected TTPs and objectives of the exercise.

- Phase 3 -  Execution

	- Initial Compromise: Attempt to gain an initial foothold in the target environment using the chosen TTPs, such as phishing, social engineering, or network exploitation.
	- Lateral Movement: Once inside the target environment, expand access and move laterally across systems and networks to achieve the predefined objectives.
	- Privilege Escalation: Attempt to escalate privileges and gain higher levels of access within the target environment.
	- Data Exfiltration: Simulate the extraction or exfiltration of sensitive data or intellectual property from the target environment.
	- Persistence: Establish mechanisms to maintain long-term access to the target environment, such as creating backdoors, installing persistent malware, or creating unauthorized accounts.

- Phase 4 - Post-Exploitation and Analysis

	- Analysis of Compromised Systems: Analyze the compromised systems and networks to understand the impact and potential risks associated with the identified vulnerabilities.
	- Documentation: Document the actions taken, findings, and observed vulnerabilities for later reporting and analysis.
	- Lessons Learned: Conduct a thorough review of the exercise, identifying strengths, weaknesses, and areas for improvement in the organization's security posture.

- Phase 5 - Reporting and Recommendations

	- Reporting: Prepare a comprehensive report that includes detailed findings, analysis, and recommendations to address the identified vulnerabilities and improve security controls.
	- Remediation Planning: Work with the organization's security team to develop a plan for remediation and mitigation of the identified vulnerabilities.
	- Communication: Present the findings and recommendations to relevant stakeholders, such as executives, IT teams, and security personnel.

### Red Team Structure

- RED TEAM LEAD

	- Serves as the operational and administrative lead for the Red Team. Conducts engagement, budget, and resource management for the Red Team, Provides oversight and guidance for engagements, capabilities, and technologies. Ensures adherence to all laws, regulations, policies, and Rules of Engagement.

- RED TEAM OPERATOR

	- Complies with all Red Team requirements under the direction of the Red Team Lead. Operational executor of the engagement. Applies Red Team TTPs to the engagement. Provides technical research and capability to the Red Team. Keeps detailed logs during each phase of the engagement. Provides log and information support for the creation of the final report

- RED TEAMING

	- Red teaming is the process of using Tactics, Techniques, and Procedures (TTPs) to emulate real-world threats with the goal of training and measuring the effectiveness of the people, processes, and technology used to defend an environment.
	- In terms of business risk, a red team engagement focuses on understanding how well security operations deal with a threat through training or measurement. Technical findings are often revealed during an engagement but are not the focus. Red teaming engagements are designed to challenge security operation’s defensive strategies and assumptions and to identify gaps or flaws in the defensive strategies. Improving security operations through training or measurement is the goal of a red teaming engagement.

### NIST Cyber Security Framework

- The NIST Cybersecurity Framework (CSF) provides a comprehensive framework for organizations to manage and improve their cybersecurity posture. While the framework primarily focuses on risk management and cybersecurity controls, it can be effectively used in conjunction with a red team exercise to assess an organization's security defenses and identify potential vulnerabilities.

	- Identify (Red Team Objective: Reconnaissance and Threat Modeling):

		- Identify the critical assets, systems, and networks within the organization's infrastructure that need to be evaluated during the red team engagement.
		- Conduct reconnaissance and gather information about the target organization, including its architecture, vulnerabilities, and potential attack vectors.
		- Use this information to develop a threat model that outlines the likely adversaries, their motivations, and the potential tactics, techniques, and procedures (TTPs) they may employ.

	- Protect (Red Team Objective: Unauthorized Access and Exploitation):

		- Assess the effectiveness of the organization's protective measures, such as access controls, authentication mechanisms, network segmentation, and encryption.
		- Attempt to bypass or exploit these protective measures to gain unauthorized access to critical systems or sensitive information.

	- Detect (Red Team Objective: Evasion and Stealth):

		- Test the organization's detection capabilities, including intrusion detection systems, log monitoring, and incident response processes.
		- Employ evasion techniques to avoid detection while performing red team activities, such as manipulating or obfuscating network traffic or disguising malicious activities.

	- Respond (Red Team Objective: Incident Response and Persistence):

		- Evaluate the organization's incident response capabilities by simulating attacks and assessing how well the team detects, responds to, and mitigates the simulated incidents.
		- Test the organization's ability to detect and remove persistent access by establishing persistence mechanisms, such as backdoors or hidden accounts.

	- Recover (Red Team Objective: Reporting and Recommendations):

		- Document and report the findings, observations, and recommendations based on the red team exercise.
		- Provide actionable recommendations to improve the organization's cybersecurity posture, strengthen protective measures, and enhance incident response and recovery capabilities.

### CIS Controls

- Apologies for the confusion. The Center for Internet Security (CIS) Controls consists of 18 controls that provide a framework for organizations to improve their cybersecurity posture. While the controls are primarily focused on proactive cybersecurity measures, they can be used as a reference for red teaming exercises to identify vulnerabilities and assess the effectiveness of an organization's security defenses.

	- Inventory and Control of Hardware Assets:

		- Evaluate the organization's ability to maintain an accurate inventory of hardware assets and control their use to prevent unauthorized access or exploitation.

	- Inventory and Control of Software Assets:

		- Assess the organization's practices for managing software assets, including software inventory, patch management, and vulnerability assessment.

	- Continuous Vulnerability Management:

		- Test the organization's vulnerability management program, including vulnerability scanning, patch management, and prioritization of vulnerabilities for remediation.

	- Secure Configuration for Hardware and Software:

		- Assess the organization's implementation of secure configurations for hardware, operating systems, applications, and other software components to prevent exploitation.

	- Controlled Use of Administrative Privileges:

		- Evaluate the organization's control and monitoring of administrative privileges, including the management of privileged accounts and access controls.

	- Maintenance, Monitoring, and Analysis of Audit Logs:

		- Test the organization's logging and monitoring capabilities to detect and respond to security incidents, including the analysis and retention of audit logs.

	- Email and Web Browser Protections:

		- Assess the organization's email and web browsing security controls, including spam filtering, email authentication, web content filtering, and protection against phishing attacks.

	- Malware Defenses:

		- Test the organization's defenses against malware, including antivirus solutions, endpoint protection, and incident response procedures for malware incidents.

	- Limitation and Control of Network Ports, Protocols, and Services:

		- Evaluate the organization's network security controls, including firewall configurations, network segmentation, and controls for network ports, protocols, and services.

	- Data Recovery Capabilities:

		- Assess the organization's data backup and recovery processes, including backup configurations, off-site storage, and restoration procedures in the event of data loss or system compromise.

	- Secure Configuration for Network Devices, such as Routers and Switches:
	- Boundary Defense:

		- Test the organization's network boundary defenses, including firewalls, intrusion prevention systems (IPS), and other network security controls.

	- Data Protection:

		- Assess the organization's data protection measures, including encryption, access controls, and data loss prevention (DLP) solutions.

	- Controlled Access Based on the Need to Know:

		- Evaluate the organization's access control mechanisms, including user access rights, privileges, and least privilege principles.

	- Wireless Access Control:

		- Test the organization's wireless network security controls, including Wi-Fi authentication, encryption, and intrusion detection systems for wireless networks.

	- Account Monitoring and Control:

		- Assess the organization's practices for monitoring and controlling user accounts, including account provisioning, deprovisioning, and account activity monitoring.

	- Security Awareness and Training Programs:

		- Evaluate the organization's security awareness and training programs, including phishing simulations, security education, and user awareness of security best practices.

	- Application Software Security:

		- Test the security of applications developed or used by the organization, including secure coding practices, input validation, and secure configuration of application software.

## How to make?

### Create Plan

- To showcase the practical use of ATT&CK for offensive operators and defenders, MITRE created Adversary Emulation Plans. These are prototype documents of what can be done with publicly available threat reports and ATT&CK. The purpose of this activity is to allow defenders to more effectively test their networks and defenses by enabling red teams to more actively model adversary behavior, as described by ATT&CK. This is part of a larger process to help more effectively test products and environments, as well as create analytics for ATT&CK behaviors rather than detecting a specific indicator of compromise (IOC) or specific tool.

	- There are many threat intel reports that focus on malware reverse engineering, initial compromise, and command and control (C2) explanations; however, there are not many threat reports on how attackers are chaining techniques together or how attackers operate on keyboard. Because these prototypes are built on these open threat reports, they have the same limitations. To help with this, we provided a sample way to string the ATT&CK tactics together based on general red teaming experience. To create these plans, the team drilled down on specific APT groups listed in ATT&CK and see what kind of plans could be generated for an operator to emulate those APTs. After reading what capabilities were provided by an APT's tools, we compiled a list of other ways to exhibit the same behavior. We wanted operators to behave generally like a specific adversary (sticking to that adversary's known TTPs and behaviors), but having some latitude in actual implementation. To help with this, we also provided a cheat sheet for commands that can be executed for similar behavior in some of the most commonly used red teaming tools. An example, high-level diagram below highlights one possible way to structure an APT3 emulation plan.

		- http://attack.mitre.org/resources/adversary-emulation-plans/

- Threat Intelligence

	- Gather and Analyze Threat Intelligence:

		- Collect relevant threat intelligence from reliable sources, such as government agencies, cybersecurity vendors, industry reports, and open-source intelligence (OSINT).
		- Analyze the threat intelligence to identify specific threat actors, their TTPs, target sectors, and recent attack patterns.

	- Define the Objectives and Scope:

		- Determine the objectives of the threat emulation exercise based on the identified threat actors and their TTPs.
		- Define the scope of the exercise, including the systems, networks, and assets to be targeted, and any constraints or limitations.

	- Select the TTPs to Emulate:

		- Based on the threat intelligence analysis, choose the TTPs most relevant to the target organization and its industry sector.
		- Prioritize TTPs that pose the highest risk or align with recent attacks observed in the threat intelligence.

	- Plan the Emulation Exercise:

		- Develop a detailed plan that outlines the specific TTPs to be emulated, the sequence of actions, and the tools and techniques to be used.
		- Consider the potential impact on the target organization's operations, availability, and confidentiality during the planning phase.

	- Execute the Threat Emulation Exercise:

		- Implement the planned TTPs in a controlled manner, simulating the actions of the identified threat actors.
		- Use a combination of social engineering, network exploitation, phishing, or any other relevant methods to execute the chosen TTPs.

	- Monitor and Assess:

		- Continuously monitor and assess the effectiveness of the emulated TTPs in achieving the objectives of the exercise.
		- Document the actions taken, techniques used, and observations during the emulation exercise.

	- Evaluate Detection and Response Capabilities:

		- Evaluate the target organization's detection and response capabilities by monitoring how the emulated TTPs are detected and mitigated.
		- Assess the effectiveness of security controls, incident response procedures, and threat hunting capabilities.

	- Document Findings and Recommendations:

		- Prepare a comprehensive report that includes the findings, observed vulnerabilities, strengths, weaknesses, and recommendations.
		- Provide actionable recommendations to improve the organization's security posture based on the observed gaps and weaknesses.

	- Review and Iteration:

		- Conduct a thorough review of the threat emulation exercise and the findings.
		- Use the insights gained to refine the organization's security controls, detection mechanisms, and incident response procedures.

	- Continuous Improvement:

		- Integrate the lessons learned from the threat emulation exercise into the organization's cybersecurity practices.
		- Continuously update the threat intelligence and adapt the threat emulation plan to address emerging threats and changing attack patterns.

- Select APT Emulation Plan

	- Select a combination of TTPs associated with the chosen APT group, considering their modus operandi and relevance to the target organization:

		- Spear-phishing: Craft and send tailored spear-phishing emails to key individuals within the organization.
		- Watering Hole Attacks: Identify and compromise websites frequented by the organization's employees to deliver malware.
		- Exploitation of Zero-Day Vulnerabilities: Exploit undisclosed vulnerabilities in software or systems used by the organization.
		- Social Engineering: Manipulate individuals through phone calls, impersonation, or physical infiltration to gain unauthorized access.
		- Lateral Movement and Persistence: Attempt to move laterally within the network, escalate privileges, and establish long-term persistence.
		- Data Exfiltration: Simulate the extraction of sensitive data using various covert channels and techniques.

### Execution

- Emulating an Advanced Persistent Threat (APT) involves simulating the tactics, techniques, and procedures (TTPs) of a specific threat actor to assess an organization's defenses against sophisticated and persistent attacks.

	- Spear-phishing: Craft convincing spear-phishing emails and distribute them to targeted individuals within the organization.
	- Watering Hole Attacks: Identify and compromise legitimate websites frequented by the organization's employees to deliver malware.
	- Exploitation of Zero-Day Vulnerabilities: Identify and exploit undisclosed vulnerabilities in software or systems used by the organization.
	- Social Engineering: Engage in activities like impersonation, physical infiltration, or phone calls to gain unauthorized access.
	- Lateral Movement and Persistence: Attempt to move laterally, escalate privileges, and establish persistent access within the organization's network.
	- Data Exfiltration: Simulate the extraction of sensitive data using covert channels, encryption, steganography, or other advanced techniques.

- Create ttps spreadsheets based on the tools available for you to test

	- Select a TTP to emulate
	- By category extract the procedures
	- And put all the tools and commands to run

- Threat Profiles

	- A threat profile is used to establish the rules as to how a Red Team will act and operate. These rules serve as a roadmap for a Red Team by guiding how and what type of actions should be performed. Threat profiles are a key part of developing and designing C2 early in Red Team planning.

### Post-Execution

- Monitoring and Assessment:

	- Continuously monitor the emulation exercise, documenting the actions taken, techniques used, and responses from the organization's security controls.
	- Evaluate the organization's detection capabilities, incident response procedures, and ability to mitigate the emulated APT's activities.

- Findings and Recommendations:

	- Document the findings, including successful compromises, observed vulnerabilities, and weaknesses in the organization's defenses.
	- Provide actionable recommendations to enhance the organization's security posture, such as improving threat detection, incident response, employee awareness, or system hardening.

- Review and Iteration:

	- Conduct a comprehensive review of the emulation exercise and findings with the organization's security team.
	- Incorporate the lessons learned into the organization's security controls, policies, and procedures.
	- Consider conducting periodic APT emulations to track progress and identify emerging vulnerabilities and response improvements.


## References

- https://howto.thec2matrix.com/ (The C2 Matrix)
- http://attack.mitre.org/ (Mitre Att&ck)
- https://github.com/R0B1NL1N/adversary_emulation_library-1 (Adversary Emulation Library)
- https://redteam.guide/ (Red Team Guide)
- https://medium.com/mitre-engenuity/introducing-the-all-new-adversary-emulation-plan-library-234b1d543f6b (Emulation Plan)
- https://www.cisecurity.org/ (CIS Controls)
- https://www.nist.gov/cyberframework (NIST CSF)
- https://csrc.nist.gov/glossary/term/red_team_exercise (Red Team Exercise)
- https://github.com/CyberSecurityUP/Red-Team-Management (Red Team Management)



