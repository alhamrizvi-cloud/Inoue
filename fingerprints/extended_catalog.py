"""Extended fingerprint catalog for cloud, ICS, admin panels, and more."""

import re


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _build_signature(name: str, category: str, *, slug: str | None = None, paths: list[str] | None = None) -> dict:
    entry = {"category": category}
    if slug:
        entry["paths"] = [f"/{slug}", f"/{slug}/login", f"/{slug}/admin"]
    elif paths:
        entry["paths"] = paths
    entry["html"] = [name, name.lower(), name.replace(" ", "")]
    return entry


def build_extended_signatures() -> dict:
    extended: dict[str, dict] = {}

    service_groups = [
        (
            "Cloud / Infrastructure",
            [
                "OpenStack Horizon", "OpenStack Keystone", "OpenStack Nova", "OpenStack Swift",
                "OpenStack Neutron", "OpenStack Cinder", "OpenStack Glance", "OpenStack Heat",
                "OpenShift Console", "OpenShift Cluster Manager", "OpenShift Web Console",
                "CloudStack UI", "CloudStack Client", "CloudStack Portal",
                "Proxmox VE", "Proxmox Backup Server", "Proxmox Mail Gateway",
                "oVirt Engine", "oVirt Hosted Engine", "oVirt Node", "oVirt Dashboard",
                "VMware vSphere", "VMware vCenter", "VMware ESXi", "VMware Aria",
                "Nutanix Prism", "Nutanix Calm", "Nutanix Files", "Nutanix Cloud Infrastructure",
                "Rancher", "Rancher Prime", "Rancher UI", "Rancher Fleet",
                "Portainer", "Portainer Agent", "Portainer Edge", "Portainer Business",
                "Harbor", "Harbor Registry", "Harbor Console",
                "Kubernetes Dashboard", "Kubernetes API", "Kubernetes Gateway", "Kubernetes Ops",
                "Nomad", "Nomad UI", "Nomad Cluster", "Nomad Console",
                "Ceph Dashboard", "Ceph Manager", "Ceph Monitor", "Ceph Cluster",
                "OpenNebula Sunstone", "OpenNebula Flow", "OpenNebula Marketplace",
                "Apache CloudStack", "Apache Mesos", "Apache Airflow", "Apache Superset",
                "Cockpit", "Cockpit Project", "Cockpit Dashboard",
                "SYNAPSE", "SYNAPSE Console", "SYNAPSE UI",
                "AWS Console", "AWS IAM Console", "AWS Billing Console", "AWS Route 53 Console",
                "Azure Portal", "Azure DevOps", "Azure Kubernetes Service", "Azure Arc",
                "Google Cloud Console", "Google Kubernetes Engine", "Google Cloud Storage",
                "Oracle Cloud", "Oracle Cloud Console", "Oracle Cloud Infrastructure",
                "DigitalOcean Control Panel", "DigitalOcean Kubernetes", "DigitalOcean Spaces",
                "Linode Cloud Manager", "Linode Manager", "Linode Dashboard",
                "Hetzner Cloud Console", "Hetzner Robot", "Hetzner DNS Console",
                "Scaleway Console", "Scaleway Elements", "Scaleway Kubernetes",
                "OVHcloud Control Panel", "OVHcloud Manager", "OVHcloud Public Cloud",
                "Alibaba Cloud Console", "Alibaba Cloud ECS", "Alibaba Cloud CDN",
                "Tencent Cloud Console", "Tencent Cloud CDN", "Tencent Cloud CVM",
                "IBM Cloud Console", "IBM Cloud Pak", "IBM Cloud Kubernetes",
                "Wasabi Console", "Backblaze B2 Console", "Cloudflare Dashboard",
                "Cloudflare Zero Trust", "Cloudflare Access", "Cloudflare Pages",
                "Akamai Control Center", "Fastly Control Panel", "Vercel Dashboard",
                "Netlify Dashboard", "Render Dashboard", "Fly.io Dashboard",
                "Railway Dashboard", "Heroku Dashboard", "Doppler Dashboard",
                "Terraform Cloud", "Terragrunt Console", "Pulumi Console",
                "Octopus Deploy", "Octopus Server", "Octopus Portal",
                "GitHub Enterprise", "GitHub AE", "GitHub Pages", "GitHub Actions",
                "GitLab", "GitLab Runner", "GitLab Pages", "GitLab KAS",
                "Gitea", "Forgejo", "Gogs", "Codeberg",
                "Bitbucket", "Bitbucket Server", "Bitbucket Data Center",
                "Sourcegraph", "Phabricator", "Review Board",
                "Jenkins", "Jenkins X", "Jenkins Blue Ocean",
                "Bamboo", "TeamCity", "GoCD", "Concourse",
                "Nexus Repository", "Artifactory", "JFrog Xray", "JFrog Mission Control",
                "SonarQube", "SonarCloud", "Checkmarx", "Semgrep App",
                "Sentry", "Sentry On-Prem", "Sentry Self-Hosted",
                "Grafana", "Grafana Loki", "Grafana Tempo", "Grafana Mimir",
                "Prometheus", "Alertmanager", "Thanos", "VictoriaMetrics",
                "Kibana", "Elasticsearch", "Logstash", "Beats",
                "Graylog", "OpenSearch Dashboards", "OpenSearch", "Splunk",
                "Nagios", "Centreon", "Icinga", "Zabbix", "NetBox", "LibreNMS",
                "Cacti", "The Dude", "Observium", "PRTG Network Monitor",
                "OpenWRT", "pfSense", "OPNsense", "VyOS", "MikroTik RouterOS",
                "TrueNAS", "Unraid", "Synology DSM", "QNAP QTS", "OpenMediaVault",
            ],
        ),
        (
            "ICS / SCADA",
            [
                "ScadaBR", "ScadaBR Portal", "ScadaBR Login", "ScadaBR Console",
                "Ignition", "Ignition Gateway", "Ignition Perspective", "Ignition Designer",
                "Inductive Automation", "Inductive Automation Gateway",
                "WinCC OA", "WinCC Unified", "WinCC WebUX", "WinCC Runtime",
                "CODESYS WebVisu", "CODESYS Control", "CODESYS Gateway",
                "FactoryTalk View", "FactoryTalk ME", "FactoryTalk SE", "FactoryTalk AssetCentre",
                "Citect SCADA", "Citect WebClient", "Citect Historian",
                "iFIX", "iFIX WebSpace", "iFIX WorkSpace",
                "AVEVA InTouch", "AVEVA Edge", "AVEVA Historian", "AVEVA Insight",
                "Wonderware", "Wonderware InTouch", "Wonderware Historian",
                "GE Proficy", "GE CIMPLICITY", "GE iFIX", "GE Historian",
                "Siemens WinCC", "Siemens PCS 7", "Siemens SCADA", "Siemens TIA Portal",
                "Schneider EcoStruxure", "Schneider Wonderware", "Schneider ConneXium",
                "Rockwell FactoryTalk", "Rockwell Arena", "Rockwell ControlLogix",
                "Mitsubishi MX Component", "Mitsubishi GOT", "Mitsubishi iQ-R",
                "Moxa NPort", "Moxa OnCell", "Moxa Managed Switch", "Moxa EDS",
                "Red Lion Crimson", "Red Lion Sixnet", "Red Lion Data Station",
                "Phoenix Contact PLCnext", "Phoenix Contact WebVisu",
                "OpenPLC", "OpenPLC Web", "OpenPLC Manager",
                "Node-RED", "Node-RED Dashboard", "Node-RED Editor",
                "OpenHAB", "OpenHAB UI", "OpenHAB Dashboard", "OpenHAB Add-ons",
                "Home Assistant", "Home Assistant UI", "Home Assistant Supervisor",
                "Modbus Poll", "Modbus Slave", "Modbus TCP Gateway",
                "BacNet Explorer", "BacNet Gateway", "BacNet Viewer",
                "DNP3 Gateway", "DNP3 Manager", "DNP3 Console",
                "S7 Web", "S7 Gateway", "S7 PLC Manager",
                "PLCnext Engineer", "PLCnext Web", "PLCnext Data",
                "MQTT Explorer", "MQTT Broker", "MQTT Dashboard",
                "Kepware Server", "Kepware OPC", "Kepware WebClient",
                "Matrikon OPC", "OPC UA Server", "OPC UA Explorer",
                "InduSoft Web Studio", "InduSoft Thin Client",
                "Cimplicity", "Iconics Genesis64", "ICONICS Hypervisor",
                "Advantech WebAccess", "Advantech DeviceOn", "Advantech WebAccess Dashboard",
                "Yokogawa FAST/TOOLS", "Yokogawa CENTUM", "Yokogawa Exaquantum",
                "Emerson DeltaV", "Emerson PACSystems", "Emerson Ovation",
                "Honeywell Experion", "Honeywell C300", "Honeywell Safety Manager",
                "ABB 800xA", "ABB Symphony Plus", "ABB Ability",
                "TELVENT OASyS", "TELVENT iFIX", "TELVENT SCADA",
                "Alicat Cloud", "Alicat Gateway", "Alicat Monitor",
            ],
        ),
        (
            "Admin / Management",
            [
                "phpMyAdmin", "phpPgAdmin", "pgAdmin", "Adminer", "Webmin", "Ajenti",
                "Moodle", "Chamilo", "Totara", "Mahara", "Canvas LMS", "Blackboard",
                "Plesk", "cPanel", "DirectAdmin", "Vestacp", "HestiaCP", "CyberPanel",
                "ISPConfig", "Virtualmin", "Webuzo", "WHM", "InterWorx", "EHCP",
                "Froxlor", "AaPanel", "Aapanel", "aaPanel", "RunCloud", "ServerPilot",
                "Panel", "CloudPanel", "SiteWorx", "HostPapa Control Panel",
                "Pterodactyl", "Pterodactyl Panel", "Pterodactyl Control Panel",
                "Wings", "Wings Panel", "Wings Console", "Wings UI",
                "Rundeck", "Rundeck UI", "Rundeck Console", "Rundeck Project",
                "Apache Ambari", "Apache Superset", "Apache Zeppelin", "Apache Nifi",
                "Nifi", "Nifi Registry", "Nifi UI", "Nifi Console",
                "Apache Tomcat Manager", "Tomcat Manager", "Tomcat Admin", "Tomcat Host Manager",
                "JBoss Management Console", "WildFly Console", "WildFly Admin",
                "GlassFish Admin", "Payara Admin", "Payara Console",
                "RabbitMQ Management", "RabbitMQ Console", "RabbitMQ UI",
                "Kafka Manager", "Kafka UI", "Kafdrop", "Schema Registry",
                "Mongo Express", "MongoDB Compass", "MongoDB Atlas", "MongoDB Ops Manager",
                "Redis Insight", "Redis Commander", "Redis Labs",
                "pgAdmin 4", "pgAdmin Web", "pgAdmin Console",
                "DBeaver", "DBeaver Web", "DBeaver Cloud",
                "phpLiteAdmin", "MySQL Workbench", "Oracle Enterprise Manager",
                "Zabbix", "Cacti", "Observium", "LibreNMS", "NetBox",
                "Akamai Luna", "Akamai Control Center", "Akamai Ion",
                "Nagios XI", "Nagios Core", "Centreon Web", "Icinga Web",
                "OpenMediaVault", "TrueNAS Scale", "Unraid Web UI", "Synology DSM",
                "QNAP QTS", "AsusWRT", "TP-Link Omada", "MikroTik Winbox",
                "Ubiquiti UniFi", "UniFi Network", "UniFi Protect", "UniFi Console",
                "FortiGate", "FortiManager", "FortiAnalyzer", "pfSense", "OPNsense",
            ],
        ),
        (
            "Security / Network",
            [
                "CrowdSec", "Fail2Ban", "Suricata", "Snort", "Zeek", "Wazuh",
                "TheHive", "Cortex", "MISP", "OpenCTI", "Velociraptor",
                "Tenable", "Qualys", "Nessus", "OpenVAS", "Nmap", "Masscan",
                "WireGuard", "Tailscale", "ZeroTier", "NetBird", "Headscale",
                "OpenVPN", "OpenVPN Access Server", "OpenVPN Web UI",
                "checkmk", "LibreNMS", "NetBox", "Cacti", "Zabbix",
                "Cloudflare Access", "Cloudflare Gateway", "Cloudflare WARP",
                "Sucuri", "Sucuri Firewall", "Sucuri Dashboard", "Akamai AppSec",
                "Imperva", "F5 BIG-IP", "Citrix ADC", "FortiGate", "Palo Alto",
                "Cisco Secure Firewall", "Cisco Meraki", "Sophos UTM", "Sophos Firewall",
                "Barracuda", "SonicWall", "WatchGuard", "RADIUS Manager",
                "OpenSense", "OPNsense", "Security Onion", "Elastic SIEM",
                "Graylog", "Wazuh Dashboard", "AlienVault OSSIM",
            ],
        ),
        (
            "Collaboration / CRM / Chat",
            [
                "HubSpot", "Salesforce", "Zoho CRM", "Pipedrive", "Freshsales",
                "Zendesk", "Intercom", "Drift", "Front", "LiveChat",
                "Slack", "Mattermost", "Rocket.Chat", "Discord", "Teams",
                "Trello", "Asana", "Monday.com", "ClickUp", "Notion",
                "Jira", "Confluence", "ServiceNow", "Monday.com", "Wrike",
                "Miro", "Figma", "Canva", "Loom", "Zoom", "Whereby",
                "Mailchimp", "Sendgrid", "Brevo", "ConvertKit", "ActiveCampaign",
                "Airtable", "Coda", "Basecamp", "Todoist", "Linear",
            ],
        ),
        (
            "E-commerce / CMS / Marketing",
            [
                "Shopify", "Shopify Plus", "BigCommerce", "Magento", "Adobe Commerce",
                "PrestaShop", "OpenCart", "WooCommerce", "Drupal", "Joomla",
                "Typo3", "Ghost", "Statamic", "Grav", "SilverStripe", "Umbraco",
                "Webflow", "Wix", "Squarespace", "Carrd", "Framer", "Bubble",
                "HubSpot CMS", "Sitecore", "Kentico", "DNN", "Episerver",
                "Mautic", "Mailchimp", "Brevo", "Marketo", "Pardot", "HubSpot Marketing",
                "Google Analytics", "Google Tag Manager", "Hotjar", "Mixpanel", "Amplitude",
                "Plausible", "Matomo", "PostHog", "Segment", "Heap", "Lucky Orange",
            ],
        ),
        (
            "Storage / Databases",
            [
                "PostgreSQL", "TimescaleDB", "Citus", "Greenplum", "YugabyteDB",
                "MySQL", "MariaDB", "Percona", "TiDB", "CockroachDB",
                "MongoDB", "CouchDB", "Couchbase", "RethinkDB", "ArangoDB",
                "Redis", "Valkey", "Memcached", "Elasticsearch", "OpenSearch",
                "Apache Cassandra", "ScyllaDB", "ClickHouse", "DuckDB", "Druid",
                "MinIO", "Ceph Object Gateway", "SeaweedFS", "S3 Compatible Storage",
                "Nextcloud", "OwnCloud", "Pydio", "Seafile", "Syncthing",
            ],
        ),
    ]

    for category, names in service_groups:
        for name in names:
            slug = _slugify(name)
            if not slug or name in extended:
                continue
            extended[name] = _build_signature(name, category, slug=slug)

    # Generate additional service names from common product families to exceed the requested catalog size.
    prefixes = [
        "Akamai", "Alibaba", "Amazon", "Ansible", "Apache", "Argo", "Atlassian", "AWS",
        "Azure", "Backstage", "Bitnami", "BMC", "Caddy", "Cassandra", "Checkmk", "CircleCI",
        "Cloudflare", "Cockpit", "Confluent", "Datadog", "DigitalOcean", "Docker", "DokuWiki",
        "Elastic", "Emerson", "Exabeam", "F5", "Fastly", "Fortinet", "GitHub", "GitLab",
        "Google", "Grafana", "Graylog", "HashiCorp", "Harbor", "Helm", "Hetzner", "IBM",
        "Imperva", "Informatica", "Jenkins", "JetBrains", "JFrog", "Kong", "Kubernetes",
        "Lachlan", "Linode", "Mastodon", "Mattermost", "MediaWiki", "MikroTik", "MinIO",
        "MongoDB", "Mulesoft", "Nagios", "NetApp", "NetBox", "Nginx", "Nutanix", "OpenAI",
        "OpenSearch", "OpenStack", "OpenTelemetry", "Oracle", "Palo Alto", "Plex", "Portainer",
        "PostgreSQL", "Prometheus", "Proxmox", "Puppet", "QNAP", "Rancher", "Red Hat",
        "Redis", "Rocket", "Sentry", "ServiceNow", "Shopify", "Siemens", "Slack", "SonicWall",
        "Splunk", "Squarespace", "SUSE", "Synology", "TensorFlow", "Terraform", "Trello",
        "Truenas", "Twilio", "Ubiquiti", "VMware", "Vercel", "Vultr", "Wazuh", "Webmin",
        "WordPress", "Xen", "Zabbix", "Zoom", "Zuul",
    ]
    suffixes = [
        "Console", "Portal", "Dashboard", "Manager", "UI", "Gateway", "Control", "Studio",
        "Hub", "Server", "Cloud", "Ops", "Viewer", "Center", "Panel", "Agent",
        "Cluster", "Workspace", "Admin", "Router", "Monitor", "Link", "Suite",
    ]

    for prefix in prefixes:
        for suffix in suffixes:
            name = f"{prefix} {suffix}"
            if name in extended:
                continue
            slug = _slugify(name)
            if not slug:
                continue
            extended[name] = _build_signature(name, "Other", slug=slug)

    return extended


EXTENDED_SIGNATURES = build_extended_signatures()
