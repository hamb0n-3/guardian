import unittest
from unittest.mock import patch, Mock, MagicMock
import socket # For socket.gaierror and socket constants
import subprocess # For TimeoutExpired

# Assuming modules are importable from the project root (e.g. running tests with python -m unittest)
from modules.network_scan import perform_traceroute, discover_dhcp_servers
from modules.utils import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

# --- Samples for perform_traceroute ---
SAMPLE_TRACEROUTE_OUTPUT_SUCCESS = """
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  0.543 ms
 2  10.0.0.1  1.234 ms
 3  8.8.8.8  2.345 ms
"""
SAMPLE_TRACEROUTE_HIGH_RTT = """
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1  250.543 ms
 2  *
 3  93.184.216.34  300.000 ms
"""
SAMPLE_TRACEROUTE_UNREACHABLE = """
traceroute to 10.255.255.1 (10.255.255.1), 30 hops max, 60 byte packets
 1  192.168.1.1  0.543 ms
 2  10.0.0.1  1.234 ms
 3  * * *
 4  * * *
 5  * * *
"""

class TestPerformTraceroute(unittest.TestCase):
    def setUp(self):
        self.managed_stats = {'network': {'traceroute': {}}}
        self.mock_findings_list = []
        def mock_add_finding(managed_findings_ignored, severity, title, description, recommendation="N/A"):
            self.mock_findings_list.append({
                "severity": severity, "title": title, "description": description, "recommendation": recommendation
            })
        self.mock_add_finding_func = mock_add_finding
        self.mock_findings_list.clear()

    def _get_mock_popen(self, stdout_data, stderr_data="", returncode=0):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (stdout_data, stderr_data)
        mock_proc.returncode = returncode
        return mock_proc

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_successful(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "8.8.8.8"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_OUTPUT_SUCCESS)
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertIn(target_host, self.managed_stats['network']['traceroute'])
        trace_results = self.managed_stats['network']['traceroute'][target_host]
        self.assertIsNone(trace_results.get('error'))
        self.assertTrue("successfully reached" in trace_results['summary'].lower())
        hops = trace_results.get('hops', [])
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[2]['ip'], "8.8.8.8")

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_high_rtt_packet_loss(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "example.com"; target_ip = "93.184.216.34"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_ip, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_HIGH_RTT)
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertTrue(any(f["severity"] == SEVERITY_MEDIUM and "High RTT" in f["title"] and "192.168.1.1" in f["description"] for f in self.mock_findings_list))
        self.assertTrue(any(f["severity"] == SEVERITY_MEDIUM and "Packet Loss/Timeout at Hop 2" in f["title"] for f in self.mock_findings_list))

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_target_unreachable(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "10.255.255.1"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_UNREACHABLE)
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and f"Target {target_host} Unreachable" in f["title"] for f in self.mock_findings_list))

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_command_not_found(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "8.8.8.8"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen("", "traceroute: command not found", 127)
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and "Traceroute Execution Error" in f["title"] and "command not found" in f["description"].lower() for f in self.mock_findings_list))

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_host_resolution_error_socket(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "nonexistenthost123abc.com"
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        mock_subproc_popen.return_value = self._get_mock_popen("", f"traceroute: unknown host {target_host}", 1)
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and ("Traceroute Host Resolution Error" in f["title"] or "unknown host" in f["description"].lower()) or (f["severity"] == SEVERITY_LOW and "Traceroute Pre-computation Warning" in f["title"]) for f in self.mock_findings_list))

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_empty_output(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "8.8.8.8"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen("")
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        self.assertTrue(any(f["severity"] == SEVERITY_LOW and ("Traceroute Empty Output" in f["title"] or "No Hops Parsed" in f["title"]) for f in self.mock_findings_list))


# --- Tests for discover_dhcp_servers ---
SAMPLE_DHCP_XML_NO_SERVERS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap --script broadcast-dhcp-discover -oX -" start="1678886400" startstr="Mon Mar 15 12:00:00 2023" version="7.92" xmloutputversion="1.05">
<runstats><finished time="1678886405" timestr="Mon Mar 15 12:00:05 2023" elapsed="5.00" summary="Nmap done at Mon Mar 15 12:00:05 2023; 0 IP addresses (0 hosts up) scanned in 5.00 seconds" exit="success"/><hosts up="0" down="0" total="0"/>
</runstats>
</nmaprun>
"""
SAMPLE_DHCP_XML_ONE_SERVER = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap --script broadcast-dhcp-discover -oX -" start="1678886410" version="7.92">
<host starttime="1678886411" endtime="1678886412">
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostscript>
<script id="broadcast-dhcp-discover" output="&#xa;  Interface: eth0&#xa;    IP Offered: 192.168.1.150&#xa;    DHCP Message Type: DHCPOFFER&#xa;    Server Identifier: 192.168.1.1&#xa;    IP Address Lease Time: 1d0h0m0s&#xa;    Subnet Mask: 255.255.255.0&#xa;    Router: 192.168.1.1&#xa;    Domain Name Server: 192.168.1.1, 8.8.8.8&#xa;"/>
</hostscript>
</host>
<runstats><finished time="1678886415" elapsed="5.00"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""
SAMPLE_DHCP_XML_TWO_SERVERS = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap --script broadcast-dhcp-discover -oX -" start="1678886420" version="7.92">
<host starttime="1678886421" endtime="1678886422"><address addr="192.168.1.1" addrtype="ipv4"/><hostscript>
<script id="broadcast-dhcp-discover" output="&#xa;  Interface: eth0&#xa;    IP Offered: 192.168.1.150&#xa;    Server Identifier: 192.168.1.1&#xa;"/>
</hostscript></host>
<host starttime="1678886423" endtime="1678886424"><address addr="192.168.1.99" addrtype="ipv4"/><hostscript>
<script id="broadcast-dhcp-discover" output="&#xa;  Interface: eth0&#xa;    IP Offered: 192.168.1.199&#xa;    Server Identifier: 192.168.1.99&#xa;"/>
</hostscript></host>
<runstats><finished time="1678886425" elapsed="5.00"/><hosts up="2" down="0" total="2"/>
</runstats>
</nmaprun>
"""
MALFORMED_DHCP_XML = "<?xml version='1.0'?><nmaprun><host>This is not closed properly."

class TestDHCPDiscovery(unittest.TestCase):
    def setUp(self):
        self.managed_stats = {'network': {}}
        self.mock_findings_list = []
        def mock_add_finding(managed_findings_ignored, severity, title, description, recommendation="N/A"):
            self.mock_findings_list.append({
                "severity": severity, "title": title, "description": description, "recommendation": recommendation
            })
        self.mock_add_finding_func = mock_add_finding
        self.mock_findings_list.clear()

    def _get_mock_subprocess_run(self, stdout_data="", stderr_data="", returncode=0, side_effect=None):
        mock_run_instance = Mock()
        if side_effect:
            mock_run_instance.side_effect = side_effect
            return mock_run_instance
        
        mock_completed_process = Mock()
        mock_completed_process.stdout = stdout_data
        mock_completed_process.stderr = stderr_data
        mock_completed_process.returncode = returncode
        mock_run_instance.return_value = mock_completed_process
        return mock_run_instance

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_nmap_not_found(self, mock_run):
        mock_run.side_effect = [FileNotFoundError("Nmap not found")] # Only one call expected now for nmap --version
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, [])
        self.assertIn("Nmap is required", self.managed_stats['network']['dhcp_discovery_error'])
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and "Nmap Not Found" in f["title"] for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_nmap_command_error(self, mock_run):
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_fail = self._get_mock_subprocess_run(stdout_data="", stderr_data="Some Nmap Error", returncode=1)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_fail.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, [])
        self.assertIn("Nmap DHCP discovery finished with return code 1", self.managed_stats['network']['dhcp_discovery_error'])
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and "Nmap DHCP Discovery Failed" in f["title"] for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_nmap_timeout(self, mock_run):
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_run.side_effect = [mock_version_ok.return_value, subprocess.TimeoutExpired(cmd="nmap...", timeout=45)]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, [])
        self.assertIn("timed out after 45 seconds", self.managed_stats['network']['dhcp_discovery_error'])
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and "Nmap DHCP Discovery Timed Out" in f["title"] for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_no_servers_found(self, mock_run):
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_empty = self._get_mock_subprocess_run(stdout_data=SAMPLE_DHCP_XML_NO_SERVERS)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_empty.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, [])
        self.assertEqual(self.managed_stats['network']['dhcp_servers'], [])
        self.assertIsNone(self.managed_stats['network']['dhcp_discovery_error']) # Should be None if XML is empty but valid
        self.assertTrue(any((f["severity"] == SEVERITY_INFO and "No DHCP Offers Parsed" in f["title"]) or \
                            (f["severity"] == SEVERITY_LOW and "No DHCP Offers Received" in f["title"])
                            for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_authorized_server_found(self, mock_run):
        authorized_list = ["192.168.1.1"]
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_one_auth = self._get_mock_subprocess_run(stdout_data=SAMPLE_DHCP_XML_ONE_SERVER)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_one_auth.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, authorized_list)
        servers = self.managed_stats['network']['dhcp_servers']
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0]['server_ip'], "192.168.1.1")
        self.assertTrue(any(f["severity"] == SEVERITY_INFO and "Authorized DHCP Server Found" in f["title"] for f in self.mock_findings_list))
        self.assertFalse(any(f["severity"] == SEVERITY_CRITICAL for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_rogue_server_found(self, mock_run):
        authorized_list = ["192.168.1.1"] # .99 will be rogue
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_two = self._get_mock_subprocess_run(stdout_data=SAMPLE_DHCP_XML_TWO_SERVERS)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_two.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, authorized_list)
        self.assertTrue(any(f["severity"] == SEVERITY_CRITICAL and "Rogue DHCP Server Detected" in f["title"] and "192.168.1.99" in f["description"] for f in self.mock_findings_list))
        self.assertTrue(any(f["severity"] == SEVERITY_INFO and "Authorized DHCP Server Found" in f["title"] and "192.168.1.1" in f["description"] for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_authorized_list_empty(self, mock_run):
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_one = self._get_mock_subprocess_run(stdout_data=SAMPLE_DHCP_XML_ONE_SERVER)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_one.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, []) # Empty list
        self.assertTrue(any(f["severity"] == SEVERITY_CRITICAL and "Rogue DHCP Server Detected" in f["title"] and "(empty)" in f["description"] for f in self.mock_findings_list))

    @patch('modules.network_scan.subprocess.run')
    def test_dhcp_malformed_xml(self, mock_run):
        mock_version_ok = self._get_mock_subprocess_run(stdout_data="Nmap version ...")
        mock_scan_malformed = self._get_mock_subprocess_run(stdout_data=MALFORMED_DHCP_XML)
        mock_run.side_effect = [mock_version_ok.return_value, mock_scan_malformed.return_value]
        discover_dhcp_servers(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, [])
        self.assertIn("Failed to parse Nmap XML", self.managed_stats['network']['dhcp_discovery_error'])
        self.assertTrue(any(f["severity"] == SEVERITY_HIGH and "Nmap DHCP XML Parse Error" in f["title"] for f in self.mock_findings_list))

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
