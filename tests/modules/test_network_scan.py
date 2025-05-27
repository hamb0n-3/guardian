import unittest
from unittest.mock import patch, Mock, MagicMock
import socket # For socket.gaierror and socket constants

# Assuming modules are importable from the project root (e.g. running tests with python -m unittest)
from modules.network_scan import perform_traceroute
from modules.utils import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

# Sample successful traceroute output (simplified for testing)
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
""" # Target 10.255.255.1 is not reached


class TestPerformTraceroute(unittest.TestCase):

    def setUp(self):
        self.managed_stats = {'network': {'traceroute': {}}}
        self.mock_findings_list = []

        # Create a mock add_finding_func that appends to our list
        def mock_add_finding(managed_findings_ignored, severity, title, description, recommendation="N/A"):
            self.mock_findings_list.append({
                "severity": severity,
                "title": title,
                "description": description,
                "recommendation": recommendation
            })
        self.mock_add_finding_func = mock_add_finding
        
        # Reset findings list for each test
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
        
        # Configure socket.getaddrinfo mock
        # addrinfo format: (family, type, proto, canonname, sockaddr)
        # sockaddr for IPv4 is (host, port)
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        
        # Configure subprocess.Popen mock
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_OUTPUT_SUCCESS)

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)

        # Assertions for managed_stats
        self.assertIn(target_host, self.managed_stats['network']['traceroute'])
        trace_results = self.managed_stats['network']['traceroute'][target_host]
        self.assertIsNone(trace_results.get('error'))
        self.assertIsNotNone(trace_results.get('summary'))
        self.assertTrue("successfully reached" in trace_results['summary'].lower())
        
        hops = trace_results.get('hops', [])
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0]['ip'], "192.168.1.1")
        self.assertEqual(hops[0]['rtt_ms'], 0.543)
        self.assertEqual(hops[1]['ip'], "10.0.0.1")
        self.assertEqual(hops[1]['rtt_ms'], 1.234)
        self.assertEqual(hops[2]['ip'], "8.8.8.8") # Target reached
        self.assertEqual(hops[2]['rtt_ms'], 2.345)

        # Assertions for findings (expect no high/medium severity findings for a clean trace)
        for finding in self.mock_findings_list:
            self.assertNotIn(finding['severity'], [SEVERITY_HIGH, SEVERITY_MEDIUM])
        
        # Check that getaddrinfo was called
        mock_getaddrinfo.assert_called_with(target_host, None)
        # Check that Popen was called with the correct command
        mock_subproc_popen.assert_called_once()
        args, kwargs = mock_subproc_popen.call_args
        self.assertEqual(args[0], ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "30", target_host])


    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_high_rtt_packet_loss(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "example.com"
        target_ip = "93.184.216.34"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_ip, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_HIGH_RTT)

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)

        trace_results = self.managed_stats['network']['traceroute'][target_host]
        hops = trace_results.get('hops', [])
        self.assertEqual(len(hops), 3)
        
        self.assertEqual(hops[0]['ip'], "192.168.1.1")
        self.assertEqual(hops[0]['rtt_ms'], 250.543)
        self.assertEqual(hops[1]['ip'], "N/A (Timeout)") # Parsed from '*'
        self.assertEqual(hops[1]['packet_loss_percent'], 100.0)
        self.assertEqual(hops[2]['ip'], target_ip)
        self.assertEqual(hops[2]['rtt_ms'], 300.000)
        
        self.assertTrue("successfully reached" in trace_results['summary'].lower() or "ended at" in trace_results['summary'].lower())


        # Check for findings
        high_rtt_finding_1 = any(
            f["severity"] == SEVERITY_MEDIUM and "High RTT" in f["title"] and "192.168.1.1" in f["description"]
            for f in self.mock_findings_list
        )
        packet_loss_finding = any(
            f["severity"] == SEVERITY_MEDIUM and "Packet Loss/Timeout at Hop 2" in f["title"]
            for f in self.mock_findings_list
        )
        high_rtt_finding_2 = any(
            f["severity"] == SEVERITY_MEDIUM and "High RTT" in f["title"] and target_ip in f["description"]
            for f in self.mock_findings_list
        )
        self.assertTrue(high_rtt_finding_1, "Missing high RTT finding for hop 1")
        self.assertTrue(packet_loss_finding, "Missing packet loss finding for hop 2")
        self.assertTrue(high_rtt_finding_2, "Missing high RTT finding for hop 3")


    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_target_unreachable(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "10.255.255.1" # Non-existent, assuming it won't be resolved as last hop
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen(SAMPLE_TRACEROUTE_UNREACHABLE)

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        
        trace_results = self.managed_stats['network']['traceroute'][target_host]
        self.assertTrue("NOT explicitly reached" in trace_results['summary'] or "failed to reach the target" in trace_results['summary'], f"Unexpected summary: {trace_results['summary']}")
        self.assertEqual(trace_results.get('error'), "Target not reached")

        unreachable_finding_exists = any(
            f["severity"] == SEVERITY_HIGH and f"Target {target_host} Unreachable" in f["title"]
            for f in self.mock_findings_list
        )
        self.assertTrue(unreachable_finding_exists, "Missing target unreachable finding.")


    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_command_not_found(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "8.8.8.8"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        
        # Simulate FileNotFoundError by Popen itself, or stderr indicating command not found
        mock_subproc_popen.return_value = self._get_mock_popen("", "traceroute: command not found", 127) # Common exit code for command not found

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)

        trace_results = self.managed_stats['network']['traceroute'][target_host]
        self.assertIn("Traceroute command not found", trace_results.get('error', ''))
        
        not_found_finding = any(
            f["severity"] == SEVERITY_HIGH and "Traceroute Execution Error" in f["title"] and "command not found" in f["description"].lower()
            for f in self.mock_findings_list
        )
        self.assertTrue(not_found_finding, "Missing traceroute command not found finding.")

    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_host_resolution_error_socket(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "nonexistenthost123abc.com"
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        # Popen might not even be called if getaddrinfo fails first and the function handles it.
        # Depending on implementation, Popen might still be called if resolution is also done by traceroute command itself.
        # The current perform_traceroute tries to resolve early.

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)

        trace_results = self.managed_stats['network']['traceroute'][target_host]
        # This test assumes early resolution failure is caught.
        # The actual error message might vary based on how `perform_traceroute` handles this.
        # In the provided `perform_traceroute`, an early `socket.getaddrinfo` failure leads to a warning
        # and then traceroute command itself might fail.
        
        # If traceroute command itself fails due to unresolvable host (common behavior)
        mock_subproc_popen.return_value = self._get_mock_popen("", f"traceroute: unknown host {target_host}", 1) # Simulate traceroute's own error
        
        # Re-run with Popen now set up to simulate traceroute's failure for resolution
        self.setUp() # Reset stats and findings
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known") # Still raise for initial check
        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)
        
        trace_results_after_rerun = self.managed_stats['network']['traceroute'][target_host]

        self.assertIsNotNone(trace_results_after_rerun.get('error'))
        self.assertTrue("host not found" in trace_results_after_rerun['error'].lower() or \
                        "name or service not known" in trace_results_after_rerun['error'].lower() or \
                        "unknown host" in trace_results_after_rerun['error'].lower() or \
                        "could not resolve" in trace_results_after_rerun['summary'].lower()
                        )

        resolution_finding_exists = any(
            f["severity"] == SEVERITY_HIGH and ("Traceroute Host Resolution Error" in f["title"] or "unknown host" in f["description"].lower())
            for f in self.mock_findings_list
        )
        # Also check for the early warning finding if applicable
        early_warning_finding = any(
            f["severity"] == SEVERITY_LOW and "Traceroute Pre-computation Warning" in f["title"] and "Could not resolve" in f["description"]
            for f in self.mock_findings_list
        )
        self.assertTrue(resolution_finding_exists or early_warning_finding, "Missing host resolution error finding.")


    @patch('modules.network_scan.socket.getaddrinfo')
    @patch('modules.network_scan.subprocess.Popen')
    def test_perform_traceroute_empty_output(self, mock_subproc_popen, mock_getaddrinfo):
        target_host = "8.8.8.8"
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (target_host, 0))]
        mock_subproc_popen.return_value = self._get_mock_popen("") # Empty stdout

        perform_traceroute(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func, target_host)

        trace_results = self.managed_stats['network']['traceroute'][target_host]
        self.assertTrue("no standard output" in trace_results.get('summary', '').lower() or "no hops parsed" in trace_results.get('summary','').lower())
        
        empty_output_finding = any(
            f["severity"] == SEVERITY_LOW and ("Traceroute Empty Output" in f["title"] or "No Hops Parsed" in f["title"])
            for f in self.mock_findings_list
        )
        self.assertTrue(empty_output_finding, "Missing empty/no hops output finding.")

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
