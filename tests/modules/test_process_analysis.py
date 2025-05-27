import unittest
from unittest.mock import patch, Mock, MagicMock
import psutil # For psutil specific exceptions like AccessDenied, NoSuchProcess
import socket # For socket constants
from datetime import datetime

from modules.process_analysis import get_running_processes
from modules.utils import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO

# Helper to create psutil address objects (psutil._common.addr)
def make_addr(ip, port):
    addr = Mock()
    addr.ip = ip
    addr.port = port
    return addr

# Helper to create mock psutil connection objects (psutil._common.pconn)
def make_pconn(laddr_ip, laddr_port, raddr_ip=None, raddr_port=None, status=psutil.CONN_ESTABLISHED, conn_type=socket.SOCK_STREAM):
    pconn = Mock()
    pconn.fd = -1 
    pconn.family = socket.AF_INET
    pconn.type = conn_type
    pconn.laddr = make_addr(laddr_ip, laddr_port) if laddr_ip else None
    pconn.raddr = make_addr(raddr_ip, raddr_port) if raddr_ip and raddr_port else None
    pconn.status = status
    return pconn

# Helper to create mock IO counters object
def make_io_counters(read_bytes, write_bytes, read_count=0, write_count=0):
    counters = Mock()
    counters.read_bytes = read_bytes
    counters.write_bytes = write_bytes
    counters.read_count = read_count
    counters.write_count = write_count
    # Add other attributes if your version of psutil includes them and they are accessed
    # For example, on Linux: read_chars, write_chars
    # On Windows/macOS: other_count, other_bytes
    if hasattr(psutil._common, 'piofile'): # Heuristic for newer psutil versions
        counters.read_chars = 0
        counters.write_chars = 0
    if psutil.WINDOWS or psutil.MACOS:
        counters.other_count = 0
        counters.other_bytes = 0
    return counters
    

class MockPsutilProcess:
    def __init__(self, pid, name, username="testuser", cmdline=None, create_time=None, status=psutil.STATUS_RUNNING, ppid=1, cwd="/tmp", connections=None, io_counters=None, connections_error=None, io_counters_error=None):
        self.pid = pid
        self._name = name
        self._username = username
        self._cmdline = cmdline if cmdline is not None else [name]
        self._create_time = create_time if create_time is not None else datetime.now().timestamp()
        self._status = status
        self._ppid = ppid
        self._cwd = cwd
        self._connections_data = connections if connections is not None else []
        self._io_counters_data = io_counters
        self._connections_error = connections_error
        self._io_counters_error = io_counters_error

    def info(self): # Matches structure of proc.info from psutil.process_iter
        return {
            'pid': self.pid,
            'name': self._name,
            'username': self._username,
            'cmdline': self._cmdline,
            'create_time': self._create_time,
            'status': self._status,
            'ppid': self._ppid,
            'cwd': self._cwd
        }

    def connections(self, kind='inet'):
        if self._connections_error:
            raise self._connections_error
        return self._connections_data
    
    def io_counters(self):
        if self._io_counters_error:
            raise self._io_counters_error
        if self._io_counters_data is None: # Default if not specified
            return make_io_counters(0,0) 
        return self._io_counters_data


class TestProcessAnalysis(unittest.TestCase):
    def setUp(self):
        self.managed_stats = {'processes': {}}
        self.mock_findings_list = []

        def mock_add_finding(managed_findings_ignored, severity, title, description, recommendation="N/A"):
            self.mock_findings_list.append({
                "severity": severity, "title": title, "description": description, "recommendation": recommendation
            })
        self.mock_add_finding_func = mock_add_finding
        self.mock_findings_list.clear()

    @patch('modules.process_analysis.psutil.process_iter')
    def test_protocol_id_and_io_counters(self, mock_process_iter):
        mock_procs = [
            MockPsutilProcess(
                pid=101, name="nginx", username="www-data", cmdline=["nginx", "-g", "daemon off;"],
                connections=[
                    make_pconn("0.0.0.0", 80, status=psutil.CONN_LISTEN), # HTTP
                    make_pconn("10.1.1.1", 12345, "50.50.50.50", 443, status=psutil.CONN_ESTABLISHED) # Outgoing HTTPS
                ],
                io_counters=make_io_counters(read_bytes=1024*1024, write_bytes=2*1024*1024) # 1MB read, 2MB written
            ),
            MockPsutilProcess(
                pid=102, name="sshd", username="root", cmdline=["/usr/sbin/sshd", "-D"],
                connections=[make_pconn("0.0.0.0", 2222, status=psutil.CONN_LISTEN)], # SSH on non-standard port
                io_counters=make_io_counters(read_bytes=500, write_bytes=600)
            ),
            MockPsutilProcess(
                pid=103, name="myclient", username="testuser",
                connections=[make_pconn("192.168.1.100", 54321, "8.8.8.8", 53, status=psutil.CONN_ESTABLISHED, conn_type=socket.SOCK_DGRAM)], # Outgoing DNS (UDP)
                io_counters=make_io_counters(read_bytes=100, write_bytes=50)
            ),
            MockPsutilProcess(
                pid=104, name="highvolume_proc", username="testuser",
                connections=[], # No connections, just high I/O
                io_counters=make_io_counters(read_bytes=150*1024*1024, write_bytes=5*1024*1024) # 150MB read
            ),
             MockPsutilProcess(
                pid=105, name="error_proc", username="testuser",
                connections_error=psutil.AccessDenied("Connections denied for PID 105"),
                io_counters_error=psutil.AccessDenied("I/O denied for PID 105")
            )
        ]
        mock_process_iter.return_value = mock_procs

        get_running_processes(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func)

        # Assertions
        self.assertIn('processes', self.managed_stats)
        proc_list = self.managed_stats['processes'].get('list', [])
        self.assertEqual(len(proc_list), 5)

        # Process 1 (nginx)
        nginx_proc = next((p for p in proc_list if p['pid'] == 101), None)
        self.assertIsNotNone(nginx_proc)
        self.assertEqual(nginx_proc['bytes_read'], 1024*1024)
        self.assertEqual(nginx_proc['bytes_sent'], 2*1024*1024)
        conns_nginx = nginx_proc.get('network_connections', [])
        self.assertEqual(len(conns_nginx), 2)
        
        http_conn_nginx = next((c for c in conns_nginx if c['laddr'].endswith(":80")), None)
        self.assertIsNotNone(http_conn_nginx)
        self.assertEqual(http_conn_nginx['identified_protocol'], "HTTP")
        self.assertTrue("Port-based" in http_conn_nginx['protocol_certainty'] or "Process-inferred" in http_conn_nginx['protocol_certainty'])

        https_conn_nginx = next((c for c in conns_nginx if c['raddr'] and c['raddr'].endswith(":443")), None)
        self.assertIsNotNone(https_conn_nginx)
        self.assertEqual(https_conn_nginx['identified_protocol'], "HTTPS")
        self.assertTrue("well-known remote port" in https_conn_nginx['protocol_certainty'] or "Process-inferred" in https_conn_nginx['protocol_certainty'])


        # Process 2 (sshd)
        sshd_proc = next((p for p in proc_list if p['pid'] == 102), None)
        self.assertIsNotNone(sshd_proc)
        conns_sshd = sshd_proc.get('network_connections', [])
        self.assertEqual(len(conns_sshd), 1)
        ssh_conn = conns_sshd[0]
        self.assertEqual(ssh_conn['identified_protocol'], "SSH")
        self.assertEqual(ssh_conn['protocol_certainty'], "Process-inferred (Listening)") # Because 'sshd' name

        # Process 3 (myclient - DNS)
        myclient_proc = next((p for p in proc_list if p['pid'] == 103), None)
        self.assertIsNotNone(myclient_proc)
        conns_myclient = myclient_proc.get('network_connections', [])
        self.assertEqual(len(conns_myclient), 1)
        dns_conn = conns_myclient[0]
        self.assertEqual(dns_conn['identified_protocol'], "DNS")
        self.assertEqual(dns_conn['type'], "UDP")
        self.assertEqual(dns_conn['protocol_certainty'], "Port-based (Remote, Established)")
        
        # Process 4 (highvolume_proc) - Check for high I/O finding
        highvolume_proc = next((p for p in proc_list if p['pid'] == 104), None)
        self.assertIsNotNone(highvolume_proc)
        self.assertEqual(highvolume_proc['bytes_read'], 150*1024*1024)
        high_io_finding = any(
            f["severity"] == SEVERITY_MEDIUM and "High I/O Volume" in f["title"] and "highvolume_proc" in f["description"]
            for f in self.mock_findings_list
        )
        self.assertTrue(high_io_finding, "Missing high I/O finding for highvolume_proc")

        # Process 5 (error_proc) - Check for error handling
        error_proc = next((p for p in proc_list if p['pid'] == 105), None)
        self.assertIsNotNone(error_proc)
        self.assertEqual(error_proc['network_connections_error'], "Access Denied")
        self.assertEqual(error_proc['io_counters_error'], "Access Denied")
        self.assertEqual(error_proc['bytes_sent'], -1) # Check placeholder for numeric fields
        self.assertEqual(error_proc['bytes_read'], -1)
        
        # Check for connection info error finding specifically for PID 105
        conn_error_finding_105 = any(
            f["severity"] == SEVERITY_LOW and "Connection Info Error for PID 105" in f["title"]
            for f in self.mock_findings_list
        )
        # Note: The current process_analysis module doesn't add a finding for I/O counter errors, only logs them.
        # If it did, we'd test for that here.
        self.assertTrue(conn_error_finding_105, "Missing connection info error finding for PID 105")


    @patch('modules.process_analysis.psutil.process_iter')
    def test_protocol_mismatch_finding(self, mock_process_iter):
        # Process named 'sshd' listening on port 80 (HTTP port)
        mock_procs = [
            MockPsutilProcess(
                pid=201, name="sshd", username="root",
                connections=[make_pconn("0.0.0.0", 80, status=psutil.CONN_LISTEN)],
                io_counters=make_io_counters(0,0)
            )
        ]
        mock_process_iter.return_value = mock_procs
        get_running_processes(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func)
        
        mismatch_finding = any(
            f["severity"] == SEVERITY_MEDIUM and 
            "Potential Protocol Mismatch on Port 80" in f["title"] and
            "Process 'sshd' (PID: 201) is using port 80 (typically HTTP)" in f["description"] and
            "process name suggests it might be SSH" in f["description"]
            for f in self.mock_findings_list
        )
        self.assertTrue(mismatch_finding, "Missing protocol mismatch finding.")

    @patch('modules.process_analysis.psutil.process_iter')
    def test_multiple_unknown_protocols_finding(self, mock_process_iter):
        # Process with many connections, most of which are unknown
        connections = []
        for i in range(10): # 10 connections
            connections.append(make_pconn("127.0.0.1", 10000 + i, "1.2.3.4", 20000 + i, status=psutil.CONN_ESTABLISHED))
        
        mock_procs = [
            MockPsutilProcess(
                pid=301, name="mysteriousapp", username="test",
                connections=connections, # All will be unknown as ports are not in map
                io_counters=make_io_counters(0,0)
            )
        ]
        mock_process_iter.return_value = mock_procs
        get_running_processes(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func)

        unknown_finding = any(
            f["severity"] == SEVERITY_LOW and
            "Process with Multiple Unknown Protocols" in f["title"] and
            "mysteriousapp" in f["description"] and "10 connections with undetermined protocols" in f["description"]
            for f in self.mock_findings_list
        )
        self.assertTrue(unknown_finding, "Missing multiple unknown protocols finding.")


    @patch('modules.process_analysis.psutil.process_iter')
    def test_existing_process_checks_preserved(self, mock_process_iter):
        # Test if existing checks (root, suspicious CWD) are still working
        mock_procs = [
            MockPsutilProcess(pid=401, name="unexpected_root_proc", username="root", cwd="/bin"),
            MockPsutilProcess(pid=402, name="tmp_runner", username="testuser", cwd="/tmp/payload")
        ]
        mock_process_iter.return_value = mock_procs
        get_running_processes(self.managed_stats, self.mock_findings_list, self.mock_add_finding_func)

        root_finding = any(
            f["severity"] == SEVERITY_LOW and "Process Running as Root: unexpected_root_proc" in f["title"]
            for f in self.mock_findings_list
        )
        suspicious_cwd_finding = any(
            f["severity"] == SEVERITY_MEDIUM and "Process Running from Suspicious Location: tmp_runner" in f["title"]
            for f in self.mock_findings_list
        )
        self.assertTrue(root_finding, "Missing unexpected root process finding.")
        self.assertTrue(suspicious_cwd_finding, "Missing suspicious CWD finding.")


if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
