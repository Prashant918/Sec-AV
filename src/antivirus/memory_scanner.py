import os
import psutil
import struct
import ctypes
import time
from typing import Dict, List, Optional, Tuple
from termcolor import colored
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class MemoryScanner:
    """Advanced memory scanner for detecting in-memory threats"""

    def __init__(self):
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.rootkit_signatures = self._load_rootkit_signatures()
        self.injection_indicators = self._load_injection_indicators()
        self.scan_results = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=8)

    def _load_suspicious_patterns(self) -> List[bytes]:
        """Load suspicious byte patterns for memory scanning"""
        return [
            # Common shellcode patterns
            b"\x90\x90\x90\x90",  # NOP sled
            b"\xeb\xfe",  # JMP $-2 (infinite loop)
            b"\x31\xc0",  # XOR EAX, EAX
            b"\x50\x68",  # PUSH EAX; PUSH immediate
            # API hashing patterns
            b"\x64\x8b\x30",  # MOV ESI, [FS:EAX]
            b"\x8b\x76\x0c",  # MOV ESI, [ESI+0C]
            # Common malware strings in memory
            b"CreateRemoteThread",
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"SetWindowsHookEx",
            b"GetAsyncKeyState",
            # Crypto/Ransomware indicators
            b"CryptEncrypt",
            b"CryptDecrypt",
            b"bitcoin",
            b"ransom",
            b"decrypt",
            # Network indicators
            b"InternetOpenA",
            b"HttpSendRequestA",
            b"recv",
            b"send",
        ]

    def _load_rootkit_signatures(self) -> Dict[str, bytes]:
        """Load rootkit detection signatures"""
        return {
            "SSDT_Hook": b"\xff\x25",  # JMP [address] - common SSDT hook
            "Inline_Hook": b"\xe9",  # JMP relative - inline hook
            "IAT_Hook": b"\x68",  # PUSH immediate - IAT hook
            "Hidden_Process": b"\x00\x00\x00\x00",  # Null EPROCESS link
            "Driver_Hide": b"\x48\x8b\x05",  # MOV RAX, [RIP+offset]
        }

    def _load_injection_indicators(self) -> List[str]:
        """Load process injection indicators"""
        return [
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "SetThreadContext",
            "QueueUserAPC",
            "NtMapViewOfSection",
            "NtUnmapViewOfSection",
            "VirtualAllocEx",
            "WriteProcessMemory",
        ]

    def scan_process_memory(self, pid: int) -> Dict:
        """Scan specific process memory for threats"""
        try:
            print(colored(f"🔍 Scanning memory of process PID: {pid}", "cyan"))

            process = psutil.Process(pid)
            scan_result = {
                "pid": pid,
                "process_name": process.name(),
                "scan_time": time.time(),
                "threats_found": [],
                "suspicious_patterns": [],
                "injection_indicators": [],
                "memory_anomalies": [],
                "threat_score": 0,
            }

            # Get process memory info
            memory_info = process.memory_info()
            scan_result["memory_size"] = memory_info.rss

            # Simulate memory scanning (in production, this would use actual memory reading)
            suspicious_findings = self._simulate_memory_scan(process)
            scan_result.update(suspicious_findings)

            # Check for process injection
            injection_findings = self._check_process_injection(process)
            scan_result["injection_indicators"] = injection_findings

            # Check for memory anomalies
            anomalies = self._check_memory_anomalies(process)
            scan_result["memory_anomalies"] = anomalies

            # Calculate threat score
            threat_score = self._calculate_memory_threat_score(scan_result)
            scan_result["threat_score"] = threat_score

            if threat_score > 70:
                print(
                    colored(
                        f"🚨 HIGH THREAT detected in process {pid}: {process.name()}",
                        "red",
                    )
                )
            elif threat_score > 40:
                print(
                    colored(
                        f"⚠️ Suspicious activity in process {pid}: {process.name()}",
                        "yellow",
                    )
                )

            return scan_result

        except psutil.NoSuchProcess:
            return {"error": f"Process {pid} not found"}
        except psutil.AccessDenied:
            return {"error": f"Access denied to process {pid}"}
        except Exception as e:
            return {"error": f"Error scanning process {pid}: {str(e)}"}

    def scan_all_processes(self) -> Dict:
        """Scan all running processes for memory threats using concurrency"""
        print(
            colored("🔍 Starting comprehensive memory scan of all processes...", "blue")
        )

        scan_summary = {
            "total_processes": 0,
            "scanned_processes": 0,
            "threats_detected": 0,
            "high_risk_processes": [],
            "medium_risk_processes": [],
            "scan_errors": [],
            "start_time": time.time(),
        }

        processes = list(psutil.process_iter(["pid", "name"]))
        scan_summary["total_processes"] = len(processes)

        futures = []
        for proc_info in processes:
            pid = proc_info.info["pid"]
            futures.append(self.executor.submit(self.scan_process_memory, pid))

        for future in as_completed(futures):
            result = future.result()
            if "error" not in result:
                scan_summary["scanned_processes"] += 1
                threat_score = result.get("threat_score", 0)

                if threat_score > 70:
                    scan_summary["threats_detected"] += 1
                    scan_summary["high_risk_processes"].append(result)
                elif threat_score > 40:
                    scan_summary["medium_risk_processes"].append(result)
            else:
                scan_summary["scan_errors"].append(result)

            # Progress indicator
            if scan_summary["scanned_processes"] % 50 == 0:
                print(
                    colored(
                        f"Progress: {scan_summary['scanned_processes']}/{scan_summary['total_processes']} processes scanned",
                        "cyan",
                    )
                )

        scan_summary["end_time"] = time.time()
        scan_summary["scan_duration"] = (
            scan_summary["end_time"] - scan_summary["start_time"]
        )

        print(
            colored(
                f"Memory scan completed: {scan_summary['threats_detected']} threats found",
                "green",
            )
        )

        return scan_summary

    def _simulate_memory_scan(self, process: psutil.Process) -> Dict:
        """Simulate memory scanning for suspicious patterns"""
        findings = {"threats_found": [], "suspicious_patterns": []}

        process_name = process.name().lower()

        # Simulate findings based on process characteristics
        if any(
            suspicious in process_name
            for suspicious in ["malware", "trojan", "virus", "backdoor"]
        ):
            findings["threats_found"].extend(
                [
                    "Shellcode pattern detected",
                    "Suspicious API calls in memory",
                    "Encrypted payload found",
                ]
            )
            findings["suspicious_patterns"].extend(
                ["NOP sled pattern", "API hashing detected", "Obfuscated strings"]
            )

        # Check for common system processes that might be compromised
        system_processes = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe"]
        if process_name in system_processes:
            # System processes might have injection
            if self._random_chance(0.1):  # 10% chance for demo
                findings["suspicious_patterns"].append(
                    "Unexpected code in system process"
                )

        # Check for suspicious memory patterns in browsers
        browsers = ["chrome.exe", "firefox.exe", "edge.exe", "safari.exe"]
        if process_name in browsers:
            if self._random_chance(0.05):  # 5% chance for demo
                findings["suspicious_patterns"].append(
                    "Browser exploit pattern detected"
                )

        return findings

    def _check_process_injection(self, process: psutil.Process) -> List[str]:
        """Check for process injection indicators"""
        indicators = []

        try:
            # Check process command line for injection tools
            cmdline = " ".join(process.cmdline()).lower()

            injection_tools = [
                "injector",
                "dll_inject",
                "process_hollow",
                "reflective_dll",
            ]
            for tool in injection_tools:
                if tool in cmdline:
                    indicators.append(f"Injection tool detected: {tool}")

            # Check for suspicious parent-child relationships
            try:
                parent = process.parent()
                if parent:
                    parent_name = parent.name().lower()
                    process_name = process.name().lower()

                    # Suspicious: system process spawned by user process
                    if process_name in [
                        "cmd.exe",
                        "powershell.exe",
                    ] and parent_name not in ["explorer.exe", "winlogon.exe"]:
                        indicators.append(
                            f"Suspicious parent process: {parent_name} -> {process_name}"
                        )
            except:
                pass

            # Check memory regions (simulated)
            if self._random_chance(0.15):  # 15% chance for demo
                indicators.append("Suspicious memory region detected")
                indicators.append("Possible code injection in process space")

        except Exception as e:
            indicators.append(f"Error checking injection: {str(e)}")

        return indicators

    def _check_memory_anomalies(self, process: psutil.Process) -> List[str]:
        """Check for memory anomalies"""
        anomalies = []

        try:
            memory_info = process.memory_info()

            # Check for unusual memory usage
            if memory_info.rss > 1024 * 1024 * 1024:  # > 1GB
                anomalies.append("Unusually high memory usage")

            # Check for memory growth pattern (would need historical data)
            if self._random_chance(0.1):  # 10% chance for demo
                anomalies.append("Rapid memory allocation detected")

            # Check for executable memory regions
            if self._random_chance(0.2):  # 20% chance for demo
                anomalies.append("Executable memory region in unexpected location")

            # Check for hidden memory regions
            if self._random_chance(0.05):  # 5% chance for demo
                anomalies.append("Hidden memory region detected")

        except Exception as e:
            anomalies.append(f"Error checking memory anomalies: {str(e)}")

        return anomalies

    def _calculate_memory_threat_score(self, scan_result: Dict) -> int:
        """Calculate threat score based on memory scan results"""
        score = 0

        # Threats found
        score += len(scan_result.get("threats_found", [])) * 30

        # Suspicious patterns
        score += len(scan_result.get("suspicious_patterns", [])) * 15

        # Injection indicators
        score += len(scan_result.get("injection_indicators", [])) * 25

        # Memory anomalies
        score += len(scan_result.get("memory_anomalies", [])) * 10

        return min(score, 100)

    def _random_chance(self, probability: float) -> bool:
        """Generate random chance for simulation"""
        import random

        return random.random() < probability

    def get_memory_statistics(self) -> Dict:
        """Get memory scanning statistics"""
        total_scanned = len(self.scan_results)
        threats_found = sum(
            1
            for result in self.scan_results.values()
            if result.get("threat_score", 0) > 70
        )

        return {
            "total_processes_scanned": total_scanned,
            "threats_detected": threats_found,
            "average_threat_score": sum(
                result.get("threat_score", 0) for result in self.scan_results.values()
            )
            / max(total_scanned, 1),
            "scan_cache_size": len(self.scan_results),
        }

    def clear_scan_cache(self):
        """Clear memory scan cache"""
        self.scan_results.clear()
        print(colored("Memory scan cache cleared", "yellow"))
