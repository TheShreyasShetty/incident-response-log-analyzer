import csv
from datetime import datetime
from collections import defaultdict
import argparse

class IncidentAnalyzer:
    """
    Analyzes Windows Event Logs for security incidents
    Detects: Brute force, Account compromise, Privilege escalation, New accounts
    """
    def __init__(self, log_file, threshold=5):
        """
        Initialize the analyzer
        
        Args:
            log_file (str): Path to CSV log file
            threshold (int): Failed login threshold for brute force detection
        """
        self.log_file = log_file
        self.threshold = threshold
        self.events = []
        self.suspicious_events = []
        self.severity_high = []
        self.severity_medium = []
        self.severity_low = []
        
    def parse_logs(self):
        """
        Read and parse the CSV log file
        Validates required columns exist
        
        Returns:
            bool: True if successful, False if error
        """
        try:
            with open(self.log_file, 'r') as f:
                reader = csv.DictReader(f)
                self.events = list(reader)
                
                # Validate required columns
                if self.events:
                    required_cols = ['Timestamp', 'EventID', 'Username', 'SourceIP', 'Status']
                    if not all(col in self.events[0].keys() for col in required_cols):
                        print("[-] Error: Log file missing required columns")
                        print(f"    Required: {', '.join(required_cols)}")
                        return False
                        
            print(f"[+] Loaded {len(self.events)} events from {self.log_file}")
            return True
            
        except FileNotFoundError:
            print(f"[-] Error: File '{self.log_file}' not found")
            return False
        except Exception as e:
            print(f"[-] Error reading file: {str(e)}")
            return False
    
    def detect_brute_force(self):
        """
        Detect brute force attacks: multiple failed logins from same IP
        
        Algorithm:
        1. Group all Event ID 4625 (failed logins) by source IP
        2. Count failures per IP
        3. Flag as HIGH severity if count >= threshold
        """
        print("[*] Detecting brute force attacks...")
    
        # Dictionary to group failed attempts by IP
        # Key: IP address, Value: list of failed login events
        failed_attempts = defaultdict(list)
    
        # Group all failed login attempts by source IP
        for event in self.events:
            if event['EventID'] == '4625':  # Failed login
                failed_attempts[event['SourceIP']].append({
                    'timestamp': event['Timestamp'],
                    'username': event['Username'],
                    'description': event['Description']
                })
    
        # Check if any IP exceeds the threshold
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.threshold:
                # Extract unique usernames that were targeted
                targeted_users = list(set([attempt['username'] for attempt in attempts]))
            
                self.suspicious_events.append({
                    'severity': 'HIGH',
                    'type': 'Brute Force Attack',
                    'source_ip': ip,
                    'description': f'{len(attempts)} failed login attempts detected from {ip}',
                    'details': f"Targeted usernames: {', '.join(targeted_users)}",
                    'recommendation': f'IMMEDIATE ACTION: Block IP {ip}, investigate targeted accounts ({", ".join(targeted_users)}), check firewall logs for this IP',
                    'timestamp': attempts[0]['timestamp']
                })
            
                print(f"  └─ Found: {len(attempts)} failed attempts from {ip}")
            print("[*] Detecting brute force attacks...")
    
        # Dictionary to group failed attempts by IP
        # Key: IP address, Value: list of failed login events
        failed_attempts = defaultdict(list)
    
        # Group all failed login attempts by source IP
        for event in self.events:
            if event['EventID'] == '4625':  # Failed login
                failed_attempts[event['SourceIP']].append({
                    'timestamp': event['Timestamp'],
                    'username': event['Username'],
                    'description': event['Description']
                })
    
        # Check if any IP exceeds the threshold
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.threshold:
                # Extract unique usernames that were targeted
                targeted_users = list(set([attempt['username'] for attempt in attempts]))
            
                self.suspicious_events.append({
                    'severity': 'HIGH',
                    'type': 'Brute Force Attack',
                    'source_ip': ip,
                    'description': f'{len(attempts)} failed login attempts detected from {ip}',
                    'details': f"Targeted usernames: {', '.join(targeted_users)}",
                    'recommendation': f'IMMEDIATE ACTION: Block IP {ip}, investigate targeted accounts ({", ".join(targeted_users)}), check firewall logs for this IP',
                    'timestamp': attempts[0]['timestamp']
                })
            
                print(f"  └─ Found: {len(attempts)} failed attempts from {ip}")
    
    def detect_account_compromise(self):
        """
        Detect potential account compromise
        Pattern: Multiple failed logins followed by successful login
        
        Algorithm:
        1. Group login events (4624, 4625) by username
        2. Check for pattern: 3+ failures then success
        3. Flag as HIGH severity
        """
        print("[*] Detecting account compromise...")
        
        # Dictionary to track login activity by username
        # Key: username, Value: list of login events in chronological order
        user_activity = defaultdict(list)
    
        # Group all login events by username
        for event in self.events:
            if event['EventID'] in ['4624', '4625']:  # Both success and failed logins
                user_activity[event['Username']].append({
                    'timestamp': event['Timestamp'],
                    'event_id': event['EventID'],
                    'source_ip': event['SourceIP'],
                    'status': event['Status']
                })
    
        # Check for failed-then-successful pattern for each user
        for username, activities in user_activity.items():
            failed_count = 0
        
            for activity in activities:
                if activity['status'] == 'Failed':
                    # Count consecutive failures
                    failed_count += 1
                elif activity['status'] == 'Success' and failed_count >= 3:
                    # Successful login after 3+ failures = potential compromise
                    self.suspicious_events.append({
                        'severity': 'HIGH',
                        'type': 'Potential Account Compromise',
                        'source_ip': activity['source_ip'],
                        'description': f"Account '{username}' logged in successfully after {failed_count} failed attempts",
                        'details': f"Successful login from {activity['source_ip']} at {activity['timestamp']}. Previous {failed_count} failed attempts suggest password guessing attack succeeded.",
                        'recommendation': f"IMMEDIATE ACTION: Contact user '{username}' to verify login legitimacy, force password reset, review account activity after {activity['timestamp']}, check for privilege escalation or data exfiltration",
                        'timestamp': activity['timestamp']
                    })
                
                    print(f"  └─ Found: {username} compromised after {failed_count} failures")
                
                    # Reset counter after detecting compromise
                    failed_count = 0
                else:
                    # Successful login without prior failures - reset counter
                    failed_count = 0
 
    def detect_privilege_escalation(self):
        """
        Detect suspicious privilege escalation
        Monitors Event ID 4672 (admin privileges assigned)
        
        Algorithm:
        1. Look for Event ID 4672
        2. Flag as MEDIUM severity (needs verification)
        """
        print("[*] Detecting privilege escalation...")

        for event in self.events:
            # Detect admin privilege assignment
            if event['EventID'] == '4672':
                self.suspicious_events.append({
                    'severity': 'MEDIUM',
                    'type': 'Privilege Escalation',
                    'source_ip': event['SourceIP'],
                    'description': f"Admin privileges assigned to '{event['Username']}'",
                    'details': f"Event occurred at {event['Timestamp']} from {event['SourceIP']}. User '{event['Username']}' received special privileges.",
                    'recommendation': f"Verify if privilege assignment for '{event['Username']}' was authorized through proper change management. Review user's role and recent activity.",
                    'timestamp': event['Timestamp']
                })
            
            print(f"  └─ Found: Admin privileges assigned to {event['Username']}")
    
    def detect_unusual_activity(self):
        """
        Detect other unusual patterns
        Monitors Event ID 4720 (new account creation)
        
        Algorithm:
        1. Look for Event ID 4720
        2. Flag as MEDIUM severity (needs verification)
        """
        print("[*] Detecting unusual account activity...")
        
        for event in self.events:
            # Detect new account creation
            if event['EventID'] == '4720':
                self.suspicious_events.append({
                    'severity': 'MEDIUM',
                    'type': 'New Account Created',
                    'source_ip': event['SourceIP'],
                    'description': f"New user account created: '{event['Username']}'",
                    'details': f"Account created at {event['Timestamp']} from {event['SourceIP']}. This could be legitimate or a persistence mechanism.",
                    'recommendation': f"Verify if account creation for '{event['Username']}' was authorized through proper procedures. Check who initiated the creation and the account's intended purpose.",
                    'timestamp': event['Timestamp']
                })
            
            print(f"  └─ Found: New account created - {event['Username']}")
    
    def classify_severity(self):
        """
        Classify detected incidents by severity level
        HIGH, MEDIUM, LOW categories
        """
        print("[*] Classifying incidents by severity...")
        
        for event in self.suspicious_events:
            if event['severity'] == 'HIGH':
                self.severity_high.append(event)
            elif event['severity'] == 'MEDIUM':
                self.severity_medium.append(event)
            else:
                self.severity_low.append(event)
    
    def generate_report(self):
        """
        Generate comprehensive incident response report
        Outputs to console and saves to file
        """
        print("[*] Generating report...")
        
        report_lines = []
    
        # Header
        report_lines.append("=" * 70)
        report_lines.append("INCIDENT RESPONSE ANALYSIS REPORT".center(70))
        report_lines.append("=" * 70)
        report_lines.append("")
    
        # Summary Section
        report_lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Log File Analyzed: {self.log_file}")
        report_lines.append(f"Total Events Processed: {len(self.events)}")
        report_lines.append(f"Suspicious Incidents Detected: {len(self.suspicious_events)}")
        report_lines.append("")
    
        # Severity Breakdown
        report_lines.append("-" * 70)
        report_lines.append("SEVERITY SUMMARY")
        report_lines.append("-" * 70)
        report_lines.append(f"HIGH Priority Incidents: {len(self.severity_high)}")
        report_lines.append(f"MEDIUM Priority Incidents: {len(self.severity_medium)}")
        report_lines.append(f"LOW Priority Incidents: {len(self.severity_low)}")
        report_lines.append("")
    
        # Check if no incidents found
        if not self.suspicious_events:
            report_lines.append("=" * 70)
            report_lines.append("NO SUSPICIOUS ACTIVITIES DETECTED")
            report_lines.append("=" * 70)
            report_lines.append("")
            report_lines.append("All analyzed events appear to be normal operations.")
            report_lines.append("No immediate security concerns identified.")
            report_lines.append("")
        else:
            # Detailed Findings Section
            report_lines.append("=" * 70)
            report_lines.append("DETAILED FINDINGS")
            report_lines.append("=" * 70)
            report_lines.append("")
        
            # HIGH SEVERITY INCIDENTS (Show first - most critical)
            if self.severity_high:
                report_lines.append("HIGH PRIORITY INCIDENTS (Immediate Action Required)")
                report_lines.append("=" * 70)
            
                for idx, incident in enumerate(self.severity_high, 1):
                    report_lines.append(f"\n[HIGH-{idx}] {incident['type']}")
                    report_lines.append(f"  Timestamp: {incident['timestamp']}")
                    report_lines.append(f"  Source IP: {incident['source_ip']}")
                    report_lines.append(f"  Description: {incident['description']}")
                    report_lines.append(f"  Details: {incident['details']}")
                    report_lines.append(f"  RECOMMENDATION: {incident['recommendation']}")
            
                report_lines.append("\n" + "-" * 70)
                report_lines.append("")
        
            # MEDIUM SEVERITY INCIDENTS
            if self.severity_medium:
                report_lines.append("MEDIUM PRIORITY INCIDENTS (Investigation Recommended)")
                report_lines.append("=" * 70)
            
                for idx, incident in enumerate(self.severity_medium, 1):
                    report_lines.append(f"\n[MEDIUM-{idx}] {incident['type']}")
                    report_lines.append(f"  Timestamp: {incident['timestamp']}")
                    report_lines.append(f"  Source IP: {incident['source_ip']}")
                    report_lines.append(f"  Description: {incident['description']}")
                    report_lines.append(f"  Details: {incident['details']}")
                    report_lines.append(f"  RECOMMENDATION: {incident['recommendation']}")
            
                report_lines.append("\n" + "-" * 70)
                report_lines.append("")
        
            # LOW SEVERITY INCIDENTS (if any)
            if self.severity_low:
                report_lines.append("LOW PRIORITY INCIDENTS (For Awareness)")
                report_lines.append("=" * 70)
            
                for idx, incident in enumerate(self.severity_low, 1):
                    report_lines.append(f"\n[LOW-{idx}] {incident['type']}")
                    report_lines.append(f"  Timestamp: {incident['timestamp']}")
                    report_lines.append(f"  Description: {incident['description']}")
            
                report_lines.append("\n" + "-" * 70)
                report_lines.append("")
    
        # Footer
        report_lines.append("=" * 70)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 70)
        report_lines.append("")
        report_lines.append("Generated by Incident Response Log Analyzer")
        report_lines.append("For questions or issues, contact your security team")
    
        # Convert to single string
        report = "\n".join(report_lines)
    
        # Print to console
        print(report)
    
        # Save to file with timestamp
        output_file = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"\n Report saved to: {output_file}")
        except Exception as e:
            print(f"\n Warning: Could not save report to file: {str(e)}")
    
    def run_analysis(self):
        """
        Main analysis workflow - orchestrates all detection methods
        """
        print("\n" + "="*70)
        print("INCIDENT RESPONSE LOG ANALYZER".center(70))
        print("="*70 + "\n")
        
        # Step 1: Parse logs
        if not self.parse_logs():
            return
        
        # Step 2: Run all detection algorithms
        print("\n[*] Running detection algorithms...")
        self.detect_brute_force()
        self.detect_privilege_escalation()
        self.detect_account_compromise()
        self.detect_unusual_activity()
        
        # Step 3: Classify by severity
        self.classify_severity()
        
        # Step 4: Generate report
        print("\n[*] Generating incident report...\n")
        self.generate_report()

def main():
    """
    Entry point for command-line execution
    """
    parser = argparse.ArgumentParser(
        description='Analyze Windows Event Logs for security incidents',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python incident_analyzer.py sample_logs.csv
  python incident_analyzer.py brute_force_scenario.csv --threshold 3
  
Supported Event IDs:
  4624 - Successful login
  4625 - Failed login
  4672 - Admin privileges assigned
  4720 - User account created
        """
    )
    
    parser.add_argument('log_file', 
                       help='Path to CSV log file')
    parser.add_argument('--threshold', 
                       type=int, 
                       default=5,
                       help='Failed login threshold for brute force detection (default: 5)')
    
    args = parser.parse_args()
    
    # Create analyzer and run
    analyzer = IncidentAnalyzer(args.log_file, args.threshold)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()