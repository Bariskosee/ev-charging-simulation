#!/usr/bin/env python3
"""
Quick audit log viewer for lab demonstration
Usage: python show_audit_logs.py
"""

from evcharging.common.database import AuditDB

def show_audit_logs():
    """Display audit logs in a readable format"""
    
    db = AuditDB("ev_charging.db")
    events = db.query_events(limit=20)
    
    if not events:
        print("❌ No audit events found. Run the system first to generate logs.")
        return
    
    print("\n" + "="*80)
    print("                    EV CHARGING AUDIT LOG")
    print("="*80)
    
    for event in events:
        time = event['date_time'].split('T')[1].split('.')[0] if 'T' in event['date_time'] else event['date_time']
        
        # Color code by severity
        severity_icon = {
            'INFO': '✅',
            'WARN': '⚠️',
            'ERROR': '❌',
            'CRITICAL': '🚨'
        }.get(event['severity'], '📝')
        
        print(f"\n{severity_icon} [{time}] {event['action']}")
        print(f"   Who: {event['who']}")
        print(f"   IP: {event['ip']}")
        print(f"   Description: {event['description']}")
        if event.get('reason_code'):
            print(f"   Reason: {event['reason_code']}")
    
    print("\n" + "="*80)
    print(f"Total events: {len(events)}")
    
    # Summary statistics
    from collections import Counter
    actions = Counter(e['action'] for e in events)
    print("\nEvent Summary:")
    for action, count in sorted(actions.items(), key=lambda x: -x[1]):
        print(f"  - {action}: {count}")
    print("="*80 + "\n")

if __name__ == "__main__":
    show_audit_logs()
