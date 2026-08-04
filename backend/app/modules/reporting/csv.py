import csv
import io


def generate_csv_report(data: dict) -> str:
    """Generate CSV report export of scan findings."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Category", "Metric / Module", "Value / Status", "Risk / Details"])
    writer.writerow(["General", "Target Domain", data.get("target", "N/A"), "N/A"])
    writer.writerow(["General", "Security Score", data.get("security_score", 0), data.get("overall_risk", "N/A")])

    modules = data.get("modules", {})

    # SSL
    ssl_mod = modules.get("ssl", {})
    writer.writerow(["SSL/TLS", "Status", ssl_mod.get("status", "N/A"), f"Grade: {ssl_mod.get('grade', 'N/A')}"])

    # Headers
    hdr_mod = modules.get("headers", {})
    writer.writerow(["HTTP Headers", "Overall Risk", hdr_mod.get("overall_risk", "N/A"), f"Grade: {hdr_mod.get('grade', 'N/A')}"])

    # DNS
    dns_mod = modules.get("dns", {})
    writer.writerow(["DNS", "IP Address", dns_mod.get("ip_address", "N/A"), f"SPF: {dns_mod.get('spf_status', 'N/A')}, DMARC: {dns_mod.get('dmarc_status', 'N/A')}"])

    # Open Ports
    ports_mod = modules.get("ports", {})
    writer.writerow(["Open Ports", "Total Open", ports_mod.get("total_open", 0), f"High Risk Ports: {ports_mod.get('high_risk_ports', 0)}"])

    # Reputation
    rep_mod = modules.get("reputation", {})
    writer.writerow(["Reputation", "Risk Level", rep_mod.get("risk_level", "N/A"), f"Score: {rep_mod.get('reputation_score', 0)}"])

    # Threat Intel
    threat_mod = modules.get("threatintel", {})
    writer.writerow(["Threat Intel", "Threat Level", threat_mod.get("threat_level", "N/A"), f"Score: {threat_mod.get('threat_intel_score', 0)}"])

    # Typosquatting
    typo_mod = modules.get("typosquatting", {})
    writer.writerow(["Typosquatting", "Active Squatted Domains", typo_mod.get("active_count", 0), typo_mod.get("risk_level", "N/A")])

    return output.getvalue()
