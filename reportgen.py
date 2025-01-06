import sqlite3
import questionary
from docx import Document
from docx.shared import Pt
import matplotlib.pyplot as plt
import logging
import seaborn as sns
from openai import OpenAI

# Initialize OpenAI Client
client = OpenAI(
    api_key="YOUR API KEY GOES HERE"
)

# Step 1: Database Setup and Queries
def setup_database():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
            vulnerability_id INTEGER PRIMARY KEY,
            vulnerability_name TEXT NOT NULL,
            vulnerability_details_1 TEXT,
            cvss3_base_score REAL,
            cvss3_base_vector TEXT,
            vulnerability_family TEXT,
            vulnerability_references TEXT,
            see_also TEXT,
            vulnerability_solution TEXT,
            vulnerability_exploitprobability_score REAL,
            severity TEXT
        )''')
        conn.commit()
        conn.close()
        logging.info("Database setup completed successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error setting up database: {e}")

def fetch_vulnerabilities():
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT
            vulnerability_id, vulnerability_name, vulnerability_details_1, cvss3_base_score,
            cvss3_base_vector, vulnerability_family, vulnerability_references,
            see_also, vulnerability_solution, vulnerability_exploitprobability_score, severity
        FROM vulnerabilities''')
        rows = cursor.fetchall()
        conn.close()
        logging.info("Fetched vulnerabilities from the database.")
        return [
            {
                "vulnerability_id": row[0],
                "vulnerability_name": row[1],
                "vulnerability_details_1": row[2],
                "cvss3_base_score": row[3],
                "cvss3_base_vector": row[4],
                "vulnerability_family": row[5],
                "vulnerability_references": row[6],
                "see_also": row[7],
                "vulnerability_solution": row[8],
                "vulnerability_exploitprobability_score": row[9],
                "severity": row[10],
            }
            for row in rows
        ]
    except sqlite3.Error as e:
        logging.error(f"Error fetching vulnerabilities: {e}")
        return []

# Step 2: Basic Info and Scope
def get_basic_info():
    try:
        return {
            "client": questionary.text("Enter Client Name:").ask(),
            "vendor": questionary.text("Enter Vendor Name:").ask(),
            "service": questionary.text("Enter Service Name (e.g., Web Application Penetration Test):").ask(),
            "service_type": questionary.select("Enter Type of Service:", choices=['black', 'grey', 'white']).ask(),
            "start_date": questionary.text("Enter Start Date (e.g., July 1, 2024):").ask(),
            "end_date": questionary.text("Enter End Date (e.g., July 5, 2024):").ask(),
            "author1": questionary.text("Enter Author 1 Name (e.g., Kendall Lewis):").ask(),
            "author2": questionary.text("Enter Author 2 Name (e.g., Liam Henig):").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting basic info: {e}")
        return {}

def get_vuln_scope():
    try:
        return {
            "service_scope": questionary.checkbox("Select the Scope of the Test (Choose all that apply):",
                                                  choices=["Network", "Web Application", "Mobile Application", "Other"]).ask(),
            "service_detailed_scope": questionary.text("Enter Detailed Scope (e.g., firewall, servers, wifi):").ask(),
        }
    except Exception as e:
        logging.error(f"Error getting vulnerability scope: {e}")
        return {}

# Step 3: Vulnerability Selection
def select_vulnerabilities(vulnerabilities):
    try:
        selected_ids = questionary.checkbox(
            "Select vulnerabilities to include in the report:",
            choices=[f"{v['vulnerability_id']}: {v['vulnerability_name']} (Severity: {v['severity']})" for v in vulnerabilities]
        ).ask()
        selected_ids = [int(choice.split(":")[0]) for choice in selected_ids]
        return [v for v in vulnerabilities if v['vulnerability_id'] in selected_ids]
    except Exception as e:
        logging.error(f"Error selecting vulnerabilities: {e}")
        return []

# Step 4: Narrative Generation
def generate_narrative(vulnerabilities):
    severity_groups = {}
    for v in vulnerabilities:
        severity_groups.setdefault(v['severity'], []).append(v)

    prompt = "Generate a concise executive summary for the following grouped vulnerabilities:\n\n"
    for severity, vulns in severity_groups.items():
        prompt += f"Severity: {severity}\n"
        for v in vulns:
            prompt += f"- {v['vulnerability_name']} (CVSS3 Score: {v['cvss3_base_score']})\n"
        prompt += "\n"

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=30,
            temperature=0.7,
        )
        return response.choices[0].message["content"]
    except Exception as e:
        logging.error(f"Error generating narrative: {e}")
        return "Error generating narrative."

# Step 5: Heatmap Generation
def generate_heatmap(vulnerabilities):
    try:
        plt.figure(figsize=(10, 6))
        sns.heatmap(
            [[v['cvss3_base_score'], v['vulnerability_exploitprobability_score']] for v in vulnerabilities],
            annot=True, fmt=".2f", cmap="YlGnBu",
            xticklabels=["CVSS3 Score", "Exploit Probability"]
        )
        plt.title("Vulnerability Heatmap")
        plt.savefig("heatmap.png")
        logging.info("Heatmap generated and saved as heatmap.png.")
    except Exception as e:
        logging.error(f"Error generating heatmap: {e}")

# Step 6: Generate Report
def add_vulnerability_table(doc, vulnerabilities):
    table = doc.add_table(rows=1, cols=6)
    table.style = 'Table Grid'
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Vulnerability Name'
    hdr_cells[1].text = 'Details'
    hdr_cells[2].text = 'CVSS3 Score'
    hdr_cells[3].text = 'Solution'
    hdr_cells[4].text = 'Exploit Probability'
    hdr_cells[5].text = 'Severity'

    for vuln in vulnerabilities:
        row_cells = table.add_row().cells
        row_cells[0].text = vuln['vulnerability_name']
        row_cells[1].text = vuln['vulnerability_details_1'] or "N/A"
        row_cells[2].text = str(vuln['cvss3_base_score']) or "N/A"
        row_cells[3].text = vuln['vulnerability_solution'] or "N/A"
        row_cells[4].text = str(vuln['vulnerability_exploitprobability_score']) or "N/A"
        row_cells[5].text = vuln['severity'] or "N/A"

def generate_report(client, vulnerabilities, start_date, end_date, author1, author2):
    doc = Document()
    doc.add_heading(f"Penetration Test Report for {client}", 0)
    doc.add_paragraph(f"Test Period: {start_date} to {end_date}")
    doc.add_paragraph(f"Authors: {author1}, {author2}")

    doc.add_heading('Executive Summary', level=1)
    doc.add_paragraph(generate_narrative(vulnerabilities))

    doc.add_heading('Detailed Vulnerability Information', level=1)
    add_vulnerability_table(doc, vulnerabilities)

    doc.save(f'{client}_report.docx')

# Main Workflow
def main():
    setup_database()
    basic_info = get_basic_info()
    vuln_scope = get_vuln_scope()
    vulnerabilities = fetch_vulnerabilities()
    selected_vulns = select_vulnerabilities(vulnerabilities)

    generate_report(
        basic_info['client'], selected_vulns,
        basic_info['start_date'], basic_info['end_date'],
        basic_info['author1'], basic_info['author2']
    )
    generate_heatmap(selected_vulns)
    print(f"Report generated for {basic_info['client']}!")

if __name__ == "__main__":
    main()
